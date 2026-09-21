#![cfg(target_os = "macos")]
//! `nd7-exec` against the real kernel sandbox. Every test builds its own
//! sessions directory under the temp dir and points the binary at it with
//! `ND7_SESSIONS_DIR` (the `test-seams` override); the real `~/.nd7` is never
//! read or written.
//!
//! The session is named after THIS process: the spawned `nd7-exec`'s parent is
//! the test binary, which is what its ancestry walk finds.

use std::{
    env, fs,
    io::Write,
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

const EXEC: &str = env!("CARGO_BIN_EXE_nd7-exec");

/// A fresh empty directory for one test, named after the test and this pid.
fn scratch(name: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("nd7-exec-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    // `subpath` matches resolved paths, and macOS temp dirs live under
    // `/private`.
    dir.canonicalize().unwrap()
}

/// The sessions directory of `root`, with a session for this process in it.
fn session(root: &Path) -> PathBuf {
    let dir = root.join(format!("sessions/{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn nd7_exec(root: &Path, cmd: &str) -> Command {
    let mut c = Command::new(EXEC);
    c.env("ND7_SESSIONS_DIR", root.join("sessions"))
        .args(["-c", cmd]);
    c
}

fn run(root: &Path, cmd: &str) -> Output {
    nd7_exec(root, cmd).output().unwrap()
}

/// Denies everything but reading, execing, and writing under `dir`.
fn strict_policy(dir: &Path) -> String {
    format!(
        r#"(version 1)
(deny default)
(import "system.sb")
(allow process-exec process-fork)
(allow sysctl-read)
(allow file-read*)
(allow file-ioctl)
(allow file-write* (subpath "{}"))
"#,
        dir.display()
    )
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn usage_errors_exit_2() {
    for args in [vec![], vec!["-c"], vec!["-c", "a", "b"], vec!["-x"]] {
        let out = Command::new(EXEC).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            stderr(&out).contains("usage:"),
            "{args:?}: {}",
            stderr(&out)
        );
        assert_eq!(stdout(&out), "", "{args:?}");
    }
}

#[test]
fn refuses_without_session() {
    let root = scratch("no-session");
    fs::create_dir_all(root.join("sessions")).unwrap();
    let probe = root.join("should-not-exist");

    let out = run(&root, &format!("/usr/bin/touch {}", probe.display()));

    assert_eq!(out.status.code(), Some(126));
    assert!(
        stderr(&out).contains("nd7-exec: no nd7 session"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "");
    assert!(!probe.exists());

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn refuses_without_policy() {
    let root = scratch("no-policy");
    session(&root);

    let out = run(&root, "echo hi");

    assert_eq!(out.status.code(), Some(126));
    assert!(
        stderr(&out).contains("nd7-exec: session has no policy.sb"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn refuses_unreadable_policy() {
    let root = scratch("unreadable-policy");
    // A directory where the profile should be: it exists, so the session looks
    // complete, but reading it fails.
    fs::create_dir_all(session(&root).join("policy.sb")).unwrap();

    let out = run(&root, "echo hi");

    assert_eq!(out.status.code(), Some(126));
    assert!(
        stderr(&out).contains("nd7-exec: read"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn refuses_invalid_policy() {
    let root = scratch("invalid-policy");
    fs::write(session(&root).join("policy.sb"), "(version 1)\n(junk").unwrap();

    let out = run(&root, "echo hi");

    assert_eq!(out.status.code(), Some(126));
    assert!(
        stderr(&out).contains("nd7-exec: apply session policy"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(stdout(&out), "");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn runs_under_policy_and_passes_exit_code() {
    let root = scratch("under-policy");
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(session(&root).join("policy.sb"), strict_policy(&proj)).unwrap();

    let inside = run(
        &root,
        &format!("echo hi > {p}/x && cat {p}/x; exit 3", p = proj.display()),
    );
    assert_eq!(stdout(&inside), "hi\n", "stderr: {}", stderr(&inside));
    assert_eq!(inside.status.code(), Some(3));

    let outside = root.join("y");
    let out = run(&root, &format!("echo hi > {}", outside.display()));
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("operation not permitted"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!outside.exists());

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn signal_exit_code() {
    let root = scratch("signal");
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(session(&root).join("policy.sb"), strict_policy(&proj)).unwrap();

    // `nd7-exec` became the shell, so the signal that killed the shell is the
    // one the caller sees: there is no intermediary to turn it into a code.
    let out = run(&root, "kill -TERM $$");

    assert_eq!(out.status.code(), None);
    assert_eq!(out.status.signal(), Some(libc::SIGTERM));

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn stdin_stdout_stderr_pass_through() {
    let root = scratch("pipes");
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(session(&root).join("policy.sb"), strict_policy(&proj)).unwrap();

    let input: Vec<u8> = (0..1024 * 1024).map(|i| (i % 251) as u8).collect();
    let mut child = nd7_exec(&root, "cat; echo err >&2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // A megabyte does not fit in the pipe buffer: feed it while the child
    // drains, or both sides block.
    let mut stdin = child.stdin.take().unwrap();
    let writer = std::thread::spawn(move || stdin.write_all(&input).unwrap());
    let out = child.wait_with_output().unwrap();
    writer.join().unwrap();

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(out.stdout.len(), 1024 * 1024);
    assert!(
        out.stdout
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i % 251) as u8)
    );
    assert_eq!(stderr(&out), "err\n");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn nested_call_inside_policy_passes_through() {
    let root = scratch("nested");
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(session(&root).join("policy.sb"), strict_policy(&proj)).unwrap();

    // The inner one is already confined, so it skips the session lookup and
    // just becomes the shell.
    let out = run(&root, &format!(r#"{EXEC} -c "echo nested; exit 4""#));

    assert_eq!(stdout(&out), "nested\n", "stderr: {}", stderr(&out));
    assert_eq!(out.status.code(), Some(4));

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn cannot_nest_a_looser_sandbox() {
    let root = scratch("nest-looser");
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(session(&root).join("policy.sb"), strict_policy(&proj)).unwrap();

    let out = run(
        &root,
        r#"sandbox-exec -p "(version 1)(allow default)" /bin/sh -c "echo ESCAPED" || echo refused"#,
    );

    assert_eq!(stdout(&out), "refused\n", "stderr: {}", stderr(&out));

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn policy_change_applies_to_next_call() {
    let root = scratch("policy-change");
    let proj = root.join("proj");
    let grant = root.join("grant");
    fs::create_dir_all(&proj).unwrap();
    fs::create_dir_all(&grant).unwrap();
    let policy = session(&root).join("policy.sb");
    fs::write(&policy, strict_policy(&proj)).unwrap();

    let target = grant.join("z");
    let cmd = format!("echo hi > {}", target.display());

    let denied = run(&root, &cmd);
    assert_eq!(denied.status.code(), Some(1));
    assert!(!target.exists());

    // Nothing is restarted: the next call reads the file again.
    fs::write(
        &policy,
        format!(
            "{}(allow file-write* (subpath \"{}\"))\n",
            strict_policy(&proj),
            grant.display()
        ),
    )
    .unwrap();

    let allowed = run(&root, &cmd);
    assert!(allowed.status.success(), "stderr: {}", stderr(&allowed));
    assert_eq!(fs::read_to_string(&target).unwrap(), "hi\n");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn caller_environment_does_not_choose_the_policy() {
    let root = scratch("caller-env");
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::write(session(&root).join("policy.sb"), strict_policy(&proj)).unwrap();

    // A complete, permissive session under a HOME the caller controls. The
    // binary takes HOME from passwd, so none of this is ever looked at.
    let fake_home = root.join("fake-home");
    let fake_session = fake_home.join(format!(".nd7/sessions/{}", std::process::id()));
    fs::create_dir_all(&fake_session).unwrap();
    fs::write(
        fake_session.join("policy.sb"),
        "(version 1)\n(allow default)\n",
    )
    .unwrap();

    let outside = root.join("escaped");
    let out = nd7_exec(&root, &format!("echo hi > {}", outside.display()))
        .env("HOME", &fake_home)
        .current_dir(&fake_home)
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("operation not permitted"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!outside.exists());

    // The shell is exec'd by absolute path, so an unusable PATH changes nothing.
    let out = nd7_exec(&root, "echo hi")
        .env("PATH", "/nonexistent")
        .output()
        .unwrap();
    assert_eq!(stdout(&out), "hi\n", "stderr: {}", stderr(&out));

    fs::remove_dir_all(&root).unwrap();
}
