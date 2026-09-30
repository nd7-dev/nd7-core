#![cfg(target_os = "macos")]
//! The whole trampoline, end to end: `nd7 run` puts a floor profile around a
//! shell, and `nd7-exec` — the one binary that floor lets out with
//! `(with no-sandbox)` — replaces it with the session policy.
//!
//! Inside `nd7 run` the ancestry is `nd7-exec` -> zsh -> `nd7 run` -> this test
//! process, so the session is named after this process, the outermost ancestor.
//! That mirrors production, where `nd7 run` is the ancestor holding the record.

use std::{
    env, fs,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    thread,
};

const EXEC: &str = env!("CARGO_BIN_EXE_nd7-exec");
const ND7: &str = env!("CARGO_BIN_EXE_nd7");

/// A scratch root with `proj/` and `out/`, a floor profile, and a session for
/// this process. Returns the root, the writable project directory, and the
/// floor profile's path.
fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf) {
    let root = env::temp_dir().join(format!("nd7-e2e-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    // `subpath` matches resolved paths, and macOS temp dirs live under
    // `/private`.
    let root = root.canonicalize().unwrap();

    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    fs::create_dir_all(root.join("out")).unwrap();
    fs::create_dir_all(root.join(format!("sessions/{}", std::process::id()))).unwrap();

    let floor = root.join("floor.sb");
    fs::write(
        &floor,
        format!(
            r#"(version 1)
(deny default)
(import "system.sb")
(allow process-fork sysctl-read file-read* file-ioctl signal)
(allow process-exec (literal "/bin/zsh") (literal "/bin/sh") (literal "/usr/bin/true") (literal "/bin/sleep"))
(allow file-write* (subpath "{proj}"))
(allow process-exec (with no-sandbox) (literal "{EXEC}"))
"#,
            proj = proj.display()
        ),
    )
    .unwrap();

    (root, proj, floor)
}

/// The session policy: everything denied but reading, execing, and writing
/// under `dir`. Deliberately allows more exec than the floor does.
fn write_policy(root: &Path, dir: &Path) {
    fs::write(
        root.join(format!("sessions/{}/policy.sb", std::process::id())),
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
        ),
    )
    .unwrap();
}

fn nd7_run(root: &Path, floor: &Path, script: &str) -> Command {
    let mut c = Command::new(ND7);
    c.args(["run", "--profile"])
        .arg(floor)
        .args(["/bin/zsh", "-c", script])
        // Inherited all the way down to nd7-exec.
        .env("ND7_SESSIONS_DIR", root.join("sessions"));
    c
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn unprefixed_exec_is_denied_by_floor() {
    let (root, proj, floor) = setup("floor-exec");

    // `/usr/bin/touch` is not on the floor's exec list, so the shell's execve
    // fails with EPERM and zsh reports it the way it reports a command it
    // cannot run: exit 127.
    let denied = nd7_run(
        &root,
        &floor,
        &format!("/usr/bin/touch {}/a", proj.display()),
    )
    .output()
    .unwrap();
    assert_eq!(
        denied.status.code(),
        Some(127),
        "stderr: {}",
        stderr(&denied)
    );
    assert!(
        stderr(&denied).contains("operation not permitted: /usr/bin/touch"),
        "stderr: {}",
        stderr(&denied)
    );
    assert!(!proj.join("a").exists());

    // The same write as a shell builtin needs no exec, and the floor allows
    // the directory.
    let allowed = nd7_run(&root, &floor, &format!("echo hi > {}/b", proj.display()))
        .output()
        .unwrap();
    assert!(allowed.status.success(), "stderr: {}", stderr(&allowed));
    assert_eq!(fs::read_to_string(proj.join("b")).unwrap(), "hi\n");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn prefixed_command_leaves_floor_and_gets_policy() {
    let (root, proj, floor) = setup("prefixed");
    write_policy(&root, &proj);

    // `touch` is denied by the floor and allowed by the policy: running it
    // proves nd7-exec left the floor and applied a fresh profile.
    let out = nd7_run(
        &root,
        &floor,
        &format!(
            r#"{EXEC} -c "/usr/bin/touch {}/c && echo ok""#,
            proj.display()
        ),
    )
    .output()
    .unwrap();
    assert_eq!(stdout(&out), "ok\n", "stderr: {}", stderr(&out));
    assert!(proj.join("c").exists());

    // The fresh profile is not a wider one: a write outside `proj` is denied
    // by the policy just as it was by the floor.
    let outside = root.join("out/d");
    let out = nd7_run(
        &root,
        &floor,
        &format!(r#"{EXEC} -c "echo hi > {}""#, outside.display()),
    )
    .output()
    .unwrap();
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
fn exit_is_not_available_inside_the_policy() {
    let (root, proj, floor) = setup("no-second-exit");
    write_policy(&root, &proj);

    // The policy has no `no-sandbox` rule of its own, so the one-time exit the
    // floor granted cannot be taken again from inside it.
    let out = nd7_run(
        &root,
        &floor,
        &format!(
            r#"{EXEC} -c 'sandbox-exec -p "(version 1)(allow default)" /usr/bin/true && echo ESCAPED || echo refused'"#
        ),
    )
    .output()
    .unwrap();

    assert_eq!(stdout(&out), "refused\n", "stderr: {}", stderr(&out));

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn detached_caller_cannot_escape() {
    let (root, proj, floor) = setup("detached");
    write_policy(&root, &proj);
    let escape = root.join("out/esc");

    // The session is found by walking ppids, so a caller that outlives its
    // ancestry should find nothing. `disown` plus `exit` reparents the
    // background subshell to pid 1 within microseconds; the `sleep` makes
    // nd7-exec start its walk a full second after that.
    //
    // `output()` returns only once every writer of the stderr pipe is gone, so
    // the detached nd7-exec's refusal is captured without a sleep here.
    let out = nd7_run(
        &root,
        &floor,
        &format!(
            r#"( /bin/sleep 1; {EXEC} -c "echo hi > {}" ) & disown; exit"#,
            escape.display()
        ),
    )
    .output()
    .unwrap();

    assert!(
        stderr(&out).contains("nd7-exec: no nd7 session"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!escape.exists());

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn caller_cwd_does_not_widen() {
    let (root, proj, floor) = setup("cwd");
    write_policy(&root, &proj);
    let outside = root.join("out");

    // The cwd is only a cwd: nothing in the policy is derived from it.
    let out = nd7_run(&root, &floor, &format!(r#"{EXEC} -c "echo hi > ./esc""#))
        .current_dir(&outside)
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("operation not permitted"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!outside.join("esc").exists());

    fs::remove_dir_all(&root).unwrap();
}

/// The real path, no `--profile`: `nd7 run` builds the policy from its cwd,
/// creates the session, applies the rendered floor, and removes the session
/// when the program exits. The exit is the `nd7-exec` built next to `nd7`, and
/// `ND7_SESSIONS_DIR` keeps the record out of `~/.nd7`.
#[test]
fn nd7_run_creates_the_session_and_applies_the_rendered_floor() {
    let (root, proj, _floor) = setup("real-run");
    let sessions = root.join("sessions");
    // The rendered profiles allow the temp dir, where `root` lives, so a
    // denied target has to be elsewhere: /private/tmp outside `claude-*`.
    let outside = PathBuf::from(format!(
        "/private/tmp/nd7-e2e-outside-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&outside);
    fs::create_dir_all(&outside).unwrap();
    // `setup` made a session for this process; the real run makes its own,
    // named after `nd7 run`'s pid, which is what nd7-exec must find.
    fs::remove_dir_all(sessions.join(std::process::id().to_string())).unwrap();

    let script = format!(
        r#"ls {sessions} | tr '\n' ' '; echo;
           {EXEC} -c "echo hi > {proj}/via-exec && echo exec-ok";
           {EXEC} -c "echo hi > {outside}/esc" 2>&1 | grep -o 'operation not permitted' | head -1;
           echo hi > {outside}/direct"#,
        sessions = sessions.display(),
        proj = proj.display(),
        outside = outside.display()
    );
    let out = Command::new(ND7)
        .args(["run", "/bin/zsh", "-c", &script])
        .current_dir(&proj)
        .env("ND7_SESSIONS_DIR", &sessions)
        .output()
        .unwrap();
    let stdout = stdout(&out);
    let mut lines = stdout.lines();

    // The session existed while the program ran, named after a pid that is
    // not this test's.
    let listed = lines.next().unwrap_or("").trim().to_owned();
    assert!(
        !listed.is_empty(),
        "no session listed; stderr: {}",
        stderr(&out)
    );
    assert_ne!(listed, std::process::id().to_string());
    // A prefixed command got the policy: the project is writable.
    assert_eq!(
        lines.next(),
        Some("exec-ok"),
        "stdout: {stdout}\nstderr: {}",
        stderr(&out)
    );
    assert_eq!(fs::read_to_string(proj.join("via-exec")).unwrap(), "hi\n");
    // Outside the project is denied through nd7-exec (the policy) ...
    assert_eq!(
        lines.next(),
        Some("operation not permitted"),
        "stdout: {stdout}\nstderr: {}",
        stderr(&out)
    );
    assert!(!outside.join("esc").exists());
    // ... and directly (the floor). zsh reports a failed redirection on its
    // own stderr before running the command, so it shows up there.
    assert!(
        stderr(&out).contains("operation not permitted: ") && stderr(&out).contains("/direct"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!outside.join("direct").exists());
    assert!(
        !out.status.success(),
        "the last command failed, so the shell must too"
    );
    // And the session is gone once nd7 run returned.
    assert!(
        !sessions.join(&listed).exists(),
        "session {listed} left behind"
    );
    assert!(
        stderr(&out).contains("nd7 run: session"),
        "stderr: {}",
        stderr(&out)
    );

    fs::remove_dir_all(&root).unwrap();
    fs::remove_dir_all(&outside).unwrap();
}

/// A root under `/private/tmp`, not the temp dir: a Unix socket path may be at
/// most 103 bytes on macOS, and the canonical temp dir alone uses half of
/// them. Returns the root and the project directory inside it.
fn short_root(name: &str) -> (PathBuf, PathBuf) {
    let root = PathBuf::from(format!(
        "/private/tmp/nd7-e2e-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let proj = root.join("proj");
    fs::create_dir_all(&proj).unwrap();
    (root, proj)
}

/// A stand-in for the user's ssh-agent at `path`: it answers each connection
/// with the first line it receives, then hangs up. Bytes that come back have
/// gone through both directions of whatever sits in between.
fn echo_agent(path: &Path) {
    let listener = UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        for conn in listener.incoming().flatten() {
            let mut line = String::new();
            let mut reader = BufReader::new(conn);
            if reader.read_line(&mut line).is_ok() {
                let _ = reader.get_mut().write_all(line.as_bytes());
            }
        }
    });
}

/// With an agent in the environment, `nd7 run` hands the program a socket of
/// its own inside the session directory, carries bytes through it in both
/// directions, and keeps the real agent's socket out of reach.
#[test]
fn nd7_run_proxies_the_ssh_agent_through_the_session() {
    let (root, proj) = short_root("ssh");
    let sessions = root.join("sessions");
    let upstream = root.join("agent.sock");
    echo_agent(&upstream);

    // `-w 5`: if the proxy swallows the reply, fail instead of hanging.
    let script = format!(
        r#"echo "$SSH_AUTH_SOCK";
           echo ping | /usr/bin/nc -w 5 -U "$SSH_AUTH_SOCK";
           /usr/bin/nc -w 5 -U {upstream} </dev/null 2>/dev/null; echo "direct=$?""#,
        upstream = upstream.display()
    );
    let out = Command::new(ND7)
        .args(["run", "/bin/zsh", "-c", &script])
        .current_dir(&proj)
        .env("ND7_SESSIONS_DIR", &sessions)
        .env("SSH_AUTH_SOCK", &upstream)
        .output()
        .unwrap();
    let stdout = stdout(&out);
    let mut lines = stdout.lines();

    // The program sees nd7's socket, in this run's session, not the agent's.
    let sock = PathBuf::from(lines.next().unwrap_or("").trim());
    assert!(
        sock.starts_with(&sessions) && sock.ends_with("ssh.sock"),
        "SSH_AUTH_SOCK inside the run was {}; stderr: {}",
        sock.display(),
        stderr(&out)
    );
    assert_ne!(sock, upstream);
    // Through it, the agent answers.
    assert_eq!(
        lines.next(),
        Some("ping"),
        "stdout: {stdout}\nstderr: {}",
        stderr(&out)
    );
    // Around it, the agent is unreachable: the floor names only the proxy.
    assert_eq!(
        lines.next(),
        Some("direct=1"),
        "stdout: {stdout}\nstderr: {}",
        stderr(&out)
    );

    fs::remove_dir_all(&root).unwrap();
}

/// Without an agent there is nothing to proxy: the program inherits no
/// `SSH_AUTH_SOCK`, and the session holds no socket.
#[test]
fn nd7_run_without_an_agent_offers_no_socket() {
    let (root, proj) = short_root("no-ssh");
    let sessions = root.join("sessions");

    let script = format!(
        r#"echo "${{SSH_AUTH_SOCK:-unset}}"; ls {}/*/"#,
        sessions.display()
    );
    let out = Command::new(ND7)
        .args(["run", "/bin/zsh", "-c", &script])
        .current_dir(&proj)
        .env("ND7_SESSIONS_DIR", &sessions)
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .unwrap();
    let stdout = stdout(&out);
    let mut lines = stdout.lines();

    assert_eq!(
        lines.next(),
        Some("unset"),
        "stdout: {stdout}\nstderr: {}",
        stderr(&out)
    );
    let listed: Vec<&str> = lines.collect();
    assert!(
        listed.contains(&"policy.sb") && !listed.contains(&"ssh.sock"),
        "session dir held {listed:?}; stderr: {}",
        stderr(&out)
    );

    fs::remove_dir_all(&root).unwrap();
}
