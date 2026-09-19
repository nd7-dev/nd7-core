#![cfg(target_os = "macos")]
//! These exercise the real kernel sandbox: every test spawns a program under an
//! Apple Seatbelt profile and observes what the kernel actually allows.

use nd7_core::{sandbox::spawn_with_profile, sbprofiles};
use std::{
    env, fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::Output,
};

/// A profile that denies everything but reading, and writing under `PROJ`.
const PROJECT_ONLY: &str = r#"(version 1)
(deny default)
(import "system.sb")
(allow process-exec process-fork)
(allow sysctl-read)
(allow file-read*)
(allow file-write* (subpath (param "PROJ")))
"#;

/// A fresh empty directory for one test, named after the test and this pid.
fn scratch(name: &str) -> PathBuf {
    let dir = env::temp_dir().join(format!("nd7-sandbox-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `subpath` matches resolved paths, and macOS temp dirs live under `/private`.
fn canonical(dir: &Path) -> String {
    dir.canonicalize()
        .unwrap()
        .into_os_string()
        .into_string()
        .unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn permissive_profile_runs_program() {
    let root = scratch("permissive");
    for sub in ["proj", "tmp", "home"] {
        fs::create_dir_all(root.join(sub)).unwrap();
    }
    let proj = canonical(&root.join("proj"));
    let tmp = canonical(&root.join("tmp"));
    let home = canonical(&root.join("home"));

    let params = [("PROJ", &*proj), ("TMP", &*tmp), ("HOME", &*home)];
    let out = spawn_with_profile(sbprofiles::CLAUDE, "/bin/sh", &params)
        .args(["-c", "echo ok"])
        .output()
        .unwrap();

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "ok\n");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn deny_default_blocks_exec() {
    // `(deny default)` denies process-exec too, so the child never reaches the
    // program: execvp fails with EPERM and `spawn()` reports it to the parent.
    let err = spawn_with_profile("(version 1)\n(deny default)", "/bin/sh", &[])
        .args(["-c", "echo ok"])
        .spawn()
        .unwrap_err();

    assert_eq!(err.raw_os_error(), Some(libc::EPERM));
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
}

#[test]
fn invalid_profile_reports_libsandbox_error() {
    let err = spawn_with_profile("(version 1)\n(this is not sbpl", "/bin/sh", &[])
        .args(["-c", "echo ok"])
        .spawn()
        .unwrap_err();

    // libsandbox rejects the profile, so `sandbox_init_with_parameters` fails
    // inside `pre_exec` and nothing is executed. Its own text ("sandbox
    // initialization failed: syntax error: expecting ')'") is printed by
    // libsandbox on the child's stderr; `pre_exec` itself can only carry an
    // errno back to the parent, and an error without one becomes EINVAL.
    assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
    assert!(!err.to_string().is_empty());
}

#[test]
fn write_allowed_only_under_project_param() {
    let root = scratch("write");
    fs::create_dir_all(root.join("proj")).unwrap();
    fs::create_dir_all(root.join("other")).unwrap();
    let proj = canonical(&root.join("proj"));
    let other = canonical(&root.join("other"));

    let inside = spawn_with_profile(PROJECT_ONLY, "/bin/sh", &[("PROJ", &proj)])
        .args(["-c", r#"echo hi > "$1/inside""#, "_", &proj])
        .output()
        .unwrap();
    assert!(inside.status.success(), "stderr: {}", stderr(&inside));
    assert_eq!(
        fs::read_to_string(root.join("proj/inside")).unwrap(),
        "hi\n"
    );

    let outside = spawn_with_profile(PROJECT_ONLY, "/bin/sh", &[("PROJ", &proj)])
        .args(["-c", r#"echo hi > "$1/outside""#, "_", &other])
        .output()
        .unwrap();
    assert_eq!(outside.status.code(), Some(1));
    assert!(!root.join("other/outside").exists());
    assert!(
        stderr(&outside).contains("Operation not permitted"),
        "stderr: {}",
        stderr(&outside)
    );

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn children_inherit_the_sandbox() {
    let root = scratch("inherit");
    fs::create_dir_all(root.join("proj")).unwrap();
    fs::create_dir_all(root.join("other")).unwrap();
    let proj = canonical(&root.join("proj"));
    let other = canonical(&root.join("other"));

    let out = spawn_with_profile(PROJECT_ONLY, "/bin/sh", &[("PROJ", &proj)])
        .args([
            "-c",
            r#"/bin/sh -c "echo hi > \"$1/outside\"" _ "$1""#,
            "_",
            &other,
        ])
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(1));
    assert!(!root.join("other/outside").exists());
    assert!(
        stderr(&out).contains("Operation not permitted"),
        "stderr: {}",
        stderr(&out)
    );

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn params_are_data_not_code() {
    let root = scratch("params");
    // A space and a double quote: if the parameter were interpolated into the
    // profile text, this would break the SBPL string literal.
    let dir = root.join(r#"nd7 "proj""#);
    fs::create_dir_all(&dir).unwrap();
    let proj = canonical(&dir);

    let out = spawn_with_profile(PROJECT_ONLY, "/bin/sh", &[("PROJ", &proj)])
        .args(["-c", r#"echo hi > "$1/inside""#, "_", &proj])
        .output()
        .unwrap();

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(fs::read_to_string(dir.join("inside")).unwrap(), "hi\n");

    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn network_filter_by_port() {
    let root = scratch("network");
    fs::create_dir_all(root.join("proj")).unwrap();
    let proj = canonical(&root.join("proj"));

    // Never accepted: the kernel backlog completes the handshake, which is all
    // `nc -z` needs. `nc` runs under the profile above unchanged; it needs no
    // extra operations beyond the `system.sb` import.
    let allowed = TcpListener::bind("127.0.0.1:0").unwrap();
    let denied = TcpListener::bind("127.0.0.1:0").unwrap();
    let allowed_port = allowed.local_addr().unwrap().port();
    let denied_port = denied.local_addr().unwrap().port();

    let profile = format!(
        "{PROJECT_ONLY}(allow network-outbound (remote tcp \"localhost:{allowed_port}\"))\n"
    );

    let ok = spawn_with_profile(&profile, "/usr/bin/nc", &[("PROJ", &proj)])
        .args(["-z", "127.0.0.1", &allowed_port.to_string()])
        .output()
        .unwrap();
    assert!(ok.status.success(), "stderr: {}", stderr(&ok));

    let blocked = spawn_with_profile(&profile, "/usr/bin/nc", &[("PROJ", &proj)])
        .args(["-z", "127.0.0.1", &denied_port.to_string()])
        .output()
        .unwrap();
    assert!(!blocked.status.success());

    fs::remove_dir_all(&root).unwrap();
}

#[test]
#[should_panic]
fn too_many_params_panics() {
    let params: Vec<(&str, &str)> = (0..9).map(|_| ("K", "v")).collect();
    spawn_with_profile("(version 1)\n(allow default)", "/bin/sh", &params);
}
