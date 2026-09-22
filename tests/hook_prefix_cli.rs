//! `nd7 hook-prefix` speaks only inside a session.
//!
//! `nd7 init` leaves the hook in the agent's own configuration, so it fires
//! for every session the agent starts, not only the ones `nd7 run` wrapped.
//! Outside one there is no policy for `nd7-exec` to apply and it would refuse
//! the command, so the hook must print nothing at all.

use std::{
    io::Write,
    process::{Command, Stdio},
};

const ND7: &str = env!("CARGO_BIN_EXE_nd7");

const PAYLOAD: &str = r#"{"session_id":"s","transcript_path":"/t","cwd":"/",
    "hook_event_name":"PreToolUse","tool_name":"Bash",
    "tool_input":{"command":"echo hi"},"tool_use_id":"toolu_01"}"#;

/// `nd7 hook-prefix` with the payload on stdin, and `ND7_SESSION` as given.
fn hook_prefix(session: Option<&str>) -> String {
    let mut cmd = Command::new(ND7);
    cmd.arg("hook-prefix")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped());
    match session {
        Some(pid) => cmd.env("ND7_SESSION", pid),
        None => cmd.env_remove("ND7_SESSION"),
    };

    let mut child = cmd.spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(PAYLOAD.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "exit {:?}", out.status.code());
    String::from_utf8(out.stdout).unwrap()
}

#[test]
fn outside_a_session_the_hook_says_nothing() {
    assert_eq!(hook_prefix(None), "");
}

#[test]
fn inside_a_session_the_bash_command_is_rewritten() {
    let reply = hook_prefix(Some("1"));
    assert!(
        reply.contains("\"permissionDecision\":\"allow\""),
        "{reply}"
    );
    assert!(reply.contains("nd7-exec"), "{reply}");
}
