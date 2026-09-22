//! The `PreToolUse` reply that routes Claude Code's Bash commands through
//! `nd7-exec`.
//!
//! Claude Code lets a `PreToolUse` hook rewrite the call it is about to make
//! by printing `hookSpecificOutput.updatedInput`. [`respond`] turns a Bash
//! call into `<nd7-exec> -c '<the original command>'`, so the command runs
//! under the session's Seatbelt policy instead of directly.
//!
//! Three things about that reply are easy to get wrong:
//!
//! - **The whole input is echoed back.** `updatedInput` *replaces*
//!   `tool_input`, it does not merge into it (measured against Claude Code
//!   2.1.278, `docs/spikes/2026-09-20-B-claude-under-nd7.md` §B1: a reply
//!   that sent only `command` dropped the model's `description`). So the
//!   reply carries the original object with `command` swapped.
//! - **`permissionDecision` is `allow`.** Claude Code's own sandbox does the
//!   same for commands it has confined (`autoAllowBashIfSandboxed`): once the
//!   kernel is the boundary, a second prompt asks the user to re-adjudicate
//!   something the policy already decided. nd7 plays that role here, and the
//!   profile `nd7-exec` applies — not the permission dialog — is what a
//!   command is held to. Without the `allow` the same call is auto-denied in
//!   `-p` mode (§B1, runs A and B).
//! - **The rewrite is idempotent.** The model can see the rewritten command
//!   in its transcript and copy it into the next call, and another hook may
//!   have prefixed it already; a command that is already prefixed is left
//!   alone rather than wrapped twice.
//!
//! Codex CLI (0.155.1) sends the same payload, takes the same reply and calls
//! its shell tool `Bash` too, so this serves both agents unchanged
//! (`docs/spikes/2026-09-22-E-codex.md`); its `apply_patch` is a `tool_name`
//! of its own and is deliberately not rewritten, because it runs inside the
//! codex process, where only the floor applies.

use std::path::Path;

use serde_json::{Value, json};

/// Why a `PreToolUse` payload could not be answered.
#[derive(Debug)]
pub enum Error {
    /// The payload is not valid JSON, or not a JSON object.
    Json(serde_json::Error),
    /// A Bash payload whose `tool_input` is missing or is not an object.
    ToolInput,
    /// A Bash payload whose `tool_input.command` is missing or is not a string.
    Command,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Json(e) => write!(f, "hook payload is not a JSON object: {e}"),
            Error::ToolInput => write!(f, "Bash hook payload has no tool_input object"),
            Error::Command => write!(f, "Bash tool_input has no command string"),
        }
    }
}

impl std::error::Error for Error {}

/// The reply to a `PreToolUse` hook payload that makes Claude Code run its
/// Bash command through `nd7-exec` at `exit`. `None` means "print nothing":
/// the tool is not Bash, or the command is already prefixed.
pub fn respond(payload: &str, exit: &Path) -> Result<Option<String>, Error> {
    let value: Value = serde_json::from_str(payload).map_err(Error::Json)?;
    let Value::Object(payload) = value else {
        return Err(Error::Json(serde::de::Error::custom(format!(
            "expected a JSON object, got {value}"
        ))));
    };

    if let Some(name) = payload.get("hook_event_name").and_then(Value::as_str)
        && name != "PreToolUse"
    {
        return Ok(None);
    }
    if payload.get("tool_name").and_then(Value::as_str) != Some("Bash") {
        return Ok(None);
    }

    let Some(Value::Object(tool_input)) = payload.get("tool_input") else {
        return Err(Error::ToolInput);
    };
    let Some(Value::String(command)) = tool_input.get("command") else {
        return Err(Error::Command);
    };

    // The exit path comes from `nd7 run`, never from the payload, but it
    // still lands inside a shell command, so anything beyond a bare pathname
    // is quoted like the command itself.
    let exit = exit.to_string_lossy();
    let exit = if exit
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/' | '-'))
    {
        exit.into_owned()
    } else {
        shell_single_quote(&exit)
    };

    let prefix = format!("{exit} -c ");
    if command.trim_start().starts_with(&prefix) {
        return Ok(None);
    }

    let mut updated = tool_input.clone();
    updated.insert(
        "command".to_owned(),
        Value::String(format!("{prefix}{}", shell_single_quote(command))),
    );

    let reply = json!({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "allow",
            "permissionDecisionReason":
                "nd7: the command runs under this session's sandbox policy",
            "updatedInput": Value::Object(updated),
        }
    });
    Ok(Some(reply.to_string()))
}

/// `s` as one POSIX shell word: single-quoted, with each `'` closed, escaped
/// and reopened. Everything else — `$`, `"`, backslashes, newlines — is
/// literal inside single quotes and passes through untouched.
fn shell_single_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if c == '\'' {
            out.push_str(r"'\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXIT: &str = "/usr/local/bin/nd7-exec";

    /// A `PreToolUse` Bash payload carrying `tool_input`.
    fn payload(tool_input: &str) -> String {
        format!(
            r#"{{"session_id":"s","transcript_path":"/t","cwd":"/",
                "hook_event_name":"PreToolUse","tool_name":"Bash",
                "tool_input":{tool_input},"tool_use_id":"toolu_01"}}"#
        )
    }

    fn reply(payload: &str, exit: &str) -> Value {
        let json = respond(payload, Path::new(exit)).unwrap().unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn quotes_are_posix() {
        assert_eq!(shell_single_quote("a'b"), r"'a'\''b'");
        assert_eq!(shell_single_quote(""), "''");
        assert_eq!(
            shell_single_quote("$HOME \"x\" \\ \n"),
            "'$HOME \"x\" \\ \n'"
        );
    }

    #[test]
    fn bash_call_is_prefixed_and_keeps_the_rest_of_the_input() {
        let out = reply(
            &payload(r#"{"command":"echo hi","description":"say hi"}"#),
            EXIT,
        );
        let out = &out["hookSpecificOutput"];
        assert_eq!(out["hookEventName"], "PreToolUse");
        assert_eq!(out["permissionDecision"], "allow");
        assert_eq!(
            out["updatedInput"]["command"],
            format!("{EXIT} -c 'echo hi'")
        );
        assert_eq!(out["updatedInput"]["description"], "say hi");
    }

    #[test]
    fn the_original_command_survives_quoting() {
        let command = "grep 'a b' $HOME/x | wc -l\necho \"done\"";
        let input = json!({ "command": command }).to_string();
        let out = reply(&payload(&input), EXIT);
        assert_eq!(
            out["hookSpecificOutput"]["updatedInput"]["command"],
            format!("{EXIT} -c {}", shell_single_quote(command))
        );
    }

    #[test]
    fn exit_path_with_a_space_is_quoted() {
        let exit = "/Users/a b/nd7-exec";
        let out = reply(&payload(r#"{"command":"echo hi"}"#), exit);
        assert_eq!(
            out["hookSpecificOutput"]["updatedInput"]["command"],
            "'/Users/a b/nd7-exec' -c 'echo hi'"
        );
    }

    #[test]
    fn other_tools_and_other_events_are_left_alone() {
        let write = r#"{"session_id":"s","transcript_path":"/t","cwd":"/",
            "hook_event_name":"PreToolUse","tool_name":"Write",
            "tool_input":{"file_path":"/a","content":"x"}}"#;
        assert_eq!(respond(write, Path::new(EXIT)).unwrap(), None);

        let post = r#"{"session_id":"s","transcript_path":"/t","cwd":"/",
            "hook_event_name":"PostToolUse","tool_name":"Bash",
            "tool_input":{"command":"echo hi"},"tool_response":{}}"#;
        assert_eq!(respond(post, Path::new(EXIT)).unwrap(), None);
    }

    #[test]
    fn an_already_prefixed_command_is_left_alone() {
        let done = payload(&json!({ "command": format!("{EXIT} -c 'echo hi'") }).to_string());
        assert_eq!(respond(&done, Path::new(EXIT)).unwrap(), None);

        let indented =
            payload(&json!({ "command": format!("   {EXIT} -c 'echo hi'") }).to_string());
        assert_eq!(respond(&indented, Path::new(EXIT)).unwrap(), None);

        let spaced = "/Users/a b/nd7-exec";
        let quoted = payload(&json!({ "command": format!("'{spaced}' -c 'echo hi'") }).to_string());
        assert_eq!(respond(&quoted, Path::new(spaced)).unwrap(), None);
    }

    #[test]
    fn malformed_payloads_say_which_field() {
        let cases = [
            (
                r#"{"hook_event_name":"PreToolUse","tool_name":"Bash"}"#,
                "tool_input",
            ),
            (
                r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":[]}"#,
                "tool_input",
            ),
            (
                r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{}}"#,
                "command",
            ),
            (
                r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":7}}"#,
                "command",
            ),
            ("nope", "JSON"),
            ("[]", "JSON"),
        ];
        for (payload, field) in cases {
            let e = respond(payload, Path::new(EXIT)).unwrap_err();
            let shown = e.to_string();
            assert!(shown.contains(field), "{payload}: {shown}");
        }
    }

    /// The quoting is transparent: the shell sees the same command either
    /// way. Only the shell can settle that, so this asks one.
    #[test]
    #[cfg(target_os = "macos")]
    fn zsh_runs_the_quoted_command_unchanged() {
        use std::process::Command;

        for original in [
            "echo 'a b' | tr a-z A-Z",
            r#"printf '%s\n' "x y""#,
            "echo $((1+1))",
        ] {
            let run = |script: &str| {
                let out = Command::new("/bin/zsh")
                    .args(["-c", script])
                    .output()
                    .unwrap();
                assert!(out.status.success(), "{script}");
                String::from_utf8(out.stdout).unwrap()
            };
            // `zsh -c <quoted>` runs the quoted word as the whole script.
            let quoted = shell_single_quote(original);
            let via_quote = run(&format!("/bin/zsh -c {quoted}"));
            assert_eq!(via_quote, run(original), "{original}");
        }
    }
}
