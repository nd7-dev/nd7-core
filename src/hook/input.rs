//! Typed model of the Claude Code hook payloads nd7 reads.
//!
//! Claude Code delivers one JSON object per hook invocation on stdin. Every
//! payload carries the [`Common`] fields plus fields specific to the event
//! named in `hook_event_name` (the hooks reference,
//! <https://code.claude.com/docs/en/hooks>, read on 2026-09-18).
//!
//! Only the seven events the event model reads have a typed body. Every other
//! event, documented or not, becomes [`HookEvent::Other`] and is kept whole in
//! [`HookInput::raw`], so a body that changes upstream cannot cost nd7 a
//! record.
//!
//! Design rules:
//!
//! - Field names match the wire format. Rust keywords (`type`) are renamed
//!   and annotated.
//! - Closed value sets are enums with an `Other(String)` fallback so that a
//!   new value in a future Claude Code release parses instead of erroring.
//! - Tool inputs and responses are tool-specific and undocumented beyond
//!   their examples, so they stay `serde_json::Value`.

use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// A fully parsed hook payload: the common envelope and the event body.
///
/// Built via [`FromStr`] (`raw.parse::<HookInput>()`) rather than derived, because
/// `hook_event_name` belongs to both halves.
#[derive(Debug, Clone, PartialEq)]
pub struct HookInput {
    pub common: Common,
    pub event: HookEvent,
    /// The payload as received. Stored whole, and the only record of an
    /// event without a typed body.
    pub raw: Map<String, Value>,
}

/// Why a payload could not be turned into a [`HookInput`].
#[derive(Debug)]
pub enum ParseError {
    /// The input is not valid JSON, or not a JSON object.
    Json(serde_json::Error),
    /// `hook_event_name` is missing or not a string.
    MissingEventName,
    /// The common fields did not deserialize.
    Common(serde_json::Error),
    /// The event has a typed body and the payload did not match it.
    Event {
        name: String,
        source: serde_json::Error,
    },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseError::Json(e) => write!(f, "hook payload is not a JSON object: {e}"),
            ParseError::MissingEventName => write!(f, "hook payload has no hook_event_name"),
            ParseError::Common(e) => write!(f, "hook common fields: {e}"),
            ParseError::Event { name, source } => write!(f, "hook event {name}: {source}"),
        }
    }
}

impl std::error::Error for ParseError {}

impl FromStr for HookInput {
    type Err = ParseError;

    /// Parse a raw hook payload: `raw.parse::<HookInput>()`.
    ///
    /// An event without a typed body degrades to [`HookEvent::Other`]; one of
    /// the seven with a body that does not match is [`ParseError::Event`].
    fn from_str(raw: &str) -> Result<Self, ParseError> {
        let value: Value = serde_json::from_str(raw).map_err(ParseError::Json)?;
        let Some(raw) = value.as_object() else {
            return Err(ParseError::Json(serde::de::Error::custom(format!(
                "expected a JSON object, got {value}"
            ))));
        };

        let name = raw
            .get("hook_event_name")
            .and_then(Value::as_str)
            .ok_or(ParseError::MissingEventName)?;

        // Both halves deserialize from a borrow, so the payload is copied
        // once: for the `raw` the event keeps.
        let common = Common::deserialize(&value).map_err(ParseError::Common)?;
        let event = if HookEvent::TYPED_NAMES.contains(&name) {
            HookEvent::deserialize(&value).map_err(|source| ParseError::Event {
                name: name.to_owned(),
                source,
            })?
        } else {
            HookEvent::Other {
                name: name.to_owned(),
            }
        };

        Ok(HookInput {
            common,
            event,
            raw: raw.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Common fields
// ---------------------------------------------------------------------------

/// Fields present on every hook payload.
///
/// `permission_mode` is documented as common but is absent on several events
/// (for example `SessionEnd`), so it is optional here.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Common {
    pub session_id: String,
    /// Kept verbatim even though [`HookEvent`] is derived from it, so a
    /// renamed or unknown event is never lost.
    pub hook_event_name: String,
    /// `null` from Codex under `--ephemeral`, and absent in nothing we have
    /// seen; kept optional so a payload without a transcript still records.
    #[serde(default)]
    pub transcript_path: Option<String>,
    pub cwd: String,
    #[serde(default)]
    pub permission_mode: Option<PermissionMode>,
    /// UUID of the user prompt being processed. Claude Code >= 2.1.196.
    /// Absent until the first user input.
    #[serde(default)]
    pub prompt_id: Option<String>,
    /// Present only when the hook fires inside a subagent.
    #[serde(default)]
    pub agent_id: Option<String>,
    /// Present with `--agent` or inside a subagent.
    #[serde(default)]
    pub agent_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PermissionMode {
    #[serde(rename = "default")]
    Default,
    #[serde(rename = "plan")]
    Plan,
    #[serde(rename = "acceptEdits")]
    AcceptEdits,
    #[serde(rename = "auto")]
    Auto,
    #[serde(rename = "dontAsk")]
    DontAsk,
    #[serde(rename = "bypassPermissions")]
    BypassPermissions,
    #[serde(untagged)]
    Other(String),
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Event-specific body of a hook payload, discriminated by `hook_event_name`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "hook_event_name")]
pub enum HookEvent {
    SessionStart(SessionStart),
    SessionEnd(SessionEnd),
    UserPromptSubmit(UserPromptSubmit),
    Stop(Stop),
    PreToolUse(PreToolUse),
    PostToolUse(PostToolUse),
    PostToolUseFailure(PostToolUseFailure),

    /// An event with no typed body. The payload is in [`HookInput::raw`].
    #[serde(skip)]
    Other {
        name: String,
    },
}

impl HookEvent {
    /// The `hook_event_name` values with a typed body; everything else parses
    /// to [`HookEvent::Other`].
    const TYPED_NAMES: [&'static str; 7] = [
        "SessionStart",
        "SessionEnd",
        "UserPromptSubmit",
        "Stop",
        "PreToolUse",
        "PostToolUse",
        "PostToolUseFailure",
    ];
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SessionStart {
    pub source: SessionSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionSource {
    Startup,
    Resume,
    Clear,
    Compact,
    Fork,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct SessionEnd {
    pub reason: SessionEndReason,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    Clear,
    Resume,
    Logout,
    PromptInputExit,
    Other,
    /// Any value not listed above. `bypass_permissions_disabled` was removed
    /// in Claude Code 2.1.234 and would land here.
    #[serde(untagged)]
    Unrecognised(String),
}

// ---------------------------------------------------------------------------
// Prompt and output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct UserPromptSubmit {
    /// The text the user submitted, verbatim.
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Stop {
    /// `true` when Claude Code is already continuing because of a stop hook.
    pub stop_hook_active: bool,
    /// Text content of Claude's final response for this turn.
    #[serde(default)]
    pub last_assistant_message: Option<String>,
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// The tool-call triple shared by every tool event that has a `tool_use_id`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct ToolUse {
    /// `Bash`, `Edit`, `Write`, `Read`, `mcp__<server>__<tool>`, etc.
    pub tool_name: String,
    /// Tool-specific arguments, verbatim. For `Bash` this includes `command`;
    /// for `Write` / `Edit` / `Read`, `file_path` is always absolute.
    pub tool_input: Value,
    /// Pairs `PreToolUse` with its `PostToolUse` / `PostToolUseFailure`.
    pub tool_use_id: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PreToolUse {
    #[serde(flatten)]
    pub tool: ToolUse,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PostToolUse {
    #[serde(flatten)]
    pub tool: ToolUse,
    /// The tool's structured output object, for example
    /// `{"filePath": "...", "type": "create"}` for `Write`. Tool-specific.
    pub tool_response: Value,
    /// Execution time excluding permission prompts and PreToolUse hooks.
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct PostToolUseFailure {
    #[serde(flatten)]
    pub tool: ToolUse,
    /// What went wrong. For `Bash` / `PowerShell` the first line is usually
    /// `Exit code N`; treat the rest as display text.
    pub error: String,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

// ---------------------------------------------------------------------------
// Tests: the JSON examples from the hooks reference, verbatim.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> HookInput {
        raw.parse::<HookInput>().unwrap_or_else(|e| panic!("{e}"))
    }

    #[test]
    fn pre_tool_use_bash() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "prompt_id": "550e8400-e29b-41d4-a716-446655440000",
              "transcript_path": "/home/user/.claude/projects/.../transcript.jsonl",
              "cwd": "/home/user/my-project",
              "scratchpad_dir": "/tmp/claude-1000/-home-user-my-project/abc123/scratchpad",
              "permission_mode": "default",
              "hook_event_name": "PreToolUse",
              "tool_name": "Bash",
              "tool_input": {
                "command": "npm test",
                "description": "Run test suite",
                "timeout": 120000,
                "run_in_background": false
              },
              "tool_use_id": "toolu_01ABC123..."
            }"#,
        );
        assert_eq!(input.common.permission_mode, Some(PermissionMode::Default));
        assert_eq!(
            input.common.prompt_id.as_deref(),
            Some("550e8400-e29b-41d4-a716-446655440000")
        );
        let HookEvent::PreToolUse(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.tool.tool_name, "Bash");
        assert_eq!(e.tool.tool_input["command"], "npm test");
        assert_eq!(e.tool.tool_use_id, "toolu_01ABC123...");
    }

    #[test]
    fn session_start_reads_only_the_source() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/...",
              "hook_event_name": "SessionStart",
              "source": "resume",
              "model": "claude-opus-5",
              "seconds_since_last_response": 5400,
              "context_tokens": 182340,
              "prompt_cache_likely_expired": true,
              "estimated_cache_write_usd": 1.1396
            }"#,
        );
        assert!(input.common.permission_mode.is_none());
        let HookEvent::SessionStart(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.source, SessionSource::Resume);
    }

    #[test]
    fn post_tool_use_write() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/...",
              "permission_mode": "default",
              "hook_event_name": "PostToolUse",
              "tool_name": "Write",
              "tool_input": { "file_path": "/path/to/file.txt", "content": "file content" },
              "tool_response": { "filePath": "/path/to/file.txt", "type": "create" },
              "tool_use_id": "toolu_01ABC123...",
              "duration_ms": 12
            }"#,
        );
        let HookEvent::PostToolUse(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.tool.tool_name, "Write");
        assert_eq!(e.tool_response["type"], "create");
        assert_eq!(e.duration_ms, Some(12));
    }

    #[test]
    fn post_tool_use_failure() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/...",
              "permission_mode": "default",
              "hook_event_name": "PostToolUseFailure",
              "tool_name": "Bash",
              "tool_input": { "command": "npm test", "description": "Run test suite" },
              "tool_use_id": "toolu_01ABC123...",
              "error": "Exit code 1\nError: Cannot find module 'express'",
              "is_interrupt": false,
              "duration_ms": 4187
            }"#,
        );
        let HookEvent::PostToolUseFailure(e) = input.event else {
            panic!("wrong variant")
        };
        assert!(e.error.starts_with("Exit code 1"));
    }

    #[test]
    fn stop_reads_past_the_tasks_and_crons() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "~/.claude/projects/.../t.jsonl",
              "cwd": "/Users/...",
              "permission_mode": "default",
              "hook_event_name": "Stop",
              "stop_hook_active": true,
              "last_assistant_message": "I've completed the refactoring. Here's a summary...",
              "background_tasks": [
                { "id": "task-001", "type": "shell", "status": "running", "description": "tail logs", "command": "tail -f /var/log/syslog" }
              ],
              "session_crons": [
                { "id": "cron-001", "schedule": "0 9 * * 1-5", "recurring": true, "prompt": "check the build" }
              ]
            }"#,
        );
        let HookEvent::Stop(e) = input.event else {
            panic!("wrong variant")
        };
        assert!(e.stop_hook_active);
        assert!(
            e.last_assistant_message
                .unwrap()
                .starts_with("I've completed")
        );
    }

    #[test]
    fn every_typed_name_parses_into_its_own_body() {
        let base = r#""session_id": "s", "transcript_path": "/t", "cwd": "/""#;
        let bodies = [
            r#""hook_event_name": "SessionStart", "source": "startup""#,
            r#""hook_event_name": "SessionEnd", "reason": "clear""#,
            r#""hook_event_name": "UserPromptSubmit", "prompt": "hi""#,
            r#""hook_event_name": "Stop", "stop_hook_active": false"#,
            r#""hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {}, "tool_use_id": "t1""#,
            r#""hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {}, "tool_use_id": "t1", "tool_response": {}"#,
            r#""hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "tool_input": {}, "tool_use_id": "t1", "error": "boom""#,
        ];
        assert_eq!(bodies.len(), HookEvent::TYPED_NAMES.len());
        for body in bodies {
            let input = parse(&format!("{{{base}, {body}}}"));
            assert!(
                !matches!(input.event, HookEvent::Other { .. }),
                "{body} has a typed body"
            );
        }
    }

    #[test]
    fn unknown_enum_values_fall_through() {
        let input = parse(
            r#"{"session_id": "s", "transcript_path": "/t", "cwd": "/", "permission_mode": "somethingNew",
               "hook_event_name": "SessionEnd", "reason": "bypass_permissions_disabled"}"#,
        );
        assert_eq!(
            input.common.permission_mode,
            Some(PermissionMode::Other("somethingNew".into()))
        );
        let HookEvent::SessionEnd(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(
            e.reason,
            SessionEndReason::Unrecognised("bypass_permissions_disabled".into())
        );
    }

    #[test]
    fn an_event_without_a_typed_body_is_kept_whole() {
        // Documented upstream, and its body is not checked here: a `trigger`
        // of the wrong type still records.
        let input = parse(
            r#"{"session_id": "s", "transcript_path": "/t", "cwd": "/",
               "hook_event_name": "PreCompact", "trigger": {"not": "a string"}}"#,
        );
        let HookEvent::Other { name } = &input.event else {
            panic!("wrong variant")
        };
        assert_eq!(name, "PreCompact");
        assert_eq!(input.raw["trigger"]["not"], "a string");

        let input = parse(
            r#"{"session_id": "s", "transcript_path": "/t", "cwd": "/", "hook_event_name": "FutureThing", "x": 1}"#,
        );
        let payload = input.raw;
        let HookEvent::Other { name } = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(name, "FutureThing");
        assert_eq!(payload["x"], 1);
    }

    #[test]
    fn errors_are_distinguished() {
        assert!(matches!(
            "nope".parse::<HookInput>(),
            Err(ParseError::Json(_))
        ));
        assert!(matches!(
            r#"{"session_id": "s"}"#.parse::<HookInput>(),
            Err(ParseError::MissingEventName)
        ));
        assert!(matches!(
            r#"{"hook_event_name": "Stop"}"#.parse::<HookInput>(),
            Err(ParseError::Common(_))
        ));
        assert!(matches!(
            r#"{"session_id": "s", "transcript_path": "/t", "cwd": "/", "hook_event_name": "Stop"}"#.parse::<HookInput>(),
            Err(ParseError::Event { .. })
        ));
    }
}
