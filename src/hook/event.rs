//! The nd7 event: envelope plus kind-specific body, and the transform from a
//! parsed Claude Code hook payload into it.
//!
//! This follows docs/SCHEMA.md draft 0. Everything Claude Code specific lives
//! in [`Body`]; the [`Event`] envelope is source-agnostic so that future
//! producers (`intent:codex`, `effect:*`) build the same struct.
//!
//! Field order matters: the writer hashes the exact bytes it writes, and
//! serde_json emits struct fields in declaration order. Do not reorder.


use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::input::{Common, HookEvent, HookInput, PermissionMode};

/// Schema version written into every frame. `0` while drafting.
pub const SCHEMA_VERSION: u16 = 0;

/// Producer and evidence class for events built from Claude Code hooks.
pub const SOURCE_CLAUDE_CODE: &str = "intent:claude-code";

/// One frame of the session log.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub v: u16,
    pub session_id: String,
    pub seq: u64,
    /// Unix epoch nanoseconds, UTC, taken when the recorder started.
    pub ts: i64,
    pub host: String,
    pub source: String,
    pub kind: Kind,
    /// BLAKE3 of the previous frame. Filled in by the writer once hashing
    /// lands (milestone M4); absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    pub body: Body,
    /// BLAKE3 over this frame without `hash`. Same status as `prev`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}

/// Event kinds of Phase 1 (SCHEMA.md section 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    SessionStart,
    Prompt,
    ToolCall,
    ToolResult,
    SessionEnd,
    TurnEnd,
    /// Any hook event without a dedicated kind. `body.raw` holds the payload.
    Hook,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::SessionStart => "session_start",
            Kind::Prompt => "prompt",
            Kind::ToolCall => "tool_call",
            Kind::ToolResult => "tool_result",
            Kind::SessionEnd => "session_end",
            Kind::TurnEnd => "turn_end",
            Kind::Hook => "hook",
        }
    }
}

/// Body of an `intent:claude-code` event: the common section shared by every
/// kind, then the kind-specific fields flattened alongside it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Body {
    /// Agent's working directory at the hook. Join key for effects.
    pub cwd: String,
    pub transcript_path: String,
    /// Kept even though `kind` is derived from it.
    pub hook_event_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// Parent pid of the `nd7 hook` process. Join key for process-tree
    /// attribution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hook_ppid: Option<u32>,
    #[serde(flatten)]
    pub detail: Detail,
}

/// Kind-specific body fields. Untagged: `Event::kind` is the discriminant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Detail {
    SessionStart {
        /// Payload `source` (`startup`, `resume`, `clear`, `compact`, `fork`),
        /// renamed to avoid clashing with the envelope's `source`.
        reason: String,
    },
    Prompt {
        /// Payload `prompt`, verbatim.
        text: String,
    },
    ToolCall {
        tool_use_id: String,
        tool_name: String,
        /// Full input, verbatim.
        tool_input: Value,
        /// `tool_input.command` for `Bash`, hoisted for effect matching.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        argv: Option<String>,
        /// File paths hoisted from `tool_input` for known tools.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        paths: Option<Vec<String>>,
    },
    ToolResult {
        tool_use_id: String,
        tool_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tool_input: Option<Value>,
        /// `PostToolUse::tool_response`, or the `error` string for
        /// `PostToolUseFailure`.
        tool_response: Value,
        /// `false` for `PostToolUseFailure`.
        ok: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },
    SessionEnd {
        reason: String,
    },
    TurnEnd {
        stop_hook_active: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        last_assistant_message: Option<String>,
    },
    Hook {
        /// The full hook payload.
        raw: Map<String, Value>,
    },
}

/// Recorder-side facts that go into the frame alongside the hook payload.
#[derive(Debug, Clone, PartialEq)]
pub struct Recorded {
    pub ts: i64,
    pub host: String,
    pub hook_ppid: Option<u32>,
}

impl Event {
    /// Transform a parsed hook payload into one event.
    ///
    /// `raw` is the payload as a JSON object; it is only stored for kinds
    /// without a typed body. `seq` is left at 0 for the writer to assign.
    pub fn from_hook(input: HookInput, raw: Map<String, Value>, rec: Recorded) -> Event {
        let HookInput { common, event } = input;
        let (kind, detail) = Detail::from_hook_event(event, raw);
        let session_id = common.session_id.clone();
        let body = Body::new(common, rec.hook_ppid, detail);
        Event {
            v: SCHEMA_VERSION,
            session_id,
            seq: 0,
            ts: rec.ts,
            host: rec.host,
            source: SOURCE_CLAUDE_CODE.to_owned(),
            kind,
            prev: None,
            body,
            hash: None,
        }
    }
}

impl Body {
    fn new(common: Common, hook_ppid: Option<u32>, detail: Detail) -> Body {
        Body {
            cwd: common.cwd,
            transcript_path: common.transcript_path,
            hook_event_name: common.hook_event_name,
            permission_mode: common.permission_mode.map(permission_mode_str),
            prompt_id: common.prompt_id,
            agent_id: common.agent_id,
            agent_type: common.agent_type,
            hook_ppid,
            detail,
        }
    }
}

impl Detail {
    fn from_hook_event(event: HookEvent, raw: Map<String, Value>) -> (Kind, Detail) {
        match event {
            HookEvent::SessionStart(e) => (
                Kind::SessionStart,
                Detail::SessionStart {
                    reason: enum_str(&e.source),
                },
            ),
            HookEvent::UserPromptSubmit(e) => (Kind::Prompt, Detail::Prompt { text: e.prompt }),
            HookEvent::PreToolUse(e) => {
                let argv = hoist_argv(&e.tool.tool_name, &e.tool.tool_input);
                let paths = hoist_paths(&e.tool.tool_input);
                (
                    Kind::ToolCall,
                    Detail::ToolCall {
                        tool_use_id: e.tool.tool_use_id,
                        tool_name: e.tool.tool_name,
                        tool_input: e.tool.tool_input,
                        argv,
                        paths,
                    },
                )
            }
            HookEvent::PostToolUse(e) => (
                Kind::ToolResult,
                Detail::ToolResult {
                    tool_use_id: e.tool.tool_use_id,
                    tool_name: e.tool.tool_name,
                    tool_input: Some(e.tool.tool_input),
                    tool_response: e.tool_response,
                    ok: true,
                    duration_ms: e.duration_ms,
                },
            ),
            HookEvent::PostToolUseFailure(e) => (
                Kind::ToolResult,
                Detail::ToolResult {
                    tool_use_id: e.tool.tool_use_id,
                    tool_name: e.tool.tool_name,
                    tool_input: Some(e.tool.tool_input),
                    tool_response: Value::String(e.error),
                    ok: false,
                    duration_ms: e.duration_ms,
                },
            ),
            HookEvent::SessionEnd(e) => (
                Kind::SessionEnd,
                Detail::SessionEnd {
                    reason: enum_str(&e.reason),
                },
            ),
            HookEvent::Stop(e) => (
                Kind::TurnEnd,
                Detail::TurnEnd {
                    stop_hook_active: e.stop_hook_active,
                    last_assistant_message: e.last_assistant_message,
                },
            ),
            // Every other event, typed or not, is kept whole.
            _ => (Kind::Hook, Detail::Hook { raw }),
        }
    }
}

fn permission_mode_str(mode: PermissionMode) -> String {
    enum_str(&mode)
}

/// Wire string of a unit-variant enum with an untagged `Other(String)`
/// fallback. All such enums serialize to a plain JSON string.
fn enum_str<T: Serialize>(value: &T) -> String {
    match serde_json::to_value(value) {
        Ok(Value::String(s)) => s,
        Ok(other) => other.to_string(),
        Err(_) => String::new(),
    }
}

fn hoist_argv(tool_name: &str, input: &Value) -> Option<String> {
    match tool_name {
        "Bash" | "PowerShell" => input.get("command")?.as_str().map(str::to_owned),
        _ => None,
    }
}

/// Input keys that name a file for the built-in tools.
const PATH_KEYS: &[&str] = &["file_path", "notebook_path"];

fn hoist_paths(input: &Value) -> Option<Vec<String>> {
    let paths: Vec<String> = PATH_KEYS
        .iter()
        .filter_map(|k| input.get(k)?.as_str().map(str::to_owned))
        .collect();
    if paths.is_empty() { None } else { Some(paths) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> Recorded {
        Recorded {
            ts: 1_700_000_000_000_000_000,
            host: "laptop".into(),
            hook_ppid: Some(4242),
        }
    }

    fn transform(raw: &str) -> Event {
        let value: Value = serde_json::from_str(raw).unwrap();
        let map = value.as_object().unwrap().clone();
        let input = HookInput::from_value(value).unwrap_or_else(|e| panic!("{e}"));
        Event::from_hook(input, map, rec())
    }

    const BASE: &str = r#""session_id": "abc123", "transcript_path": "/t.jsonl", "cwd": "/p", "permission_mode": "auto""#;

    #[test]
    fn pre_tool_use_bash_becomes_tool_call_with_argv() {
        let ev = transform(&format!(
            r#"{{{BASE}, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                 "tool_input": {{"command": "npm test", "description": "Run"}}, "tool_use_id": "toolu_01"}}"#
        ));
        assert_eq!(ev.kind, Kind::ToolCall);
        assert_eq!(ev.source, SOURCE_CLAUDE_CODE);
        assert_eq!(ev.body.permission_mode.as_deref(), Some("auto"));
        assert_eq!(ev.body.hook_ppid, Some(4242));
        let Detail::ToolCall { argv, paths, tool_use_id, .. } = ev.body.detail else { panic!() };
        assert_eq!(argv.as_deref(), Some("npm test"));
        assert_eq!(paths, None);
        assert_eq!(tool_use_id, "toolu_01");
    }

    #[test]
    fn pre_tool_use_write_hoists_path() {
        let ev = transform(&format!(
            r#"{{{BASE}, "hook_event_name": "PreToolUse", "tool_name": "Write",
                 "tool_input": {{"file_path": "/p/a.rs", "content": "x"}}, "tool_use_id": "toolu_02"}}"#
        ));
        let Detail::ToolCall { argv, paths, .. } = ev.body.detail else { panic!() };
        assert_eq!(argv, None);
        assert_eq!(paths, Some(vec!["/p/a.rs".to_owned()]));
    }

    #[test]
    fn failure_is_tool_result_not_ok() {
        let ev = transform(&format!(
            r#"{{{BASE}, "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                 "tool_input": {{"command": "npm test"}}, "tool_use_id": "toolu_03",
                 "error": "Exit code 1", "is_interrupt": false, "duration_ms": 7}}"#
        ));
        assert_eq!(ev.kind, Kind::ToolResult);
        let Detail::ToolResult { ok, tool_response, duration_ms, .. } = ev.body.detail else { panic!() };
        assert!(!ok);
        assert_eq!(tool_response, "Exit code 1");
        assert_eq!(duration_ms, Some(7));
    }

    #[test]
    fn session_start_source_is_renamed_to_reason() {
        let ev = transform(&format!(
            r#"{{{BASE}, "hook_event_name": "SessionStart", "source": "resume"}}"#
        ));
        assert_eq!(ev.kind, Kind::SessionStart);
        assert_eq!(ev.body.detail, Detail::SessionStart { reason: "resume".into() });
    }

    #[test]
    fn unmodeled_kinds_keep_raw_payload() {
        let ev = transform(&format!(
            r#"{{{BASE}, "hook_event_name": "SubagentStop", "stop_hook_active": false,
                 "agent_id": "a1", "agent_type": "Explore"}}"#
        ));
        assert_eq!(ev.kind, Kind::Hook);
        assert_eq!(ev.body.agent_id.as_deref(), Some("a1"));
        let Detail::Hook { raw } = ev.body.detail else { panic!() };
        assert_eq!(raw["hook_event_name"], "SubagentStop");

        let ev = transform(&format!(r#"{{{BASE}, "hook_event_name": "Brand-New", "z": 1}}"#));
        assert_eq!(ev.kind, Kind::Hook);
        assert_eq!(ev.body.hook_event_name, "Brand-New");
    }

    #[test]
    fn frame_has_deterministic_field_order_and_round_trips() {
        let ev = transform(&format!(r#"{{{BASE}, "hook_event_name": "UserPromptSubmit", "prompt": "hi"}}"#));
        let line = serde_json::to_string(&ev).unwrap();
        assert!(line.starts_with(r#"{"v":0,"session_id":"abc123","seq":0,"ts":"#), "{line}");
        assert!(line.contains(r#""kind":"prompt""#));
        assert!(line.contains(r#""text":"hi""#));
        assert!(!line.contains("prev"), "prev must be absent until hashing lands");
        let back: Event = serde_json::from_str(&line).unwrap();
        assert_eq!(back, ev);
    }
}
