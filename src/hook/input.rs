//! Typed model of every Claude Code hook payload.
//!
//! Claude Code delivers one JSON object per hook invocation on stdin. Every
//! payload carries the [`Common`] fields plus fields specific to the event
//! named in `hook_event_name`. This module models all events documented in
//! the hooks reference (https://code.claude.com/docs/en/hooks, read on
//! 2026-09-18) and keeps anything it does not recognise instead of failing.
//!
//! Design rules:
//!
//! - Field names match the wire format. Rust keywords (`final`, `type`) are
//!   renamed and annotated.
//! - Closed value sets are enums with an `Other(String)` fallback so that a
//!   new value in a future Claude Code release parses instead of erroring.
//! - Tool inputs and responses are tool-specific and undocumented beyond
//!   their examples, so they stay `serde_json::Value`.
//! - Every [`HookInput`] keeps the payload it was parsed from in `raw`, so
//!   an unknown `hook_event_name` ([`HookEvent::Unknown`]) loses nothing.

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
    /// The payload as received. Stored whole for `hook` kinds and `--raw`.
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
    /// The event is known but its body did not match the documented shape.
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
    /// Parsing is done in two steps so that an unknown event name degrades to
    /// [`HookEvent::Unknown`] while a known event with a malformed body is
    /// reported as [`ParseError::Event`].
    fn from_str(raw: &str) -> Result<Self, ParseError> {
        let value: Value = serde_json::from_str(raw).map_err(ParseError::Json)?;
        Self::from_value(value)
    }
}

impl HookInput {
    /// Same as the [`FromStr`] impl for an already decoded JSON value.
    pub fn from_value(value: Value) -> Result<Self, ParseError> {
        let raw = match value {
            Value::Object(map) => map,
            other => {
                return Err(ParseError::Json(serde::de::Error::custom(format!(
                    "expected a JSON object, got {other}"
                ))));
            }
        };

        let name = raw
            .get("hook_event_name")
            .and_then(Value::as_str)
            .ok_or(ParseError::MissingEventName)?
            .to_owned();

        let value = Value::Object(raw.clone());
        let common: Common = serde_json::from_value(value.clone()).map_err(ParseError::Common)?;

        let event = if HookEvent::KNOWN_NAMES.contains(&name.as_str()) {
            serde_json::from_value(value).map_err(|source| ParseError::Event {
                name: name.clone(),
                source,
            })?
        } else {
            HookEvent::Unknown { name }
        };

        Ok(HookInput { common, event, raw })
    }
}

// ---------------------------------------------------------------------------
// Common fields
// ---------------------------------------------------------------------------

/// Fields present on every hook payload.
///
/// `permission_mode` and `effort` are documented as common but are absent on
/// several events (for example `SessionEnd`, `Notification`), so they are
/// optional here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Common {
    pub session_id: String,
    /// Kept verbatim even though [`HookEvent`] is derived from it, so a
    /// renamed or unknown event is never lost.
    pub hook_event_name: String,
    pub transcript_path: String,
    pub cwd: String,
    /// Claude Code >= 2.1.257. Absent when the session has no scratchpad.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scratchpad_dir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_mode: Option<PermissionMode>,
    /// UUID of the user prompt being processed. Claude Code >= 2.1.196.
    /// Absent until the first user input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_id: Option<String>,
    /// Present only when the hook fires inside a subagent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Present with `--agent` or inside a subagent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// Present for events in a tool-use context when the model supports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effort: Option<Effort>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Effort {
    pub level: EffortLevel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    #[serde(rename = "xhigh")]
    XHigh,
    Max,
    #[serde(untagged)]
    Other(String),
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// Event-specific body of a hook payload, discriminated by `hook_event_name`.
///
/// Deserialize only: the bodies are individually serializable, and the
/// [`HookEvent::Unknown`] variant has no tagged wire form.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(tag = "hook_event_name")]
pub enum HookEvent {
    // Session lifecycle
    SessionStart(SessionStart),
    SessionEnd(SessionEnd),
    Setup(Setup),
    InstructionsLoaded(InstructionsLoaded),

    // Prompt and output
    UserPromptSubmit(UserPromptSubmit),
    UserPromptExpansion(UserPromptExpansion),
    MessageDisplay(MessageDisplay),
    Stop(Stop),
    StopFailure(StopFailure),
    Notification(Notification),

    // Tools and permissions
    PreToolUse(PreToolUse),
    PermissionRequest(PermissionRequest),
    PermissionDenied(PermissionDenied),
    PostToolUse(PostToolUse),
    PostToolUseFailure(PostToolUseFailure),
    PostToolBatch(PostToolBatch),

    // Subagents, tasks, teams
    SubagentStart(SubagentStart),
    SubagentStop(SubagentStop),
    TaskCreated(TaskCreated),
    TaskCompleted(TaskCompleted),
    TeammateIdle(TeammateIdle),

    // Environment
    ConfigChange(ConfigChange),
    CwdChanged(CwdChanged),
    DirectoryAdded(DirectoryAdded),
    FileChanged(FileChanged),
    WorktreeCreate(WorktreeCreate),
    WorktreeRemove(WorktreeRemove),

    // Context and model
    PreCompact(PreCompact),
    PostCompact(PostCompact),
    PreModelSwitch(ModelSwitch),
    PostModelSwitch(ModelSwitch),

    // MCP elicitation
    Elicitation(Elicitation),
    ElicitationResult(ElicitationResult),

    /// An event this build does not model. The payload is in [`HookInput::raw`].
    #[serde(skip)]
    Unknown {
        name: String,
    },
}

impl HookEvent {
    /// Every `hook_event_name` this module has a typed body for.
    pub const KNOWN_NAMES: &'static [&'static str] = &[
        "SessionStart",
        "SessionEnd",
        "Setup",
        "InstructionsLoaded",
        "UserPromptSubmit",
        "UserPromptExpansion",
        "MessageDisplay",
        "Stop",
        "StopFailure",
        "Notification",
        "PreToolUse",
        "PermissionRequest",
        "PermissionDenied",
        "PostToolUse",
        "PostToolUseFailure",
        "PostToolBatch",
        "SubagentStart",
        "SubagentStop",
        "TaskCreated",
        "TaskCompleted",
        "TeammateIdle",
        "ConfigChange",
        "CwdChanged",
        "DirectoryAdded",
        "FileChanged",
        "WorktreeCreate",
        "WorktreeRemove",
        "PreCompact",
        "PostCompact",
        "PreModelSwitch",
        "PostModelSwitch",
        "Elicitation",
        "ElicitationResult",
    ];

    /// The wire name of this event.
    pub fn name(&self) -> &str {
        match self {
            HookEvent::SessionStart(_) => "SessionStart",
            HookEvent::SessionEnd(_) => "SessionEnd",
            HookEvent::Setup(_) => "Setup",
            HookEvent::InstructionsLoaded(_) => "InstructionsLoaded",
            HookEvent::UserPromptSubmit(_) => "UserPromptSubmit",
            HookEvent::UserPromptExpansion(_) => "UserPromptExpansion",
            HookEvent::MessageDisplay(_) => "MessageDisplay",
            HookEvent::Stop(_) => "Stop",
            HookEvent::StopFailure(_) => "StopFailure",
            HookEvent::Notification(_) => "Notification",
            HookEvent::PreToolUse(_) => "PreToolUse",
            HookEvent::PermissionRequest(_) => "PermissionRequest",
            HookEvent::PermissionDenied(_) => "PermissionDenied",
            HookEvent::PostToolUse(_) => "PostToolUse",
            HookEvent::PostToolUseFailure(_) => "PostToolUseFailure",
            HookEvent::PostToolBatch(_) => "PostToolBatch",
            HookEvent::SubagentStart(_) => "SubagentStart",
            HookEvent::SubagentStop(_) => "SubagentStop",
            HookEvent::TaskCreated(_) => "TaskCreated",
            HookEvent::TaskCompleted(_) => "TaskCompleted",
            HookEvent::TeammateIdle(_) => "TeammateIdle",
            HookEvent::ConfigChange(_) => "ConfigChange",
            HookEvent::CwdChanged(_) => "CwdChanged",
            HookEvent::DirectoryAdded(_) => "DirectoryAdded",
            HookEvent::FileChanged(_) => "FileChanged",
            HookEvent::WorktreeCreate(_) => "WorktreeCreate",
            HookEvent::WorktreeRemove(_) => "WorktreeRemove",
            HookEvent::PreCompact(_) => "PreCompact",
            HookEvent::PostCompact(_) => "PostCompact",
            HookEvent::PreModelSwitch(_) => "PreModelSwitch",
            HookEvent::PostModelSwitch(_) => "PostModelSwitch",
            HookEvent::Elicitation(_) => "Elicitation",
            HookEvent::ElicitationResult(_) => "ElicitationResult",
            HookEvent::Unknown { name, .. } => name,
        }
    }
}

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStart {
    pub source: SessionSource,
    /// Active model. Can be omitted, for example after `/clear`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Present when started with `claude --agent <name>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// Session title if already set via `--name` or `/rename`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_title: Option<String>,

    // The next four arrive together on `resume` / `fork` when the transcript
    // has at least one response. Claude Code >= 2.1.251.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seconds_since_last_response: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_tokens: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_cache_likely_expired: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_cache_write_usd: Option<f64>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Fires for `claude --init-only`, or `--init` / `--maintenance` in `-p` mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Setup {
    pub trigger: SetupTrigger,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetupTrigger {
    Init,
    Maintenance,
    #[serde(untagged)]
    Other(String),
}

/// A `CLAUDE.md` or `.claude/rules/*.md` file was loaded into context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InstructionsLoaded {
    /// Absolute path of the instruction file.
    pub file_path: String,
    pub memory_type: MemoryType,
    pub load_reason: LoadReason,
    /// `paths:` frontmatter globs. Only for `path_glob_match` loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub globs: Option<Vec<String>>,
    /// File whose access triggered a lazy load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_file_path: Option<String>,
    /// Parent instruction file, for `include` loads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_file_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum MemoryType {
    User,
    Project,
    Local,
    Managed,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoadReason {
    SessionStart,
    NestedTraversal,
    PathGlobMatch,
    Include,
    Compact,
    #[serde(untagged)]
    Other(String),
}

// ---------------------------------------------------------------------------
// Prompt and output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserPromptSubmit {
    /// The text the user submitted, verbatim.
    pub prompt: String,
}

/// A typed command expanded into a prompt (skill, custom command, MCP prompt).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UserPromptExpansion {
    pub expansion_type: ExpansionType,
    pub command_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_args: Option<String>,
    /// Where the command came from, for example `plugin`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_source: Option<String>,
    /// The original prompt string, for example `/example-skill arg1 arg2`.
    pub prompt: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpansionType {
    SlashCommand,
    McpPrompt,
    #[serde(untagged)]
    Other(String),
}

/// One batch of assistant text as it is displayed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageDisplay {
    /// UUID of the current turn.
    pub turn_id: String,
    /// UUID of the assistant message, stable across batches. Not the API
    /// `msg_…` id.
    pub message_id: String,
    /// Zero-based index of this batch within the message.
    pub index: u64,
    /// `true` on the message's last batch. Wire name is `final`.
    #[serde(rename = "final")]
    pub is_final: bool,
    /// Newly completed lines since the prior batch, newlines included.
    pub delta: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stop {
    /// `true` when Claude Code is already continuing because of a stop hook.
    pub stop_hook_active: bool,
    /// Text content of Claude's final response for this turn.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_assistant_message: Option<String>,
    /// Present when the task registry is reachable; empty when idle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_tasks: Option<Vec<BackgroundTask>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_crons: Option<Vec<SessionCron>>,
}

/// One in-flight background task, as reported on `Stop` / `SubagentStop`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BackgroundTask {
    pub id: String,
    /// Friendly label such as `shell`, `subagent`, `monitor`, `workflow`,
    /// `teammate`, `cloud session`, `MCP task`, or a raw discriminant.
    /// Wire name is `type`.
    #[serde(rename = "type")]
    pub kind: String,
    pub status: String,
    /// Capped at 1000 characters with an in-string `… [+N chars]` marker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Only for `shell` tasks. Capped at 1000 characters.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Only for `subagent` tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_type: Option<String>,
    /// Only for `monitor` and `MCP task` tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Only for `monitor` and `MCP task` tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    /// Only for `workflow` tasks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// One session-scoped scheduled wakeup (`CronCreate`, `ScheduleWakeup`, `/loop`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionCron {
    pub id: String,
    /// Cron expression, for example `0 9 * * 1-5`.
    pub schedule: String,
    /// `false` for one-shot wakeups.
    pub recurring: bool,
    /// Capped at 1000 characters.
    pub prompt: String,
}

/// The turn ended because of an API error.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StopFailure {
    /// Error type; also the matcher target.
    pub error: StopFailureError,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_details: Option<String>,
    /// The rendered API error text, for example `API Error: Rate limit reached`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_assistant_message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopFailureError {
    RateLimit,
    Overloaded,
    AuthenticationFailed,
    OauthOrgNotAllowed,
    AccountOnHold,
    BillingError,
    InvalidRequest,
    ModelNotFound,
    ServerError,
    MaxOutputTokens,
    /// Claude Code >= 2.1.267.
    CloudCredentialError,
    Unknown,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Notification {
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    pub notification_type: NotificationType,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationType {
    PermissionPrompt,
    IdlePrompt,
    AuthSuccess,
    ElicitationDialog,
    ElicitationUrlDialog,
    ElicitationComplete,
    ElicitationResponse,
    /// Claude Code >= 2.1.198.
    AgentNeedsInput,
    /// Claude Code >= 2.1.198.
    AgentCompleted,
    /// Claude Code >= 2.1.234.
    QuotaAutoResumeFired,
    /// Claude Code >= 2.1.234.
    QuotaAutoResumeStale,
    /// Claude Code >= 2.1.234.
    QuotaAutoResumeDisabled,
    #[serde(untagged)]
    Other(String),
}

// ---------------------------------------------------------------------------
// Tools and permissions
// ---------------------------------------------------------------------------

/// Where an MCP server's definition came from. Claude Code >= 2.1.274.
///
/// Base trust decisions on `source`, not on `name` or the `mcp__<server>__`
/// tool-name prefix.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    /// `plugin`, `sdk`, or a configuration scope such as `user`, `project`.
    /// The Agent SDK's `McpServerProvenance` lists them all.
    pub source: String,
}

/// The tool-call triple shared by every tool event that has a `tool_use_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolUse {
    /// `Bash`, `Edit`, `Write`, `Read`, `mcp__<server>__<tool>`, etc.
    pub tool_name: String,
    /// Tool-specific arguments, verbatim. For `Bash` this includes `command`;
    /// for `Write` / `Edit` / `Read`, `file_path` is always absolute.
    pub tool_input: Value,
    /// Pairs `PreToolUse` with its `PostToolUse` / `PostToolUseFailure`.
    pub tool_use_id: String,
    /// Present only for MCP tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<McpServer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreToolUse {
    #[serde(flatten)]
    pub tool: ToolUse,
}

/// Claude Code is about to ask the user for permission (or auto-deny a call
/// that cannot prompt). Like `PreToolUse` but without `tool_use_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionRequest {
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<McpServer>,
    /// Permission updates Claude Code suggests for this request. Not an
    /// exact list of the dialog's options.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission_suggestions: Option<Vec<PermissionUpdate>>,
}

/// One permission update entry, as used by `permission_suggestions` and the
/// `updatedPermissions` output. Which fields are present depends on `type`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionUpdate {
    /// `addRules`, `replaceRules`, `removeRules`, `setMode`,
    /// `addDirectories`, `removeDirectories`. Wire name is `type`.
    #[serde(rename = "type")]
    pub kind: PermissionUpdateKind,
    /// `session`, `localSettings`, `projectSettings`, `userSettings`.
    pub destination: PermissionDestination,
    /// For the `*Rules` kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<PermissionRule>>,
    /// For the `*Rules` kinds: `allow`, `deny`, `ask`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub behavior: Option<PermissionBehavior>,
    /// For `setMode`. `manual` is an alias for `default`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// For `addDirectories` / `removeDirectories`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directories: Option<Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionUpdateKind {
    AddRules,
    ReplaceRules,
    RemoveRules,
    SetMode,
    AddDirectories,
    RemoveDirectories,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PermissionDestination {
    Session,
    LocalSettings,
    ProjectSettings,
    UserSettings,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PermissionBehavior {
    Allow,
    Deny,
    Ask,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionRule {
    pub tool_name: String,
    /// Omitted to match the whole tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_content: Option<String>,
}

/// Auto mode denied a tool call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionDenied {
    #[serde(flatten)]
    pub tool: ToolUse,
    /// Classifier verdict such as `[Data Exfiltration]`, a no-verdict text
    /// starting `Auto mode could not evaluate this action…`, or the fixed
    /// `Classifier unavailable`.
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostToolUse {
    #[serde(flatten)]
    pub tool: ToolUse,
    /// The tool's structured output object, for example
    /// `{"filePath": "...", "type": "create"}` for `Write`. Tool-specific.
    pub tool_response: Value,
    /// Execution time excluding permission prompts and PreToolUse hooks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostToolUseFailure {
    #[serde(flatten)]
    pub tool: ToolUse,
    /// What went wrong. For `Bash` / `PowerShell` the first line is usually
    /// `Exit code N`; treat the rest as display text.
    pub error: String,
    /// `true` when the failure reached Claude Code as an abort.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_interrupt: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
}

/// A whole batch of parallel tool calls resolved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostToolBatch {
    pub tool_calls: Vec<BatchToolCall>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BatchToolCall {
    pub tool_name: String,
    pub tool_input: Value,
    pub tool_use_id: String,
    /// The serialized `tool_result` content the model sees: a string or a
    /// content-block array. Differs from `PostToolUse::tool_response`.
    pub tool_response: Value,
}

// ---------------------------------------------------------------------------
// Subagents, tasks, teams
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubagentStart {
    pub agent_id: String,
    /// Matcher target: `general-purpose`, `Explore`, a custom name, or a
    /// plugin-scoped `plugin:agent` name.
    pub agent_type: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubagentStop {
    pub stop_hook_active: bool,
    pub agent_id: String,
    pub agent_type: String,
    /// The subagent's own transcript, under a nested `subagents/` folder.
    /// `Common::transcript_path` is the parent session's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_transcript_path: Option<String>,
    /// Closing text of the subagent. With `SubagentHandback` (>= 2.1.271) the
    /// actual report travels through that tool call instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_assistant_message: Option<String>,
    /// Scoped to the parent session, not the subagent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_tasks: Option<Vec<BackgroundTask>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_crons: Option<Vec<SessionCron>>,
}

/// Shared body of `TaskCreated` and `TaskCompleted`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskEvent {
    pub task_id: String,
    pub task_subject: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub teammate_name: Option<String>,
    /// Deprecated upstream; will be removed in a future Claude Code release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_name: Option<String>,
}

pub type TaskCreated = TaskEvent;
pub type TaskCompleted = TaskEvent;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeammateIdle {
    pub teammate_name: String,
    /// Deprecated upstream.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_name: Option<String>,
}

// ---------------------------------------------------------------------------
// Environment
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfigChange {
    pub source: ConfigSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigSource {
    UserSettings,
    ProjectSettings,
    LocalSettings,
    PolicySettings,
    Skills,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CwdChanged {
    pub old_cwd: String,
    pub new_cwd: String,
}

/// A working directory was added via `/add-dir` or the SDK.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectoryAdded {
    /// Absolute path of the added directory.
    pub directory: String,
    pub source: DirectorySource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectorySource {
    SlashCommand,
    RegisterRepoRoot,
    #[serde(untagged)]
    Other(String),
}

/// A watched file changed on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileChanged {
    pub file_path: String,
    pub event: FileChangeKind,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileChangeKind {
    /// Modified.
    Change,
    /// Created.
    Add,
    /// Deleted.
    Unlink,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorktreeCreate {
    /// Slug for the new worktree, user-given or generated (`bold-oak-a3f2`).
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorktreeRemove {
    /// Absolute path of the worktree being removed.
    pub worktree_path: String,
}

// ---------------------------------------------------------------------------
// Context and model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PreCompact {
    pub trigger: CompactTrigger,
    /// What the user passed to `/compact`. `null` for `auto` or when empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostCompact {
    pub trigger: CompactTrigger,
    /// The summary produced by compaction.
    pub compact_summary: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompactTrigger {
    Manual,
    Auto,
    #[serde(untagged)]
    Other(String),
}

/// Body of both `PreModelSwitch` and `PostModelSwitch`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelSwitch {
    pub from_model: String,
    /// Matcher compares against this model's canonical name.
    pub to_model: String,
    /// Alias or full id the request named; `null` for the default model or
    /// for `source == "auto"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_model: Option<String>,
    pub source: ModelSwitchSource,
    /// Tokens the next request re-sends as its prompt. `0` before the first
    /// response.
    pub context_tokens: u64,
    /// Whether the current model's prompt cache is likely still warm.
    pub prompt_cache_warm: bool,
    /// `5m` or `1h`.
    pub cache_ttl: String,
    pub estimated_cache_write_usd: f64,
    pub pricing: PricingSource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelSwitchSource {
    /// `/model <name>`, the `/config` Model setting, or fast mode.
    Command,
    Picker,
    /// Agent SDK `set_model` or `apply_flag_settings`, or Remote Control.
    Sdk,
    /// PostModelSwitch only: automatic fallback or other self-initiated change.
    Auto,
    /// PostModelSwitch only: model restored on session resume.
    Resume,
    #[serde(untagged)]
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PricingSource {
    /// The organization's own configured rates.
    Configured,
    /// List price.
    Catalog,
    /// `to_model` has no known price; a default rate was assumed.
    Default,
    #[serde(untagged)]
    Other(String),
}

// ---------------------------------------------------------------------------
// MCP elicitation
// ---------------------------------------------------------------------------

/// An MCP server requested user input during a tool call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Elicitation {
    pub mcp_server_name: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ElicitationMode>,
    /// URL-mode only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elicitation_id: Option<String>,
    /// Form-mode only: JSON Schema of the requested fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_schema: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationMode {
    Form,
    Url,
    #[serde(untagged)]
    Other(String),
}

/// The user answered an MCP elicitation, before the reply reaches the server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ElicitationResult {
    pub mcp_server_name: String,
    pub action: ElicitationAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<ElicitationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub elicitation_id: Option<String>,
    /// Submitted form values. Only for `accept`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ElicitationAction {
    Accept,
    Decline,
    Cancel,
    #[serde(untagged)]
    Other(String),
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
        assert!(e.tool.mcp_server.is_none());
    }

    #[test]
    fn session_start_resume_with_cache_fields() {
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
        assert_eq!(e.model.as_deref(), Some("claude-opus-5"));
        assert_eq!(e.context_tokens, Some(182340));
        assert_eq!(e.prompt_cache_likely_expired, Some(true));
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
        assert_eq!(e.is_interrupt, Some(false));
    }

    #[test]
    fn permission_request_with_suggestions() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/...",
              "permission_mode": "default",
              "hook_event_name": "PermissionRequest",
              "tool_name": "Bash",
              "tool_input": { "command": "rm -rf node_modules", "description": "Remove node_modules directory" },
              "permission_suggestions": [
                {
                  "type": "addRules",
                  "rules": [{ "toolName": "Bash", "ruleContent": "rm -rf node_modules" }],
                  "behavior": "allow",
                  "destination": "localSettings"
                }
              ]
            }"#,
        );
        let HookEvent::PermissionRequest(e) = input.event else {
            panic!("wrong variant")
        };
        let s = &e.permission_suggestions.unwrap()[0];
        assert_eq!(s.kind, PermissionUpdateKind::AddRules);
        assert_eq!(s.destination, PermissionDestination::LocalSettings);
        assert_eq!(s.behavior, Some(PermissionBehavior::Allow));
        assert_eq!(s.rules.as_ref().unwrap()[0].tool_name, "Bash");
    }

    #[test]
    fn post_tool_batch() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/...",
              "permission_mode": "default",
              "hook_event_name": "PostToolBatch",
              "tool_calls": [
                { "tool_name": "Read", "tool_input": {"file_path": "/a.py"}, "tool_use_id": "toolu_01...", "tool_response": "     1\tfrom __future__ import annotations\n" },
                { "tool_name": "Read", "tool_input": {"file_path": "/b.py"}, "tool_use_id": "toolu_02...", "tool_response": "     1\tfrom __future__ import annotations\n" }
              ]
            }"#,
        );
        let HookEvent::PostToolBatch(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.tool_calls.len(), 2);
        assert!(e.tool_calls[0].tool_response.is_string());
    }

    #[test]
    fn stop_with_tasks_and_crons() {
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
        let tasks = e.background_tasks.unwrap();
        assert_eq!(tasks[0].kind, "shell");
        assert_eq!(tasks[0].command.as_deref(), Some("tail -f /var/log/syslog"));
        assert!(e.session_crons.unwrap()[0].recurring);
    }

    #[test]
    fn subagent_stop() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "~/.claude/projects/.../abc123.jsonl",
              "cwd": "/Users/...",
              "permission_mode": "default",
              "hook_event_name": "SubagentStop",
              "stop_hook_active": false,
              "agent_id": "def456",
              "agent_type": "Explore",
              "agent_transcript_path": "~/.claude/projects/.../abc123/subagents/agent-def456.jsonl",
              "last_assistant_message": "Analysis complete. Found 3 potential issues...",
              "background_tasks": [],
              "session_crons": []
            }"#,
        );
        // agent_id / agent_type land in both the common fields and the body.
        assert_eq!(input.common.agent_id.as_deref(), Some("def456"));
        let HookEvent::SubagentStop(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.agent_type, "Explore");
        assert_eq!(e.background_tasks, Some(vec![]));
    }

    #[test]
    fn message_display_renames_final() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/my-project",
              "hook_event_name": "MessageDisplay",
              "turn_id": "0c9e6a2f-7d41-4f4e-9a15-3f4f7c2b8d10",
              "message_id": "5b2a9c8e-1f63-4d8a-b7c4-9e0d2a6f1c3b",
              "index": 0,
              "final": false,
              "delta": "Here is the plan:\n"
            }"#,
        );
        let HookEvent::MessageDisplay(e) = input.event else {
            panic!("wrong variant")
        };
        assert!(!e.is_final);
        assert_eq!(e.index, 0);
    }

    #[test]
    fn pre_model_switch() {
        let input = parse(
            r#"{
              "session_id": "abc123",
              "transcript_path": "/Users/.../t.jsonl",
              "cwd": "/Users/...",
              "hook_event_name": "PreModelSwitch",
              "from_model": "claude-sonnet-5",
              "to_model": "claude-opus-5",
              "requested_model": "opus",
              "source": "command",
              "context_tokens": 182340,
              "prompt_cache_warm": true,
              "cache_ttl": "5m",
              "estimated_cache_write_usd": 1.1396,
              "pricing": "catalog"
            }"#,
        );
        let HookEvent::PreModelSwitch(e) = input.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.source, ModelSwitchSource::Command);
        assert_eq!(e.pricing, PricingSource::Catalog);
    }

    #[test]
    fn elicitation_form_and_result() {
        let a = parse(
            r#"{
              "session_id": "abc123", "transcript_path": "/t.jsonl", "cwd": "/",
              "hook_event_name": "Elicitation",
              "mcp_server_name": "my-mcp-server",
              "message": "Please provide your credentials",
              "mode": "form",
              "requested_schema": { "type": "object", "properties": { "username": { "type": "string", "title": "Username" } } }
            }"#,
        );
        let HookEvent::Elicitation(e) = a.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.mode, Some(ElicitationMode::Form));
        assert!(e.requested_schema.is_some());

        let b = parse(
            r#"{
              "session_id": "abc123", "transcript_path": "/t.jsonl", "cwd": "/",
              "hook_event_name": "ElicitationResult",
              "mcp_server_name": "my-mcp-server",
              "action": "accept",
              "content": { "username": "alice" },
              "mode": "form",
              "elicitation_id": "elicit-123"
            }"#,
        );
        let HookEvent::ElicitationResult(e) = b.event else {
            panic!("wrong variant")
        };
        assert_eq!(e.action, ElicitationAction::Accept);
        assert_eq!(e.content.unwrap()["username"], "alice");
    }

    #[test]
    fn small_events() {
        let base = r#""session_id": "abc123", "transcript_path": "/t.jsonl", "cwd": "/""#;
        let cases = [
            (
                r#""hook_event_name": "SessionEnd", "reason": "other""#,
                "SessionEnd",
            ),
            (r#""hook_event_name": "Setup", "trigger": "init""#, "Setup"),
            (
                r#""hook_event_name": "InstructionsLoaded", "file_path": "/p/CLAUDE.md", "memory_type": "Project", "load_reason": "session_start""#,
                "InstructionsLoaded",
            ),
            (
                r#""hook_event_name": "UserPromptSubmit", "prompt": "hi""#,
                "UserPromptSubmit",
            ),
            (
                r#""hook_event_name": "UserPromptExpansion", "expansion_type": "slash_command", "command_name": "example-skill", "command_args": "arg1 arg2", "command_source": "plugin", "prompt": "/example-skill arg1 arg2""#,
                "UserPromptExpansion",
            ),
            (
                r#""hook_event_name": "StopFailure", "error": "rate_limit", "error_details": "429 Too Many Requests", "last_assistant_message": "API Error: Rate limit reached""#,
                "StopFailure",
            ),
            (
                r#""hook_event_name": "Notification", "message": "Claude needs your permission", "title": "Permission needed", "notification_type": "permission_prompt""#,
                "Notification",
            ),
            (
                r#""hook_event_name": "PermissionDenied", "tool_name": "Bash", "tool_input": {"command": "rm -rf /tmp/build"}, "tool_use_id": "toolu_01", "reason": "[Irreversible Local Destruction]""#,
                "PermissionDenied",
            ),
            (
                r#""hook_event_name": "SubagentStart", "agent_id": "agent-abc123", "agent_type": "Explore""#,
                "SubagentStart",
            ),
            (
                r#""hook_event_name": "TaskCreated", "task_id": "task-001", "task_subject": "Implement user authentication", "task_description": "Add login and signup endpoints", "teammate_name": "implementer", "team_name": "session-a1b2c3d4""#,
                "TaskCreated",
            ),
            (
                r#""hook_event_name": "TaskCompleted", "task_id": "task-001", "task_subject": "Implement user authentication""#,
                "TaskCompleted",
            ),
            (
                r#""hook_event_name": "TeammateIdle", "teammate_name": "researcher", "team_name": "session-a1b2c3d4""#,
                "TeammateIdle",
            ),
            (
                r#""hook_event_name": "ConfigChange", "source": "project_settings", "file_path": "/p/.claude/settings.json""#,
                "ConfigChange",
            ),
            (
                r#""hook_event_name": "CwdChanged", "old_cwd": "/p", "new_cwd": "/p/src""#,
                "CwdChanged",
            ),
            (
                r#""hook_event_name": "DirectoryAdded", "directory": "/other", "source": "slash_command""#,
                "DirectoryAdded",
            ),
            (
                r#""hook_event_name": "FileChanged", "file_path": "/p/.envrc", "event": "change""#,
                "FileChanged",
            ),
            (
                r#""hook_event_name": "WorktreeCreate", "name": "feature-auth""#,
                "WorktreeCreate",
            ),
            (
                r#""hook_event_name": "WorktreeRemove", "worktree_path": "/p/.claude/worktrees/feature-auth""#,
                "WorktreeRemove",
            ),
            (
                r#""hook_event_name": "PreCompact", "trigger": "manual", "custom_instructions": null"#,
                "PreCompact",
            ),
            (
                r#""hook_event_name": "PostCompact", "trigger": "auto", "compact_summary": "Summary...""#,
                "PostCompact",
            ),
            (
                r#""hook_event_name": "PostModelSwitch", "from_model": "a", "to_model": "b", "requested_model": null, "source": "auto", "context_tokens": 0, "prompt_cache_warm": false, "cache_ttl": "1h", "estimated_cache_write_usd": 0.0, "pricing": "default""#,
                "PostModelSwitch",
            ),
        ];
        for (body, name) in cases {
            let input = parse(&format!("{{{base}, {body}}}"));
            assert_eq!(input.event.name(), name, "{body}");
            assert_eq!(input.common.hook_event_name, name);
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
    fn unknown_event_is_kept() {
        let input = parse(
            r#"{"session_id": "s", "transcript_path": "/t", "cwd": "/", "hook_event_name": "FutureThing", "x": 1}"#,
        );
        let payload = input.raw;
        let HookEvent::Unknown { name } = input.event else {
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

    #[test]
    fn every_known_name_has_a_variant() {
        assert_eq!(HookEvent::KNOWN_NAMES.len(), 33);
    }
}
