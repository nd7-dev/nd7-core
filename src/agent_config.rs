//! nd7's hooks in an agent's own configuration, and the shell aliases that
//! start an agent under `nd7 run`.
//!
//! `nd7 run` can pass its `PreToolUse` hook per invocation, but Codex then
//! needs `--dangerously-bypass-hook-trust` and prints two advisories at every
//! start, because only a hook discovered from a configuration file carries the
//! trust hash it checks. Writing the hooks once — `nd7 init` — removes that,
//! registers the `record` hooks the log is made of at the same time, and
//! records the approval Codex would otherwise ask for at its next start.
//!
//! Everything here is idempotent: an install looks for a hook that is already
//! there before adding one, so running `nd7 init` twice writes nothing the
//! second time. Nothing in this module is macOS-specific.
//!
//! The aliases live in `~/.nd7/aliases.sh`, under the one directory every
//! nd7 policy denies writes to, so a sandboxed session cannot rewrite the
//! aliases that put the next session under the sandbox. The line that loads
//! them is the only line `nd7 init` adds to a shell rc.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

/// An agent nd7 knows how to configure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Agent {
    Claude,
    Codex,
}

impl Agent {
    /// The program's name, which is also the name of its configuration
    /// directory under `~` and the name the alias binds.
    pub fn name(self) -> &'static str {
        match self {
            Agent::Claude => "claude",
            Agent::Codex => "codex",
        }
    }
}

impl fmt::Display for Agent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// Whether an install had anything to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Changed {
    Installed,
    AlreadyInstalled,
}

/// The events nd7 records: exactly the set the README registers. Every other
/// documented event can be added by hand and is recorded as `kind: hook`.
const RECORD_EVENTS: [&str; 7] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "PostToolUseFailure",
    "Stop",
    "SessionEnd",
];

/// The same for Codex, which has no `PostToolUseFailure` event.
const CODEX_RECORD_EVENTS: [&str; 6] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PostToolUse",
    "Stop",
    "SessionEnd",
];

/// Seconds a `record` hook is given. `SessionEnd` gets less, because all of
/// an agent's `SessionEnd` hooks share one budget.
const RECORD_TIMEOUT: u64 = 5;
const CLAUDE_SESSION_END_TIMEOUT: u64 = 1;
const CODEX_SESSION_END_TIMEOUT: u64 = 3;

/// The tail of the `PreToolUse` hook's command, whatever nd7 wrote it.
const PREFIX_TAIL: &str = " hook-prefix";
/// The same for a `record` hook written into a Codex configuration, where the
/// command is one string rather than a command and arguments.
const RECORD_TAIL: &str = "nd7 record";

/// Puts nd7's hooks in a Claude Code settings file: the `PreToolUse` hook that
/// routes Bash through `nd7-exec`, and a `record` hook per recorded event. A
/// missing file is created, everything already in it is kept, and a hook nd7
/// already has there is not added twice.
pub fn install_claude(settings: &Path, nd7: &Path) -> io::Result<Changed> {
    let mut root = read_object(settings)?;
    let hooks = match root
        .entry("hooks")
        .or_insert_with(|| Value::Object(Map::new()))
    {
        Value::Object(hooks) => hooks,
        other => return Err(io::Error::other(format!("hooks is not an object: {other}"))),
    };

    let mut changed = false;
    // Exec form, `command` plus `args`: no `sh -c` wrapper, and the recorded
    // parent pid is the agent itself.
    let record = nd7.display().to_string();
    for event in RECORD_EVENTS {
        let entries = entries_of(hooks, event)?;
        if entries.iter().any(has_record_hook) {
            continue;
        }
        let timeout = if event == "SessionEnd" {
            CLAUDE_SESSION_END_TIMEOUT
        } else {
            RECORD_TIMEOUT
        };
        entries.push(json!({
            "hooks": [ { "type": "command", "command": record, "args": ["record"], "timeout": timeout } ]
        }));
        changed = true;
    }

    // After the `record` entry for the same event, so the log sees the call
    // before the rewrite is decided.
    let pre_tool_use = entries_of(hooks, "PreToolUse")?;
    if !pre_tool_use.iter().any(has_prefix_hook) {
        pre_tool_use.push(json!({
            "matcher": "Bash",
            "hooks": [ { "type": "command", "command": format!("{}{PREFIX_TAIL}", nd7.display()) } ]
        }));
        changed = true;
    }

    if !changed {
        return Ok(Changed::AlreadyInstalled);
    }
    write_atomic(
        settings,
        &format!("{}\n", serde_json::to_string_pretty(&root)?),
    )?;
    Ok(Changed::Installed)
}

/// Whether `settings` already runs *this* nd7 as its `PreToolUse` hook, which
/// is what lets `nd7 run` leave the hook out of the flags it passes. An
/// install is looser — any nd7 path counts, so a settings file written by
/// another checkout does not collect a second hook — but a hook naming another
/// binary is not this one's, so `nd7 run` still passes its own.
pub fn claude_has_hook(settings: &Path, nd7: &Path) -> bool {
    let want = format!("{}{PREFIX_TAIL}", nd7.display());
    let Ok(Value::Object(root)) = read_json(settings) else {
        return false;
    };
    root.get("hooks")
        .and_then(|hooks| hooks.get("PreToolUse"))
        .and_then(Value::as_array)
        .is_some_and(|entries| {
            entries
                .iter()
                .flat_map(hooks_of)
                .any(|hook| command_of(hook) == Some(&*want))
        })
}

/// The same two hook sets in Codex's configuration, which is TOML. The tables
/// are appended, never rewritten: nd7 does not own this file, and appending is
/// the one edit that cannot disturb what is already in it.
pub fn install_codex(config: &Path, nd7: &Path) -> io::Result<Changed> {
    let text = read_or_empty(config)?;
    let nd7 = nd7.display();
    let mut add = String::new();

    if !codex_command(&text, "PreToolUse", |command| {
        command.ends_with(PREFIX_TAIL)
    }) {
        add.push_str(&format!(
            "\n# nd7: routes every Bash command through nd7-exec. Installed by `nd7 init`.\n\
             [[hooks.PreToolUse]]\n\
             matcher = \"\"\n\
             \n\
             [[hooks.PreToolUse.hooks]]\n\
             type = \"command\"\n\
             command = {command}\n\
             timeout = 30\n",
            command = toml_string(&format!("{nd7}{PREFIX_TAIL}")),
        ));
    }

    // Codex sends Claude Code's hook payloads, so `nd7 record` reads them
    // unchanged.
    let record = toml_string(&format!("{nd7} record"));
    for event in CODEX_RECORD_EVENTS {
        if codex_command(&text, event, |command| command.ends_with(RECORD_TAIL)) {
            continue;
        }
        let timeout = if event == "SessionEnd" {
            CODEX_SESSION_END_TIMEOUT
        } else {
            RECORD_TIMEOUT
        };
        add.push_str(&format!(
            "\n# nd7: records this event in the session log. Installed by `nd7 init`.\n\
             [[hooks.{event}]]\n\
             \n\
             [[hooks.{event}.hooks]]\n\
             type = \"command\"\n\
             command = {record}\n\
             timeout = {timeout}\n",
        ));
    }

    // Codex asks the user to approve every hook it discovers, and records the
    // approval as a hash of the hook under `[hooks.state]`. It records it by
    // rewriting this file, which `nd7 run` makes unwritable, so the approval
    // could never be given from a session nd7 started; nd7 writes it here for
    // the hooks it installed itself, and for no others.
    let mut installed = text.clone();
    if !installed.is_empty() && !installed.ends_with('\n') {
        installed.push('\n');
    }
    installed.push_str(&add);
    let trusted = codex_trust_keys_present(&installed);
    let ours = format!("{nd7} ");
    for hook in codex_hook_tables(&installed) {
        if !hook.command.starts_with(&ours) {
            continue;
        }
        let key = codex_trust_key(config, &hook);
        if trusted.contains(&key) {
            continue;
        }
        add.push_str(&format!(
            "\n# nd7: approval Codex would otherwise ask for on first start. Installed by `nd7 init`.\n\
             [hooks.state.{key}]\n\
             trusted_hash = \"{hash}\"\n",
            key = toml_string(&key),
            hash = codex_trust_hash(
                &hook.event,
                hook.matcher.as_deref(),
                &hook.command,
                hook.timeout
            ),
        ));
    }

    if add.is_empty() {
        return Ok(Changed::AlreadyInstalled);
    }
    if let Some(dir) = config.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(config)?;
    // A table header must start a line, whatever the file ended with.
    if !text.is_empty() && !text.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    file.write_all(add.as_bytes())?;
    Ok(Changed::Installed)
}

/// Whether `config` already runs *this* nd7 as its `PreToolUse` hook. As for
/// Claude Code, the path must match, since that is the binary the hook runs.
pub fn codex_has_hook(config: &Path, nd7: &Path) -> bool {
    let want = format!("{}{PREFIX_TAIL}", nd7.display());
    let Ok(text) = fs::read_to_string(config) else {
        return false;
    };
    codex_command(&text, "PreToolUse", |command| command == want)
}

/// Whether every nd7 hook in a Codex config is one Codex has a `trusted_hash`
/// for. Codex approves hooks by rewriting `config.toml`, and under `nd7 run`
/// that file is deliberately unwritable, so approval cannot happen in a
/// session nd7 started; `nd7 init` writes it instead, and this stays false
/// only for a file edited afterwards. Until it is true, `nd7 run` passes
/// `--dangerously-bypass-hook-trust` and says so. False when the file has no
/// nd7 hook at all. The hash itself is not checked here; Codex does that.
pub fn codex_hooks_trusted(config: &Path, nd7: &Path) -> bool {
    let Ok(text) = fs::read_to_string(config) else {
        return false;
    };
    let trusted = codex_trust_keys_present(&text);
    let ours = format!("{} ", nd7.display());
    let mut found = false;
    for hook in codex_hook_tables(&text) {
        if !hook.command.starts_with(&ours) {
            continue;
        }
        if !trusted.contains(&codex_trust_key(config, &hook)) {
            return false;
        }
        found = true;
    }
    found
}

/// The `trusted_hash` Codex writes for an approved hook: `sha256:` and the hex
/// digest of the handler's canonical JSON, which is
/// `{"event_name":…,"hooks":[{"async":false,"command":…,"timeout":…,"type":"command"}]}`
/// — plus a top-level `"matcher"`, and only when the group table has a
/// `matcher` line at all — printed compactly with its keys sorted. `event` is
/// the CamelCase name; `timeout` is the effective one, in seconds. Reproduced
/// against the hashes Codex 0.155.1 wrote for all seven of nd7's hooks.
pub fn codex_trust_hash(event: &str, matcher: Option<&str>, command: &str, timeout: u64) -> String {
    // serde_json's map is a `BTreeMap` here, so this prints sorted already.
    let mut hook = json!({
        "event_name": codex_event_label(event),
        "hooks": [ { "async": false, "command": command, "timeout": timeout, "type": "command" } ],
    });
    if let Some(matcher) = matcher {
        hook["matcher"] = json!(matcher);
    }
    let json = serde_json::to_string(&hook).expect("a JSON object serialises");
    let mut out = String::from("sha256:");
    for byte in Sha256::digest(json.as_bytes()) {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The keys of the `[hooks.state."…"]` tables in `text` that carry a
/// `trusted_hash`. A key is `<config path>:<event label>:<group>:<handler>`,
/// the path spelled as Codex opened the file.
pub fn codex_trust_keys_present(text: &str) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let mut key = None;
    for line in text.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.trim_matches(['[', ']']).trim();
            key = header
                .strip_prefix("hooks.state.")
                .and_then(toml_unquote)
                .map(str::to_owned);
        } else if line.starts_with("trusted_hash")
            && let Some(key) = &key
        {
            keys.insert(key.clone());
        }
    }
    keys
}

/// The state key Codex records a hook's approval under.
fn codex_trust_key(config: &Path, hook: &CodexHook) -> String {
    format!(
        "{}:{}:{}:{}",
        config.display(),
        codex_event_label(&hook.event),
        hook.group,
        hook.handler
    )
}

/// Codex's name for an event, in a state key and in the hashed JSON:
/// `PreToolUse` becomes `pre_tool_use`.
fn codex_event_label(event: &str) -> String {
    let mut label = String::with_capacity(event.len() + 4);
    for (i, c) in event.char_indices() {
        if c.is_ascii_uppercase() {
            if i > 0 {
                label.push('_');
            }
            label.push(c.to_ascii_lowercase());
        } else {
            label.push(c);
        }
    }
    label
}

/// One `[[hooks.<Event>.hooks]]` table, placed the way Codex keys its trust
/// state: `group` is the index of its `[[hooks.<Event>]]` table among that
/// event's tables in file order, `handler` its own index within that group.
struct CodexHook {
    event: String,
    group: usize,
    handler: usize,
    matcher: Option<String>,
    command: String,
    timeout: u64,
}

/// Codex's default hook timeout, and so the one a table without a `timeout`
/// line is hashed with.
const CODEX_DEFAULT_TIMEOUT: u64 = 600;

/// Every command handler in `text`, with its position and the fields the trust
/// hash is made of. Line-based like `codex_command`, and with the same limits:
/// a hook given as an inline array is not seen.
/// The hook events Codex 0.155.1 knows. A table for any other event is
/// accepted by its parser and then ignored: it never runs and never gets a
/// trust entry, so it must not count for or against trust either.
const CODEX_EVENTS: [&str; 12] = [
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "Interrupt",
];

fn codex_hook_tables(text: &str) -> Vec<CodexHook> {
    let mut tables = codex_hook_tables_all(text);
    tables.retain(|hook| CODEX_EVENTS.contains(&hook.event.as_str()));
    tables
}

fn codex_hook_tables_all(text: &str) -> Vec<CodexHook> {
    let mut tables = Vec::new();
    // How many groups of each event the file has had so far, and the group the
    // handler tables that follow belong to: its event, index and matcher.
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let mut group: Option<(String, usize, Option<String>)> = None;
    // The handler table being read: its index in the group, and its fields.
    let mut open: Option<usize> = None;
    let mut handlers = 0;
    let mut command: Option<String> = None;
    let mut timeout: Option<u64> = None;
    let mut is_command = false;

    // The trailing header closes the last table.
    for line in text.lines().chain(std::iter::once("[")) {
        let line = line.trim();
        let Some(header) = line.strip_prefix('[') else {
            if open.is_some() {
                if let Some(value) = toml_value(line, "command") {
                    command = toml_unquote(value).map(str::to_owned);
                } else if let Some(value) = toml_value(line, "timeout") {
                    timeout = value.parse().ok();
                } else if let Some(value) = toml_value(line, "type") {
                    is_command = toml_unquote(value) == Some("command");
                }
            } else if let Some((_, _, matcher)) = group.as_mut()
                && let Some(value) = toml_value(line, "matcher")
            {
                *matcher = toml_unquote(value).map(str::to_owned);
            }
            continue;
        };

        if let Some(handler) = open
            && is_command
            && let Some(command) = command.take()
            && let Some((event, index, matcher)) = &group
        {
            tables.push(CodexHook {
                event: event.clone(),
                group: *index,
                handler,
                matcher: matcher.clone(),
                command,
                timeout: timeout.unwrap_or(CODEX_DEFAULT_TIMEOUT),
            });
        }
        open = None;
        command = None;
        timeout = None;
        is_command = false;

        let header = header.trim_matches(['[', ']']).trim();
        let Some(event) = header.strip_prefix("hooks.") else {
            group = None;
            continue;
        };
        match event.strip_suffix(".hooks") {
            // A handler of the group above it, and of nothing else.
            Some(event) if group.as_ref().is_some_and(|(open, ..)| open == event) => {
                open = Some(handlers);
                handlers += 1;
            }
            Some(_) => group = None,
            None => {
                let count = seen.entry(event.to_owned()).or_insert(0);
                group = Some((event.to_owned(), *count, None));
                *count += 1;
                handlers = 0;
            }
        }
    }
    tables
}

/// Writes `~/.nd7/aliases.sh`, one `alias <agent>='nd7 run <agent>'` per
/// agent, and returns those lines. The alias names `nd7` rather than a path,
/// so reinstalling nd7 keeps it working, and it does not recurse: `nd7 run`
/// looks its program up on `PATH` itself, where the shell's aliases do not
/// reach.
pub fn install_aliases(home: &Path, agents: &[Agent]) -> io::Result<Vec<String>> {
    let dir = home.join(".nd7");
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;

    let lines: Vec<String> = agents
        .iter()
        .map(|agent| format!("alias {agent}='nd7 run {agent}'"))
        .collect();
    let mut text = String::from(
        "# Written by `nd7 init`. Each agent starts under nd7's sandbox. Remove the `source` line from your shell rc to disable.\n",
    );
    for line in &lines {
        text.push_str(line);
        text.push('\n');
    }

    let path = dir.join("aliases.sh");
    fs::write(&path, text)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
    Ok(lines)
}

/// The one line `nd7 init` adds to a shell rc.
const SOURCE_LINE: &str =
    r#"[ -f "$HOME/.nd7/aliases.sh" ] && source "$HOME/.nd7/aliases.sh"  # nd7"#;

/// Appends that line to `rc`, unless a line there already mentions the
/// aliases file; returns whether it was added. The file is only ever appended
/// to, and is created if it does not exist.
pub fn source_aliases(rc: &Path) -> io::Result<bool> {
    let text = read_or_empty(rc)?;
    if text.lines().any(|line| line.contains(".nd7/aliases.sh")) {
        return Ok(false);
    }
    let mut file = fs::OpenOptions::new().create(true).append(true).open(rc)?;
    if !text.is_empty() && !text.ends_with('\n') {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{SOURCE_LINE}")?;
    Ok(true)
}

/// `s` as a TOML basic string: wrapped in `"`, with `\` and `"` escaped and
/// every control character written as an escape. Codex parses its
/// configuration and each `-c` override as TOML, so this is the one place a
/// value nd7 gives it is quoted.
pub fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str(r"\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            '\u{8}' => out.push_str(r"\b"),
            '\u{c}' => out.push_str(r"\f"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A file's contents, or the empty string if it does not exist.
fn read_or_empty(path: &Path) -> io::Result<String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(e),
    }
}

fn read_json(path: &Path) -> io::Result<Value> {
    let text = read_or_empty(path)?;
    if text.trim().is_empty() {
        return Ok(Value::Object(Map::new()));
    }
    serde_json::from_str(&text).map_err(|e| io::Error::other(format!("{}: {e}", path.display())))
}

/// A settings file as its top-level object; a missing or empty file is `{}`.
fn read_object(path: &Path) -> io::Result<Map<String, Value>> {
    match read_json(path)? {
        Value::Object(map) => Ok(map),
        other => Err(io::Error::other(format!(
            "{}: expected a JSON object, got {other}",
            path.display()
        ))),
    }
}

/// The array of hook entries registered for `event`, created if absent.
fn entries_of<'a>(
    hooks: &'a mut Map<String, Value>,
    event: &str,
) -> io::Result<&'a mut Vec<Value>> {
    match hooks
        .entry(event)
        .or_insert_with(|| Value::Array(Vec::new()))
    {
        Value::Array(entries) => Ok(entries),
        other => Err(io::Error::other(format!(
            "hooks.{event} is not an array: {other}"
        ))),
    }
}

/// The hooks of one registration entry.
fn hooks_of(entry: &Value) -> std::slice::Iter<'_, Value> {
    entry
        .get("hooks")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
        .iter()
}

fn command_of(hook: &Value) -> Option<&str> {
    hook.get("command").and_then(Value::as_str)
}

/// Does this entry run nd7 as a `record` hook? Any nd7 path counts: a second
/// hook running another checkout's nd7 would record every event twice.
fn has_record_hook(entry: &Value) -> bool {
    hooks_of(entry).any(|hook| {
        command_of(hook).is_some_and(|command| command.ends_with("nd7"))
            && hook.get("args").and_then(Value::as_array) == Some(&vec![json!("record")])
    })
}

fn has_prefix_hook(entry: &Value) -> bool {
    hooks_of(entry)
        .any(|hook| command_of(hook).is_some_and(|command| command.ends_with(PREFIX_TAIL)))
}

/// Does a `[[hooks.<event>]]` or `[[hooks.<event>.hooks]]` table in `text`
/// hold a `command` the predicate accepts?
///
/// Line-based, so that installing hooks needs no TOML parser and no
/// dependency: a `[`-table header opens a section, and every `command = "…"`
/// line until the next header belongs to it. That reads what `nd7 init` writes
/// and what the documented configuration looks like; a hook given as an inline
/// array (`hooks.PreToolUse = [{…}]`, the shape `-c` takes) is not seen, and
/// would make `nd7 init` append a second one.
fn codex_command(text: &str, event: &str, accept: impl Fn(&str) -> bool) -> bool {
    let (table, hooks) = (format!("hooks.{event}"), format!("hooks.{event}.hooks"));
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            let header = header.trim_matches(['[', ']']).trim();
            inside = header == table || header == hooks;
        } else if inside
            && let Some(command) = toml_value(line, "command").and_then(toml_unquote)
            && accept(command)
        {
            return true;
        }
    }
    false
}

/// The right-hand side of a `<key> = <value>` line, if that is what this line
/// is.
fn toml_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(key)?.trim_start();
    Some(rest.strip_prefix('=')?.trim_start())
}

/// The contents of a TOML basic string, up to its closing quote.
fn toml_unquote(value: &str) -> Option<&str> {
    let value = value.strip_prefix('"')?;
    value.get(..value.find('"')?)
}

/// Writes `contents` through a temporary file in the same directory, so a
/// settings file is never left half-written.
fn write_atomic(path: &Path, contents: &str) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut name = path.as_os_str().to_owned();
    name.push(".nd7-tmp");
    let tmp = PathBuf::from(name);
    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    const ND7: &str = "/usr/local/bin/nd7";

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nd7-agent-config-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn claude_install_is_idempotent() {
        let dir = scratch("claude-twice");
        let settings = dir.join("settings.json");

        assert_eq!(
            install_claude(&settings, Path::new(ND7)).unwrap(),
            Changed::Installed
        );
        let first = fs::read_to_string(&settings).unwrap();
        assert_eq!(
            install_claude(&settings, Path::new(ND7)).unwrap(),
            Changed::AlreadyInstalled
        );
        assert_eq!(fs::read_to_string(&settings).unwrap(), first);

        let root: Value = serde_json::from_str(&first).unwrap();
        let hooks = &root["hooks"];
        for event in RECORD_EVENTS {
            let entry = &hooks[event][0]["hooks"][0];
            assert_eq!(entry["command"], ND7);
            assert_eq!(entry["args"], json!(["record"]));
        }
        assert_eq!(hooks["SessionEnd"][0]["hooks"][0]["timeout"], 1);
        assert_eq!(hooks["Stop"][0]["hooks"][0]["timeout"], 5);
        // The record entry stays first; the prefix follows it, matching Bash.
        assert_eq!(hooks["PreToolUse"].as_array().unwrap().len(), 2);
        assert_eq!(hooks["PreToolUse"][1]["matcher"], "Bash");
        assert_eq!(
            hooks["PreToolUse"][1]["hooks"][0]["command"],
            format!("{ND7} hook-prefix")
        );

        assert!(claude_has_hook(&settings, Path::new(ND7)));
        assert!(!claude_has_hook(&settings, Path::new("/opt/nd7")));
        assert!(!claude_has_hook(&dir.join("absent.json"), Path::new(ND7)));
    }

    #[test]
    fn claude_install_keeps_what_is_already_there() {
        let dir = scratch("claude-merge");
        let settings = dir.join("settings.json");
        fs::write(
            &settings,
            r#"{
              "model": "opus",
              "hooks": {
                "PreToolUse": [
                  { "matcher": "Write", "hooks": [ { "type": "command", "command": "/usr/bin/audit" } ] }
                ],
                "Stop": [
                  { "hooks": [ { "type": "command", "command": "/opt/other/nd7", "args": ["record"], "timeout": 5 } ] }
                ]
              }
            }"#,
        )
        .unwrap();

        assert_eq!(
            install_claude(&settings, Path::new(ND7)).unwrap(),
            Changed::Installed
        );
        let root: Value = serde_json::from_str(&fs::read_to_string(&settings).unwrap()).unwrap();
        assert_eq!(root["model"], "opus");

        let pre = root["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 3);
        assert_eq!(pre[0]["hooks"][0]["command"], "/usr/bin/audit");
        assert_eq!(pre[1]["hooks"][0]["args"], json!(["record"]));
        assert_eq!(pre[2]["matcher"], "Bash");

        // A record hook running another nd7 is already a record hook.
        let stop = root["hooks"]["Stop"].as_array().unwrap();
        assert_eq!(stop.len(), 1);
        assert_eq!(stop[0]["hooks"][0]["command"], "/opt/other/nd7");
    }

    #[test]
    fn claude_refuses_a_settings_file_that_is_not_an_object() {
        let dir = scratch("claude-bad");
        let settings = dir.join("settings.json");
        fs::write(&settings, "[1, 2]").unwrap();
        assert!(install_claude(&settings, Path::new(ND7)).is_err());
    }

    #[test]
    fn codex_install_is_idempotent() {
        let dir = scratch("codex-twice");
        let config = dir.join("config.toml");
        fs::write(&config, "model = \"gpt-5\"\n").unwrap();

        assert_eq!(
            install_codex(&config, Path::new(ND7)).unwrap(),
            Changed::Installed
        );
        let first = fs::read_to_string(&config).unwrap();
        assert!(first.starts_with("model = \"gpt-5\"\n"));
        assert!(first.contains(&format!("command = \"{ND7} hook-prefix\"")));
        assert!(first.contains("[[hooks.SessionEnd.hooks]]"));
        assert!(first.contains("timeout = 3"));

        assert_eq!(
            install_codex(&config, Path::new(ND7)).unwrap(),
            Changed::AlreadyInstalled
        );
        assert_eq!(fs::read_to_string(&config).unwrap(), first);

        assert!(codex_has_hook(&config, Path::new(ND7)));
        assert!(!codex_has_hook(&config, Path::new("/opt/nd7")));
        assert!(!codex_has_hook(&dir.join("absent.toml"), Path::new(ND7)));
    }

    /// A hook another nd7 installed counts, and a hook under another event
    /// does not: the guard is per event.
    #[test]
    fn codex_install_sees_hooks_per_event() {
        let dir = scratch("codex-partial");
        let config = dir.join("config.toml");
        fs::write(
            &config,
            "[[hooks.Stop]]\n\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"/opt/other/nd7 record\"\ntimeout = 5\n",
        )
        .unwrap();

        install_codex(&config, Path::new(ND7)).unwrap();
        let text = fs::read_to_string(&config).unwrap();
        assert_eq!(text.matches("[[hooks.Stop]]").count(), 1);
        assert_eq!(text.matches("[[hooks.SessionStart]]").count(), 1);
        assert!(text.contains(&format!("command = \"{ND7} hook-prefix\"")));
    }

    #[test]
    fn aliases_and_the_rc_line_are_written_once() {
        let home = scratch("aliases");
        let lines = install_aliases(&home, &[Agent::Claude, Agent::Codex]).unwrap();
        assert_eq!(
            lines,
            [
                "alias claude='nd7 run claude'",
                "alias codex='nd7 run codex'"
            ]
        );
        let path = home.join(".nd7/aliases.sh");
        let first = fs::read_to_string(&path).unwrap();
        assert!(first.starts_with("# Written by `nd7 init`."));
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        install_aliases(&home, &[Agent::Claude, Agent::Codex]).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), first);

        let rc = home.join(".zshrc");
        fs::write(&rc, "export EDITOR=vi").unwrap();
        assert!(source_aliases(&rc).unwrap());
        assert_eq!(
            fs::read_to_string(&rc).unwrap(),
            format!("export EDITOR=vi\n{SOURCE_LINE}\n")
        );
        assert!(!source_aliases(&rc).unwrap());
        assert_eq!(
            fs::read_to_string(&rc).unwrap(),
            format!("export EDITOR=vi\n{SOURCE_LINE}\n")
        );

        let missing = home.join(".bashrc");
        assert!(source_aliases(&missing).unwrap());
        assert_eq!(
            fs::read_to_string(&missing).unwrap(),
            format!("{SOURCE_LINE}\n")
        );
    }

    /// The hashes Codex 0.155.1 wrote for nd7's own seven hooks, which is the
    /// whole of what makes the approval `nd7 init` writes an approval.
    #[test]
    fn codex_tables_for_events_codex_does_not_know_are_ignored() {
        let text = "[[hooks.PostToolUseFailure]]\n\n[[hooks.PostToolUseFailure.hooks]]\ntype = \"command\"\ncommand = \"/opt/nd7 record\"\ntimeout = 5\n\n[[hooks.Stop]]\n\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"/opt/nd7 record\"\ntimeout = 5\n";
        let tables = codex_hook_tables(text);
        let events: Vec<&str> = tables.iter().map(|h| h.event.as_str()).collect();
        assert_eq!(events, ["Stop"]);
    }

    #[test]
    fn codex_trust_hashes_match_what_codex_wrote() {
        // The recipe hashes the compact JSON with its keys sorted, which is
        // what `json!` prints only because serde_json's map is a `BTreeMap`.
        assert_eq!(json!({ "b": 1, "a": 0 }).to_string(), r#"{"a":0,"b":1}"#);

        const BIN: &str = "/Users/ahmedabouzied/code/work/nd7/nd7-core/target/debug/nd7";
        let record = format!("{BIN} record");
        assert_eq!(
            codex_trust_hash("PreToolUse", Some(""), &format!("{BIN} hook-prefix"), 30),
            "sha256:f9cbd7b6646c3a4b20eb1bb2451eb42e878f8dea1806bd797a4ab352b49a66c3"
        );
        for (event, timeout, hash) in [
            (
                "PreToolUse",
                5,
                "sha256:cabe9c60eb00ed439de3b0b8de1042fe963862bada93934e23bfa33f365a1743",
            ),
            (
                "PostToolUse",
                5,
                "sha256:c030f1fab807ae5792b048059214fb6a5d97ec6cce3d88ac106b9d133a67114d",
            ),
            (
                "SessionStart",
                5,
                "sha256:046fda48a39155761ff4bc80d8d9476b51be21b3f8d28c4414707aee0d3368a7",
            ),
            (
                "SessionEnd",
                3,
                "sha256:a6cfa7762b2e64ff2742a9ab7e0076b490c14dd15838fcde8faa197c85349eec",
            ),
            (
                "UserPromptSubmit",
                5,
                "sha256:dbc9e1486d479ad2c9184b01810a67bf8717b68c0c402b3a67cbdecfa657c5aa",
            ),
            (
                "Stop",
                5,
                "sha256:7f875b333a36a1a74f4a222c9198f7b57d3205f82068546c73ddd5267348a362",
            ),
        ] {
            assert_eq!(
                codex_trust_hash(event, None, &record, timeout),
                hash,
                "{event}"
            );
        }
    }

    /// `nd7 init` writes the approval, so the hooks are trusted as soon as
    /// they are installed, and stay so when it runs again.
    #[test]
    fn codex_install_writes_the_trust_codex_would_ask_for() {
        let dir = scratch("codex-trust");
        let config = dir.join("config.toml");
        let nd7 = Path::new(ND7);
        assert!(!codex_hooks_trusted(&config, nd7), "no file");

        install_codex(&config, nd7).unwrap();
        let text = fs::read_to_string(&config).unwrap();
        assert!(codex_hooks_trusted(&config, nd7));
        assert!(text.contains(&format!(
            "[hooks.state.\"{}:pre_tool_use:0:0\"]\ntrusted_hash = \"{}\"\n",
            config.display(),
            codex_trust_hash("PreToolUse", Some(""), &format!("{ND7} hook-prefix"), 30)
        )));
        assert_eq!(
            codex_trust_keys_present(&text).len(),
            7,
            "the prefix hook and six record hooks"
        );
        assert_eq!(
            install_codex(&config, nd7).unwrap(),
            Changed::AlreadyInstalled
        );
        assert_eq!(fs::read_to_string(&config).unwrap(), text);

        // Only a later edit can take the trust away again.
        let edited = text.replacen("trusted_hash", "was_trusted_hash", 1);
        fs::write(&config, edited).unwrap();
        assert!(!codex_hooks_trusted(&config, nd7));
        fs::remove_dir_all(&dir).unwrap();
    }

    /// The layout Codex keys its state by: a foreign `PreToolUse` group first
    /// puts nd7's at index 1, and the state table Codex writes for it is the
    /// one that counts — another config's is not.
    #[test]
    fn codex_trust_reads_the_state_codex_writes() {
        let dir = scratch("codex-state");
        let config = dir.join("config.toml");
        let nd7 = Path::new(ND7);
        let hooks = format!(
            "[[hooks.PreToolUse]]\n\
             matcher = \"Bash\"\n\
             \n\
             [[hooks.PreToolUse.hooks]]\n\
             type = \"command\"\n\
             command = \"/usr/bin/audit\"\n\
             timeout = 10\n\
             \n\
             [[hooks.PreToolUse]]\n\
             matcher = \"\"\n\
             \n\
             [[hooks.PreToolUse.hooks]]\n\
             type = \"command\"\n\
             command = \"{ND7} hook-prefix\"\n\
             timeout = 30\n"
        );
        let ours = &codex_hook_tables(&hooks)[1];
        assert_eq!((ours.group, ours.handler), (1, 0));
        assert_eq!(ours.matcher.as_deref(), Some(""));
        assert_eq!(ours.timeout, 30);

        let unrelated = "\n[hooks.state.\"/x:stop:0:0\"]\n\
                         trusted_hash = \"sha256:00\"\n";
        fs::write(&config, format!("{hooks}{unrelated}")).unwrap();
        assert!(!codex_hooks_trusted(&config, nd7));

        fs::write(
            &config,
            format!(
                "{hooks}{unrelated}\n[hooks.state.\"{}:pre_tool_use:1:0\"]\ntrusted_hash = \"{}\"\n",
                config.display(),
                codex_trust_hash("PreToolUse", Some(""), &format!("{ND7} hook-prefix"), 30)
            ),
        )
        .unwrap();
        assert!(codex_hooks_trusted(&config, nd7));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn toml_strings_are_quoted_and_escaped() {
        assert_eq!(toml_string("plain"), r#""plain""#);
        assert_eq!(toml_string(r#"a "b" c"#), r#""a \"b\" c""#);
        assert_eq!(toml_string(r"back\slash"), r#""back\\slash""#);
        assert_eq!(toml_string("one\ntwo\ttab"), r#""one\ntwo\ttab""#);
        assert_eq!(toml_string("\u{1}"), r#""\u0001""#);
    }
}
