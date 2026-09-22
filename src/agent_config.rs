//! nd7's hooks in an agent's own configuration, and the shell aliases that
//! start an agent under `nd7 run`.
//!
//! `nd7 run` can pass its `PreToolUse` hook per invocation, but Codex then
//! needs `--dangerously-bypass-hook-trust` and prints two advisories at every
//! start, because only a hook discovered from a configuration file carries the
//! trust hash it checks. Writing the hooks once — `nd7 init` — removes that,
//! and registers the `record` hooks the log is made of at the same time.
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
    fmt, fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use serde_json::{Map, Value, json};

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
    for event in RECORD_EVENTS {
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

/// Whether every nd7 hook in a Codex config carries the `trusted_hash` Codex
/// writes when the user approves it. Codex approves hooks by rewriting
/// `config.toml`, and under `nd7 run` that file is deliberately unwritable, so
/// approval has to happen in a session nd7 did not start. Until it has, `nd7
/// run` passes `--dangerously-bypass-hook-trust` and says so. False when the
/// file has no nd7 hook at all.
pub fn codex_hooks_trusted(config: &Path, nd7: &Path) -> bool {
    let Ok(text) = fs::read_to_string(config) else {
        return false;
    };
    let ours = format!("{} ", nd7.display());
    let (mut found, mut all_trusted) = (false, true);
    // One nd7 hook table at a time: its command, and whether a hash followed.
    let (mut in_hooks_table, mut is_ours, mut trusted) = (false, false, false);
    let mut close = |is_ours: bool, trusted: bool| {
        if is_ours {
            found = true;
            all_trusted &= trusted;
        }
    };
    for line in text.lines() {
        let line = line.trim();
        if let Some(header) = line.strip_prefix('[') {
            close(is_ours, trusted);
            let header = header.trim_matches(['[', ']']).trim();
            in_hooks_table = header.starts_with("hooks.") && header.ends_with(".hooks");
            (is_ours, trusted) = (false, false);
        } else if in_hooks_table {
            if let Some(command) = toml_command(line) {
                is_ours = command.starts_with(&ours);
            } else if line.starts_with("trusted_hash") {
                trusted = true;
            }
        }
    }
    close(is_ours, trusted);
    found && all_trusted
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
            && let Some(command) = toml_command(line)
            && accept(command)
        {
            return true;
        }
    }
    false
}

/// The value of a `command = "…"` line, if that is what this line is.
fn toml_command(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("command")?.trim_start();
    let value = rest.strip_prefix('=')?.trim_start().strip_prefix('"')?;
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

    #[test]
    fn codex_trust_is_per_nd7_hook() {
        let dir = scratch("codex-trust");
        let config = dir.join("config.toml");
        let nd7 = Path::new("/opt/nd7");
        assert!(!codex_hooks_trusted(&config, nd7), "no file");
        install_codex(&config, nd7).unwrap();
        assert!(
            !codex_hooks_trusted(&config, nd7),
            "installed, nothing approved"
        );
        // Codex approves by adding trusted_hash to each hook table. A foreign
        // hook without one does not count against nd7's.
        let approved = fs::read_to_string(&config)
            .unwrap()
            .replace("timeout = 30\n", "timeout = 30\ntrusted_hash = \"abc\"\n")
            .replace("timeout = 5\n", "timeout = 5\ntrusted_hash = \"abc\"\n")
            .replace("timeout = 3\n", "timeout = 3\ntrusted_hash = \"abc\"\n")
            + "\n[[hooks.Stop]]\n\n[[hooks.Stop.hooks]]\ntype = \"command\"\ncommand = \"/other/tool\"\n";
        fs::write(&config, approved).unwrap();
        assert!(codex_hooks_trusted(&config, nd7));
        // One nd7 hook left unapproved: not trusted.
        let partial =
            fs::read_to_string(&config)
                .unwrap()
                .replacen("trusted_hash = \"abc\"\n", "", 1);
        fs::write(&config, partial).unwrap();
        assert!(!codex_hooks_trusted(&config, nd7));
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
