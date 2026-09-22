//! `nd7`: the flight recorder's command line.
//!
//! - `nd7 record`: read one Claude Code hook payload from stdin and append it
//!   to the session log as one sealed event. This is what the hooks call.
//! - `nd7 verify <session-id>`: walk that session's chain and report.
//! - `nd7 enroll <server> <token>`: bind this machine to a vault.
//! - `nd7 ship`: push unshipped frames to that vault.
//! - `nd7 run [--profile <file>] <program> [args...]`: run a program under
//!   nd7's sandbox: a session, the floor profile, and for `claude` and
//!   `codex` the hook that routes every Bash command through `nd7-exec`.
//!   macOS only.
//! - `nd7 init [claude|codex]`: write nd7's hooks into the agent's own
//!   configuration, and the shell aliases that start it under `nd7 run`, so
//!   `nd7 run` no longer has to pass the hooks per invocation.
//! - `nd7 hook-prefix`: the PreToolUse hook `nd7 run` installs; rewrites a
//!   Bash command to run through `nd7-exec`. Silent outside a session.
//! - `nd7 allow <path>` / `nd7 deny <path>`: widen or narrow the running
//!   session's policy; the next Bash command sees it, no restart.
//!
//! Plain blocking I/O; nothing here needs a runtime.
//!
//! `sessions` and `show` arrive with milestone M5.

use std::{
    env,
    io::{self, Read},
    process::ExitCode,
    time::Duration,
};

use nd7_core::{
    agent_config::{self, Agent, Changed},
    hook::{Event, HookInput, Invocation},
    session_log::{ChainError, Report, SessionLog},
    ship,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage: nd7 <command>

commands:
  record                     read a Claude Code hook payload from stdin, append it to the session log
  verify <session-id>        check that a session's chain is intact
  enroll <server> <token>    bind this machine to a vault; --rotate replaces its signing key
  ship                       push unshipped frames to the vault; --every <duration> loops,
                             --prune-after <duration> deletes fully shipped sessions.
                             Durations are like 30s, 5m, 2h, 30d. See docs/VAULT.md.
  run <program> [args...]    run a program under nd7's sandbox: a session is created and
                             the floor profile applied; for claude and codex, the Bash hook
                             and the system-prompt note are added too. --profile <file>
                             applies that raw profile instead, with no session
  init [claude|codex]        write nd7's hooks into the agent's own configuration, once,
                             and shell aliases that start it under nd7 run. No agent
                             named: both, skipping one that is not installed. --global
                             (the default) writes under ~; --project writes .claude in
                             this directory; --no-alias leaves the shell alone
  hook-prefix                the PreToolUse hook nd7 run installs: reads the payload on
                             stdin, replies with the Bash command routed through nd7-exec
  allow <path>               let the running session write under <path>, from the next
                             command on; --session <pid> picks one when several run
  deny <path>                take that grant back";

/// What a clean verify does and does not prove. Printed with every success so
/// nobody reads it as more than it is.
const CAVEAT: &str = "note: proves the log is unchanged since its last frame was written by this machine; anyone with write access could rewrite the whole chain.";

fn main() -> ExitCode {
    // Environment first: `ts` marks when the hook fired, not when parsing ended.
    let inv = Invocation::now();
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        Some("record") => {
            // A hook must never block the agent: report on stderr, exit 0.
            // Claude Code treats exit 2 as a decision and other non-zero exits
            // as a hook error; neither is ours to make.
            if let Err(e) = record(inv) {
                eprintln!("nd7 record: {e}");
            }
            ExitCode::SUCCESS
        }
        Some("verify") => match args.next() {
            Some(session_id) => match verify(&session_id) {
                Ok(report) => {
                    let head = report.last_hash.as_deref().map_or("none", |h| &h[..16]);
                    println!("verified: {} frames, head {head}", report.frames);
                    println!("{CAVEAT}");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("nd7 verify: {e}");
                    ExitCode::from(1)
                }
            },
            None => {
                eprintln!("usage: nd7 verify <session-id>");
                ExitCode::from(2)
            }
        },
        Some("enroll") => {
            let rest: Vec<String> = args.collect();
            let rotate = rest.iter().any(|arg| arg == "--rotate");
            let named: Vec<&str> = rest
                .iter()
                .map(String::as_str)
                .filter(|arg| *arg != "--rotate")
                .collect();
            match named.as_slice() {
                [server, token] => match ship::enroll(server, token, rotate) {
                    Ok(machine_id) => {
                        println!("enrolled as {machine_id}");
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("nd7 enroll: {e}");
                        ExitCode::from(1)
                    }
                },
                _ => {
                    eprintln!("usage: nd7 enroll <server> <token> [--rotate]");
                    ExitCode::from(2)
                }
            }
        }
        Some("ship") => match ship_options(args) {
            // The exit code is `ship`'s own; see its documentation.
            Ok((every, prune_after)) => match ship::ship(every, prune_after) {
                Ok(code) => ExitCode::from(code),
                Err(e) => {
                    eprintln!("nd7 ship: {e}");
                    ExitCode::from(1)
                }
            },
            Err(e) => {
                eprintln!(
                    "nd7 ship: {e}\nusage: nd7 ship [--every <duration>] [--prune-after <duration>]"
                );
                ExitCode::from(2)
            }
        },
        Some("run") => run(args),
        Some("init") => init(args),
        Some("hook-prefix") => hook_prefix(),
        Some(verb @ ("allow" | "deny")) => match grant(verb, args) {
            Ok(msg) => {
                println!("{msg}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("nd7 {verb}: {e}\nusage: nd7 {verb} [--session <pid>] <path>");
                ExitCode::from(2)
            }
        },
        Some("-h" | "--help") => {
            println!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some(other) => {
            eprintln!("nd7: unknown command `{other}`\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn record(inv: Invocation) -> Result<()> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    let input: HookInput = raw.parse()?;
    let event = Event::new(input, inv);
    SessionLog::open(&event.session_id)?.append(event)?;
    Ok(())
}

fn verify(session_id: &str) -> std::result::Result<Report, ChainError> {
    SessionLog::open(session_id)
        .map_err(|e| ChainError::Io(e.to_string()))?
        .verify()
}

/// `nd7 run [--profile <file>] <program> [args...]`: the program runs under a
/// Seatbelt profile, with this process's stdin, stdout and stderr, and its exit
/// code becomes ours.
#[cfg(target_os = "macos")]
fn run(mut args: impl Iterator<Item = String>) -> ExitCode {
    use std::{os::unix::process::ExitStatusExt, path::PathBuf, process::ExitStatus};

    /// Seatbelt takes its parameters as strings, so a path that is not UTF-8
    /// cannot be one.
    fn param(path: PathBuf) -> Result<String> {
        path.into_os_string()
            .into_string()
            .map_err(|path| format!("path is not UTF-8: {path:?}").into())
    }

    /// `--profile <file>`: the raw profile, with PROJ, TMP and HOME as
    /// parameters, and no session. For experiments.
    fn spawn_raw(
        path: &str,
        program: &str,
        args: impl Iterator<Item = String>,
    ) -> Result<ExitStatus> {
        let profile = std::fs::read_to_string(path)?;
        // `subpath` matches resolved paths, so the parameters are canonical.
        let proj = param(env::current_dir()?.canonicalize()?)?;
        let tmp = param(env::temp_dir().canonicalize()?)?;
        let home = param(nd7_core::session::home()?)?;
        let params = [("PROJ", &*proj), ("TMP", &*tmp), ("HOME", &*home)];
        Ok(
            nd7_core::sandbox::spawn_with_profile(&profile, program, &params)
                .args(args)
                .status()?,
        )
    }

    /// The real thing: a session with this run's policy, and the floor
    /// rendered from it applied to the program and everything it spawns.
    fn spawn(program: &str, args: impl Iterator<Item = String>) -> Result<ExitStatus> {
        use nd7_core::{policy::Policy, session::Session};

        let home = nd7_core::session::home()?;
        let policy = Policy {
            project: env::current_dir()?.canonicalize()?,
            tmp: env::temp_dir().canonicalize()?,
            exit: exit_path()?,
            home,
            grants: Vec::new(),
        };
        trusted(&policy.exit)?;
        let session = Session::create(&sessions_root(&policy.home), &policy)?;
        let nd7 = nd7_binary()?;
        let agent = agent_of(program);
        eprintln!(
            "nd7 run: session {} under nd7's policy; a sandbox the program applies itself is refused{}",
            std::process::id(),
            match agent {
                Some(Agent::Codex)
                    if installed(Agent::Codex, &policy.home, &nd7)
                        && !agent_config::codex_hooks_trusted(
                            &policy.home.join(".codex/config.toml"),
                            &nd7,
                        ) =>
                {
                    " (hooks: installed, not yet trusted; run `nd7 init codex` to record Codex's approval)"
                }
                Some(agent) if installed(agent, &policy.home, &nd7) => " (hooks: installed)",
                Some(_) => " (hooks: per-invocation; run `nd7 init` to install them)",
                None => "",
            }
        );
        let mut cmd = nd7_core::sandbox::spawn_with_profile(&policy.render_floor(), program, &[]);
        // The hook nd7 installs runs for every session the agent starts, so it
        // needs to know which of them are nd7's.
        cmd.env("ND7_SESSION", std::process::id().to_string());
        let args: Vec<String> = args.collect();
        match agent {
            Some(Agent::Claude) => {
                cmd.args(claude_flags(&policy.home, &nd7)).args(&args);
            }
            Some(Agent::Codex) => {
                // Codex applies a `-c` override to a subcommand only when it
                // follows the subcommand: `codex -c hooks.… exec` accepts the
                // flag and never runs the hook, `codex exec -c hooks.…` does
                // (measured, 0.155.1). So the flags go after `exec` or
                // `resume` when that is how codex was invoked, and first
                // otherwise, for the TUI.
                let (sub, rest) = match args.first().map(String::as_str) {
                    Some("exec" | "e" | "resume") => (&args[..1], &args[1..]),
                    _ => (&args[..0], &args[..]),
                };
                cmd.args(sub)
                    .args(codex_flags(&policy.home, &nd7))
                    .args(rest);
            }
            None => {
                cmd.args(&args);
            }
        }
        let status = cmd.status()?;
        drop(session);
        Ok(status)
    }

    /// Where sessions are recorded. Must agree with `nd7-exec`, which derives
    /// it from passwd; the override exists for the tests only.
    fn sessions_root(home: &std::path::Path) -> PathBuf {
        #[cfg(feature = "test-seams")]
        if let Some(p) = env::var_os("ND7_SESSIONS_DIR") {
            return PathBuf::from(p);
        }
        home.join(".nd7/sessions")
    }

    /// The exit binary is the one thing allowed out of the sandbox, so it
    /// must exist and be writable by nobody but its owner.
    fn trusted(exit: &std::path::Path) -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(exit)
            .map_err(|e| format!("nd7-exec not found at {}: {e}", exit.display()))?;
        if !meta.is_file() {
            return Err(format!("{} is not a file", exit.display()).into());
        }
        for path in [exit, exit.parent().unwrap_or(exit)] {
            let mode = std::fs::metadata(path)?.permissions().mode();
            if mode & 0o022 != 0 {
                return Err(format!(
                    "{} is writable by group or others (mode {:o}); refusing to use it as the sandbox exit",
                    path.display(),
                    mode & 0o777
                )
                .into());
            }
        }
        Ok(())
    }

    // `--profile` is ours only before the program: from the program on, every
    // argument is the child's, including the ones that look like options.
    let (mut profile, mut program) = (None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--profile" => profile = args.next(),
            _ => {
                program = Some(arg);
                break;
            }
        }
    }
    let Some(program) = program else {
        eprintln!("usage: nd7 run [--profile <file>] <program> [args...]");
        return ExitCode::from(2);
    };

    let status = match profile {
        Some(path) => spawn_raw(&path, &program, args),
        None => spawn(&program, args),
    };
    match status {
        // No code means a signal killed it; report it as a shell would.
        Ok(status) => ExitCode::from(
            status
                .code()
                .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)) as u8,
        ),
        Err(e) => {
            eprintln!("nd7 run: {e}");
            ExitCode::from(2)
        }
    }
}

/// `program` resolved the way `Command` will resolve it — as a path when it
/// contains a `/`, on PATH otherwise — and then canonicalized, because an
/// installed agent is often a chain of symlinks (`~/.local/bin/codex` is two
/// hops from the real file).
fn resolve(program: &str) -> Option<std::path::PathBuf> {
    if program.contains('/') {
        std::path::Path::new(program).canonicalize().ok()
    } else {
        let path = env::var_os("PATH").unwrap_or_default();
        env::split_paths(&path).find_map(|dir| dir.join(program).canonicalize().ok())
    }
}

/// Which agent `program` names, if it names one. A shim under another name is
/// common, so the resolved file's name decides; if nothing resolves, the name
/// as given is all there is to go on.
#[cfg(target_os = "macos")]
fn agent_of(program: &str) -> Option<Agent> {
    let resolved = resolve(program);
    let name = resolved.as_deref().unwrap_or(std::path::Path::new(program));
    match name.file_name()?.to_str()? {
        "claude" => Some(Agent::Claude),
        "codex" => Some(Agent::Codex),
        _ => None,
    }
}

/// Whether this agent's own configuration already runs this nd7 as its
/// `PreToolUse` hook, in which case the flags leave the hook out.
#[cfg(target_os = "macos")]
fn installed(agent: Agent, home: &std::path::Path, nd7: &std::path::Path) -> bool {
    match agent {
        Agent::Claude => agent_config::claude_has_hook(&home.join(".claude/settings.json"), nd7),
        Agent::Codex => agent_config::codex_has_hook(&home.join(".codex/config.toml"), nd7),
    }
}

/// What `claude` needs to work with the floor: its own sandbox off, since
/// the floor refuses any other profile anyway and the failure would cost
/// one broken tool call; the hook that routes every Bash command through
/// `nd7-exec`, unless `nd7 init` has already put it in the settings; and one
/// line in the system prompt so a denial is read as nd7's and not as Claude
/// Code's own rules.
#[cfg(target_os = "macos")]
fn claude_flags(home: &std::path::Path, nd7: &std::path::Path) -> Vec<String> {
    let mut settings = serde_json::json!({ "sandbox": { "enabled": false } });
    if !installed(Agent::Claude, home, nd7) {
        let hook = format!("{} hook-prefix", nd7.display());
        settings["hooks"] = serde_json::json!({
            "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": hook } ] } ]
        });
    }
    vec![
        "--settings".to_owned(),
        settings.to_string(),
        "--append-system-prompt".to_owned(),
        SYSTEM_PROMPT.to_owned(),
    ]
}

/// The same three things for `codex`, in its own spelling.
/// `-s danger-full-access` keeps it from applying its own Seatbelt profile,
/// which the kernel refuses under the floor anyway; unlike
/// `--dangerously-bypass-approvals-and-sandbox` it leaves `approval_policy`
/// alone, so the TUI still asks before it runs a command.
/// `--dangerously-bypass-hook-trust` is what lets a hook given with `-c` run
/// at all: only hooks discovered from a config file carry the trust hash Codex
/// checks — which is why an installed hook needs neither that flag nor the
/// warning it prints at every start. And `developer_instructions` is Codex's
/// `--append-system-prompt`.
///
/// `-c approval_policy="never"` is deliberately not here: an interactive user
/// should keep the approvals. `codex exec` runs unattended, so add it there.
#[cfg(target_os = "macos")]
fn codex_flags(home: &std::path::Path, nd7: &std::path::Path) -> Vec<String> {
    let mut flags = vec!["-s".to_owned(), "danger-full-access".to_owned()];
    let config = home.join(".codex/config.toml");
    if !installed(Agent::Codex, home, nd7) {
        let hook = agent_config::toml_string(&format!("{} hook-prefix", nd7.display()));
        flags.push("--dangerously-bypass-hook-trust".to_owned());
        flags.push("-c".to_owned());
        flags.push(format!(
            r#"hooks.PreToolUse=[{{matcher="", hooks=[{{type="command", command={hook}, timeout=30}}]}}]"#
        ));
    } else if !agent_config::codex_hooks_trusted(&config, nd7) {
        // Installed, but the approval `nd7 init` writes is not there any more.
        // Codex records approval by writing config.toml, which the floor
        // forbids, so it cannot be given back from here.
        flags.push("--dangerously-bypass-hook-trust".to_owned());
    }
    flags.push("-c".to_owned());
    flags.push(format!(
        "developer_instructions={}",
        agent_config::toml_string(SYSTEM_PROMPT)
    ));
    flags
}

/// The note both agents get: a denial under nd7 is the policy, not the
/// agent's own permission rules, and `nd7 allow` is how it is widened.
#[cfg(target_os = "macos")]
const SYSTEM_PROMPT: &str = "This session runs under nd7's kernel sandbox. Bash commands are \
routed through nd7-exec by a hook and run under the session's policy: the project directory is \
writable, most of the rest of the filesystem is not, and only HTTPS egress is open. An \
'operation not permitted' error is that policy, not the agent's own permission rules. Do not try \
to route around it; tell the user what was denied. `nd7 allow <path>` widens the policy for \
Bash commands from the next call on; file-editing tools (Write, Edit, apply_patch) and Read see \
only the fixed policy, so for those the user must restart under a wider one.";

/// `nd7 hook-prefix`: Claude Code's PreToolUse hook. Reads the payload on
/// stdin and, for a Bash command, replies with the same command routed through
/// `nd7-exec`. Anything that goes wrong is reported on stderr and the reply
/// is empty: the command then runs unprefixed, where the floor denies it, so
/// a failing hook can only make things stricter.
fn hook_prefix() -> ExitCode {
    // `nd7 init` leaves the hook in the agent's configuration for good, so it
    // also fires for sessions nd7 did not start. There is no session then, and
    // `nd7-exec` would refuse every command it was handed, so the hook says
    // nothing and the agent runs the command itself.
    if env::var_os("ND7_SESSION").is_none() {
        return ExitCode::SUCCESS;
    }
    let mut payload = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut payload) {
        eprintln!("nd7 hook-prefix: {e}");
        return ExitCode::SUCCESS;
    }
    let exit = match exit_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("nd7 hook-prefix: {e}");
            return ExitCode::SUCCESS;
        }
    };
    match nd7_core::hook_prefix::respond(&payload, &exit) {
        Ok(Some(reply)) => println!("{reply}"),
        Ok(None) => {}
        Err(e) => eprintln!("nd7 hook-prefix: {e}"),
    }
    ExitCode::SUCCESS
}

/// `nd7 init [claude|codex] [--global|--project] [--no-alias]`: write nd7's
/// hooks into the agents' own configuration, and the aliases that start them
/// under `nd7 run`. Everything it writes is idempotent, so running it again
/// after an upgrade is safe.
fn init(args: impl Iterator<Item = String>) -> ExitCode {
    match init_agents(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!(
                "nd7 init: {e}\nusage: nd7 init [claude|codex] [--global|--project] [--no-alias]"
            );
            ExitCode::from(2)
        }
    }
}

fn init_agents(args: impl Iterator<Item = String>) -> Result<()> {
    let (mut named, mut project, mut aliases) = (None, false, true);
    for arg in args {
        match arg.as_str() {
            "claude" => named = Some(Agent::Claude),
            "codex" => named = Some(Agent::Codex),
            "--global" => project = false,
            "--project" => project = true,
            "--no-alias" => aliases = false,
            other => return Err(format!("unexpected argument `{other}`").into()),
        }
    }

    let home = nd7_core::session::home()?;
    let nd7 = nd7_binary()?;
    let agents: Vec<Agent> = match named {
        Some(agent) => vec![agent],
        // Both, except an agent that has never run on this machine: there is
        // no configuration of its own to write into.
        None => {
            let mut both = Vec::new();
            for agent in [Agent::Claude, Agent::Codex] {
                let dir = home.join(format!(".{agent}"));
                if dir.is_dir() {
                    both.push(agent);
                } else {
                    println!("{agent}: no {}; skipped", dir.display());
                }
            }
            both
        }
    };

    let root = if project {
        env::current_dir()?
    } else {
        home.clone()
    };
    for &agent in &agents {
        let (path, changed) = match agent {
            Agent::Claude => {
                let path = root.join(".claude/settings.json");
                let changed = agent_config::install_claude(&path, &nd7)?;
                (path, changed)
            }
            // Codex reads project-level hooks from `.codex/hooks.json`,
            // whose shape nd7 has not verified; `--global` is the one form it
            // writes.
            Agent::Codex if project => {
                println!("codex: project-level hooks not supported by nd7 init yet; use --global");
                continue;
            }
            Agent::Codex => {
                let path = root.join(".codex/config.toml");
                let changed = agent_config::install_codex(&path, &nd7)?;
                (path, changed)
            }
        };
        println!(
            "{agent}: hooks {} in {}",
            match changed {
                Changed::Installed => "installed",
                Changed::AlreadyInstalled => "already installed",
            },
            path.display()
        );
        if agent == Agent::Codex {
            println!(
                "note: the hooks are recorded as approved, so Codex does not ask about them at its next start."
            );
        }
    }

    if aliases {
        let mut on_path = Vec::new();
        for &agent in &agents {
            if resolve(agent.name()).is_some() {
                on_path.push(agent);
            } else {
                println!("{agent}: not on PATH; no alias written");
            }
        }
        if !on_path.is_empty() {
            let lines = agent_config::install_aliases(&home, &on_path)?;
            println!(
                "aliases: {} ({})",
                home.join(".nd7/aliases.sh").display(),
                lines.join("; ")
            );
            // zsh is macOS's login shell, so its rc is created if it is
            // missing; bash's is only added to when the user has one.
            let bashrc = home.join(".bashrc");
            for rc in [home.join(".zshrc")]
                .into_iter()
                .chain(bashrc.is_file().then_some(bashrc))
            {
                let added = agent_config::source_aliases(&rc)?;
                println!(
                    "{}: {} them",
                    rc.display(),
                    if added { "now loads" } else { "already loads" }
                );
            }
            println!("restart your shell or run: source ~/.nd7/aliases.sh");
        }
    }
    Ok(())
}

/// `nd7 allow <path>` and `nd7 deny <path>`: add or remove a write root in a
/// running session's policy. Only the record changes; `nd7-exec` reads it
/// again for the next command, so no restart is involved. Refuses paths under
/// `~/.nd7`, which no policy may ever make writable.
fn grant(verb: &str, mut args: impl Iterator<Item = String>) -> Result<String> {
    use std::path::PathBuf;
    let (mut session, mut path) = (None, None);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--session" => {
                session = Some(args.next().ok_or("--session needs a pid")?.parse::<u32>()?)
            }
            _ if path.is_none() => path = Some(arg),
            other => return Err(format!("unexpected argument `{other}`").into()),
        }
    }
    let path = path.ok_or("no path given")?;
    // `subpath` matches resolved paths, so grants are canonical. A grant whose
    // directory has since gone can still be taken back, as recorded.
    let path = match std::fs::canonicalize(&path) {
        Ok(p) => p,
        Err(_) if verb == "deny" => PathBuf::from(path),
        Err(e) => return Err(format!("{path}: {e}").into()),
    };
    let root = nd7_core::session::sessions_root()?;
    if path.starts_with(root.parent().unwrap_or(&root)) {
        return Err("nd7's own records can never be made writable".into());
    }
    let pid = match session {
        Some(pid) => pid,
        None => {
            let mut live: Vec<u32> = std::fs::read_dir(&root)?
                .filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
                .collect();
            live.sort_unstable();
            match live.as_slice() {
                [one] => *one,
                [] => return Err("no running nd7 session".into()),
                many => {
                    return Err(format!(
                        "several sessions are running ({many:?}); pass --session <pid>"
                    )
                    .into());
                }
            }
        }
    };
    let mut policy = nd7_core::session::load(&root, pid)?;
    let changed = match verb {
        "allow" if !policy.grants.contains(&path) => {
            policy.grants.push(path.clone());
            true
        }
        "deny" if policy.grants.contains(&path) => {
            policy.grants.retain(|g| g != &path);
            true
        }
        _ => false,
    };
    if changed {
        nd7_core::session::write_policy_at(&root.join(pid.to_string()), &policy)?;
    }
    Ok(match (verb, changed) {
        ("allow", true) => format!(
            "session {pid}: writes under {} allowed from the next command",
            path.display()
        ),
        ("allow", false) => format!("session {pid}: {} was already allowed", path.display()),
        (_, true) => format!(
            "session {pid}: writes under {} denied from the next command",
            path.display()
        ),
        _ => format!("session {pid}: {} was not a grant", path.display()),
    })
}

/// This binary, resolved: the hook command and the exit path are derived
/// from it, so `nd7 run` and the hook it installs always agree.
fn nd7_binary() -> Result<std::path::PathBuf> {
    Ok(env::current_exe()?.canonicalize()?)
}

/// `nd7-exec`, installed next to this binary. The floor lets exactly this
/// path out of the sandbox, so it is found by where nd7 itself is, never by
/// anything in the environment.
fn exit_path() -> Result<std::path::PathBuf> {
    Ok(nd7_binary()?.with_file_name("nd7-exec"))
}

#[cfg(not(target_os = "macos"))]
fn run(_args: impl Iterator<Item = String>) -> ExitCode {
    eprintln!("nd7 run: only supported on macOS");
    ExitCode::from(2)
}

/// `--every` and `--prune-after`, in either order, both optional.
fn ship_options(
    mut args: impl Iterator<Item = String>,
) -> Result<(Option<Duration>, Option<Duration>)> {
    let (mut every, mut prune_after) = (None, None);
    while let Some(arg) = args.next() {
        let target = match arg.as_str() {
            "--every" => &mut every,
            "--prune-after" => &mut prune_after,
            other => return Err(format!("unknown option `{other}`").into()),
        };
        let value = args.next().ok_or(format!("{arg} needs a duration"))?;
        *target = Some(parse_duration(&value)?);
    }
    Ok((every, prune_after))
}

/// A whole number of seconds, minutes, hours or days: `30s`, `5m`, `2h`,
/// `30d`. The only durations `ship` takes, and not worth a crate.
fn parse_duration(s: &str) -> Result<Duration> {
    let unit_at = s.len().saturating_sub(1);
    let secs = match s.split_at_checked(unit_at) {
        Some((count, "s")) => count.parse::<u64>().map(|n| (n, 1)),
        Some((count, "m")) => count.parse::<u64>().map(|n| (n, 60)),
        Some((count, "h")) => count.parse::<u64>().map(|n| (n, 60 * 60)),
        Some((count, "d")) => count.parse::<u64>().map(|n| (n, 24 * 60 * 60)),
        _ => return Err(format!("duration `{s}`: expected a number and s, m, h or d").into()),
    };
    let (count, unit) = secs.map_err(|_| format!("duration `{s}`: not a whole number"))?;
    let seconds = count
        .checked_mul(unit)
        .ok_or(format!("duration `{s}`: too long"))?;
    Ok(Duration::from_secs(seconds))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::fs;

    /// The name is resolved the way `Command` resolves it, so a symlink chain
    /// and a shim under another name both land on the agent they really are.
    #[test]
    fn agent_of_follows_path_and_symlinks() {
        use std::os::unix::fs::symlink;

        let root = env::temp_dir().join(format!("nd7-agent-of-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let bin = root.join("bin");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(root.join("releases/1.2.3/bin")).unwrap();
        fs::write(root.join("releases/1.2.3/bin/codex"), "").unwrap();
        fs::write(bin.join("claude"), "").unwrap();
        // As codex is installed: bin/codex -> current/bin/codex -> releases/…
        symlink(root.join("releases/1.2.3"), root.join("current")).unwrap();
        symlink(root.join("current/bin/codex"), bin.join("codex")).unwrap();
        symlink(bin.join("claude"), bin.join("my-agent")).unwrap();

        // SAFETY: the one test in this binary that touches the environment.
        unsafe { env::set_var("PATH", &bin) };

        assert_eq!(agent_of("codex"), Some(Agent::Codex));
        assert_eq!(agent_of("my-agent"), Some(Agent::Claude));
        assert_eq!(
            agent_of(bin.join("codex").to_str().unwrap()),
            Some(Agent::Codex)
        );
        assert_eq!(agent_of("zsh"), None);
        // Nothing to resolve: the name as given is all there is.
        assert_eq!(agent_of("/nowhere/claude"), Some(Agent::Claude));

        fs::remove_dir_all(&root).unwrap();
    }

    /// Both agents' flags carry the hook only while it is not in their own
    /// configuration; what makes them work with the floor stays either way.
    #[test]
    fn flags_leave_out_a_hook_the_agent_already_has() {
        let home = env::temp_dir().join(format!("nd7-flags-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let nd7 = home.join("nd7");

        let claude = claude_flags(&home, &nd7);
        assert!(claude.join(" ").contains("hook-prefix"));
        assert!(claude.contains(&"--append-system-prompt".to_owned()));
        let codex = codex_flags(&home, &nd7);
        assert!(codex.join(" ").contains("hook-prefix"));
        assert!(codex.contains(&"--dangerously-bypass-hook-trust".to_owned()));

        nd7_core::agent_config::install_claude(&home.join(".claude/settings.json"), &nd7).unwrap();
        nd7_core::agent_config::install_codex(&home.join(".codex/config.toml"), &nd7).unwrap();

        let claude = claude_flags(&home, &nd7);
        assert!(!claude.join(" ").contains("hook-prefix"));
        assert!(
            claude
                .join(" ")
                .contains(r#"{"sandbox":{"enabled":false}}"#)
        );
        // Installed, and `nd7 init` wrote the approval with it: no hook on the
        // command line, and no trust bypass either.
        let codex = codex_flags(&home, &nd7);
        assert!(!codex.join(" ").contains("hook-prefix"));
        assert!(!codex.contains(&"--dangerously-bypass-hook-trust".to_owned()));
        assert!(codex.join(" ").contains("developer_instructions="));
        assert!(codex.contains(&"danger-full-access".to_owned()));
        // The approval taken away again by hand: the bypass comes back.
        let config = home.join(".codex/config.toml");
        let edited = fs::read_to_string(&config)
            .unwrap()
            .replace("trusted_hash", "was_trusted_hash");
        fs::write(&config, edited).unwrap();
        let codex = codex_flags(&home, &nd7);
        assert!(!codex.join(" ").contains("hook-prefix"));
        assert!(codex.contains(&"--dangerously-bypass-hook-trust".to_owned()));

        fs::remove_dir_all(&home).unwrap();
    }
}
