//! `nd7`: the flight recorder's command line.
//!
//! - `nd7 record`: read one Claude Code hook payload from stdin and append it
//!   to the session log as one sealed event. This is what the hooks call.
//! - `nd7 verify <session-id>`: walk that session's chain and report.
//! - `nd7 enroll <server> <token>`: bind this machine to a vault.
//! - `nd7 ship`: push unshipped frames to that vault.
//! - `nd7 run [--profile <file>] <program> [args...]`: run a program under a
//!   Seatbelt profile. macOS only.
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
                             the floor profile applied; --profile <file> applies that raw
                             profile instead, with no session";

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
            exit: exit_path(&home),
            home,
            grants: Vec::new(),
        };
        trusted(&policy.exit)?;
        let session = Session::create(&sessions_root(&policy.home), &policy)?;
        eprintln!(
            "nd7 run: session {} under nd7's policy; a sandbox the program applies itself is refused",
            std::process::id()
        );
        let status = nd7_core::sandbox::spawn_with_profile(&policy.render_floor(), program, &[])
            .args(args)
            .status()?;
        drop(session);
        Ok(status)
    }

    /// Where `nd7-exec` is installed. The floor lets exactly this path out.
    fn exit_path(home: &std::path::Path) -> PathBuf {
        #[cfg(feature = "test-seams")]
        if let Some(p) = env::var_os("ND7_EXIT") {
            return PathBuf::from(p);
        }
        home.join(".nd7/bin/nd7-exec")
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
