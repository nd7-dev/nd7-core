//! `nd7`: the flight recorder's command line.
//!
//! - `nd7 record`: read one Claude Code hook payload from stdin and append it
//!   to the session log as one sealed event. This is what the hooks call.
//! - `nd7 verify <session-id>`: walk that session's chain and report.
//!
//! Plain blocking I/O; nothing here needs a runtime.
//!
//! `sessions` and `show` arrive with milestone M5.

use std::{
    env,
    io::{self, Read},
    process::ExitCode,
};

use nd7_core::{
    hook::{Event, HookInput, Invocation},
    session_log::{ChainError, Report, SessionLog},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage: nd7 <command>

commands:
  record                read a Claude Code hook payload from stdin, append it to the session log
  verify <session-id>   check that a session's chain is intact";

/// What a clean verify does and does not prove. Printed with every success so
/// nobody reads it as more than it is.
const CAVEAT: &str = "note: proves the log is unchanged since its last frame was written by this machine; anyone with write access could rewrite the whole chain.";

fn main() -> ExitCode {
    // Environment first: `ts` marks when the hook fired, not when parsing ended.
    let inv = Invocation::now();
    let mut args = env::args().skip(1);

    match args.next().as_deref() {
        // `hook` is the pre-rename spelling; accepted until the settings snippet
        // in the README has been out for a while.
        Some("record" | "hook") => {
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
