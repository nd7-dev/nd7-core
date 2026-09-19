//! `nd7`: the flight recorder's command line.
//!
//! - `nd7 record`: read one Claude Code hook payload from stdin and append it
//!   to the session log as one sealed event. This is what the hooks call.
//!   Plain blocking I/O; nothing here needs a runtime.
//!
//! `verify`, `sessions` and `show` arrive with milestones M4 and M5.

use std::{
    env,
    io::{self, Read},
    process::ExitCode,
};

use nd7_core::{
    hook::{Event, HookInput, Invocation},
    session_log::SessionLog,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const USAGE: &str = "usage: nd7 <command>

commands:
  record    read a Claude Code hook payload from stdin, append it to the session log";

fn main() -> ExitCode {
    // Environment first: `ts` marks when the hook fired, not when parsing ended.
    let inv = Invocation::now();

    match env::args().nth(1).as_deref() {
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
