//! `nd7audit hook`: read one Claude Code hook payload from stdin and append it
//! to the session log as an nd7 event. Plain blocking I/O; nothing here needs
//! a runtime.

use std::io::{self, Read};

use nd7_core::{
    hook::{Event, HookInput, Invocation},
    writer::SessionLog,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    // Environment first: `ts` marks when the hook fired, not when parsing ended.
    let inv = Invocation::now();

    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    let input: HookInput = raw.parse()?;
    let event = Event::new(input, inv);
    SessionLog::open(&event.session_id)?.append(event)?;
    Ok(())
}
