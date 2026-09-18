//! `nd7audit hook`: read one Claude Code hook payload from stdin and append it
//! to the session log as an nd7 event. Plain blocking I/O; nothing here needs
//! a runtime.

use std::io::{self, Read};

use nd7_core::{
    hook::{HookInput, Recorder},
    writer::SessionLog,
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    // Environment first: `ts` marks when the hook fired, not when parsing ended.
    let recorder = Recorder::now();

    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    let input: HookInput = raw.parse()?;
    let event = recorder.event(input);
    SessionLog::open(&event.session_id)?.append(event)?;
    Ok(())
}
