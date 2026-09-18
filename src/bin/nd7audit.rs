//! `nd7audit hook`: read one Claude Code hook payload from stdin and append it
//! to the session log as an nd7 event. Plain blocking I/O; nothing here needs
//! a runtime.

use std::{
    fs,
    io::{self, Read, Write},
};

use nd7_core::hook;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    let ts = hook::now_ns();
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    let frame = hook::Frame::build(&raw, ts)?;

    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(frame.path)?;
    f.write_all(frame.line.as_bytes())?;
    Ok(())
}
