//! Claude Code hook handling: payload types, the transform into nd7 events,
//! and building the frame that `nd7 hook` appends to the session log.
//!
//! - [`input`]: typed model of every Claude Code hook payload.
//! - [`event`]: the nd7 envelope and body, and the hook-to-event transform.
//! - [`Frame`]: one ready-to-append log line and where it goes.

pub mod event;
pub mod input;

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

pub use event::{Event, Recorded};
pub use input::HookInput;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// One serialized event and the log file it belongs to.
#[derive(Debug, Clone, PartialEq)]
pub struct Frame {
    /// `$XDG_STATE_HOME/nd7/sessions/<session_id>/events.ndjson`.
    pub path: PathBuf,
    /// The NDJSON line, newline included.
    pub line: String,
}

impl Frame {
    /// Turn a raw hook payload into the line to append.
    ///
    /// `ts` is the recorder's start time in Unix nanoseconds; take it before
    /// reading stdin so it marks when the hook fired, not when parsing ended.
    /// Creates the session directory if needed and assigns `seq` from the
    /// current line count (milestone M1: no lock, no hash chain yet).
    pub fn build(raw: &str, ts: i64) -> Result<Frame> {
        let value: serde_json::Value = serde_json::from_str(raw)?;
        let raw_map = value.as_object().cloned().unwrap_or_default();
        let input = HookInput::from_value(value)?;

        let rec = Recorded {
            ts,
            host: hostname(),
            // SAFETY: getppid has no preconditions and cannot fail.
            hook_ppid: Some(unsafe { libc::getppid() } as u32),
        };
        let mut event = Event::from_hook(input, raw_map, rec);

        let dir = session_dir(&event.session_id)?;
        fs::create_dir_all(&dir)?;
        let path = dir.join("events.ndjson");
        event.seq = existing_lines(&path)?;

        let mut line = serde_json::to_string(&event)?;
        line.push('\n');
        Ok(Frame { path, line })
    }
}

/// Unix epoch nanoseconds now.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

/// `$XDG_STATE_HOME/nd7/sessions/<session_id>`, default `~/.local/state`.
fn session_dir(session_id: &str) -> Result<PathBuf> {
    if session_id.is_empty()
        || session_id.contains(['/', '\\'])
        || session_id == "."
        || session_id == ".."
    {
        return Err(format!("refusing unsafe session_id {session_id:?}").into());
    }
    let state_home = env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .ok_or("neither XDG_STATE_HOME nor HOME is set")?;
    Ok(state_home.join("nd7").join("sessions").join(session_id))
}

fn existing_lines(path: &Path) -> io::Result<u64> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes.iter().filter(|&&b| b == b'\n').count() as u64),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for writes of its full length; gethostname
    // NUL-terminates within it on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if let Ok(s) = std::str::from_utf8(&buf[..end]) {
            return s.to_owned();
        }
    }
    "unknown".to_owned()
}
