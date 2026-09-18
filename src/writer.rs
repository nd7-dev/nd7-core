//! The session log writer: one append-only NDJSON file per session under
//! `$XDG_STATE_HOME/nd7/sessions/<session_id>/`.
//!
//! Milestone M1: no lock, no hash chain yet. `seq` is the current line count.
//! M4 adds `flock` on `lock`, the `head` sidecar, and `prev`/`hash`.

use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};

use crate::hook::Event;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// An open session log. Owns everything that touches the session directory.
pub struct SessionLog {
    session_id: String,
    dir: PathBuf,
}

impl SessionLog {
    /// Resolve the session directory, creating it if needed.
    pub fn open(session_id: &str) -> Result<Self> {
        let dir = session_dir(session_id)?;
        fs::create_dir_all(&dir)?;
        Ok(Self {
            session_id: session_id.to_owned(),
            dir,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }
    pub fn events_path(&self) -> PathBuf {
        self.dir.join("events.ndjson")
    }

    pub fn lock_path(&self) -> PathBuf {
        self.dir.join("lock")
    }

    /// Assign `seq` and append the event as one NDJSON line.
    pub fn append(&mut self, mut event: Event) -> Result<()> {
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path())?;
        lock_file.lock()?;

        event.seq = existing_lines(&self.events_path())?;
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');

        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(&self.events_path())?;
        f.write_all(line.as_bytes())?;
        Ok(())
    }
}

fn existing_lines(path: &Path) -> io::Result<u64> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes.iter().filter(|&&b| b == b'\n').count() as u64),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e),
    }
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
