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
    /// Open the session under `$XDG_STATE_HOME/nd7` (default `~/.local/state/nd7`),
    /// creating its directory if needed.
    pub fn open(session_id: &str) -> Result<Self> {
        Self::open_in(&state_root()?, session_id)
    }

    /// Open the session under an explicit nd7 state root, `<root>/sessions/<id>`.
    /// `open` is this with the XDG root; tests pass a temp dir.
    pub fn open_in(root: &Path, session_id: &str) -> Result<Self> {
        check_session_id(session_id)?;
        let dir = root.join("sessions").join(session_id);
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
            .open(self.events_path())?;
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

/// The session id is used verbatim as a directory name; refuse anything that
/// could escape `sessions/`.
fn check_session_id(session_id: &str) -> Result<()> {
    if session_id.is_empty()
        || session_id.contains(['/', '\\'])
        || session_id == "."
        || session_id == ".."
    {
        return Err(format!("refusing unsafe session_id {session_id:?}").into());
    }
    Ok(())
}

/// `$XDG_STATE_HOME/nd7`, default `~/.local/state/nd7`.
fn state_root() -> Result<PathBuf> {
    let state_home = env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
        .ok_or("neither XDG_STATE_HOME nor HOME is set")?;
    Ok(state_home.join("nd7"))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::BTreeSet,
        sync::atomic::{AtomicU32, Ordering},
        thread,
    };

    use super::*;
    use crate::hook::{HookInput, Recorder};

    /// A fresh directory under the OS temp dir, removed on drop.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> TempRoot {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = env::temp_dir().join(format!("nd7-writer-test-{}-{n}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            TempRoot(dir)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn event(session: &str, prompt: &str) -> Event {
        let raw = format!(
            r#"{{"session_id": "{session}", "transcript_path": "/t", "cwd": "/p",
                 "hook_event_name": "UserPromptSubmit", "prompt": "{prompt}"}}"#
        );
        let input: HookInput = raw.parse().unwrap();
        Recorder::new(1, "test".into(), 1).event(input)
    }

    fn read_seqs(path: &Path) -> Vec<u64> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str::<Event>(l).unwrap().seq)
            .collect()
    }

    #[test]
    fn append_assigns_dense_seq_and_creates_files() {
        let root = TempRoot::new();
        let mut log = SessionLog::open_in(&root.0, "s1").unwrap();
        log.append(event("s1", "one")).unwrap();
        log.append(event("s1", "two")).unwrap();

        assert_eq!(log.events_path(), root.0.join("sessions/s1/events.ndjson"));
        assert!(log.lock_path().exists());
        assert_eq!(read_seqs(&log.events_path()), vec![0, 1]);

        // A second handle on the same session continues the sequence.
        let mut again = SessionLog::open_in(&root.0, "s1").unwrap();
        again.append(event("s1", "three")).unwrap();
        assert_eq!(read_seqs(&log.events_path()), vec![0, 1, 2]);
    }

    #[test]
    fn sessions_do_not_share_a_sequence() {
        let root = TempRoot::new();
        let mut a = SessionLog::open_in(&root.0, "a").unwrap();
        let mut b = SessionLog::open_in(&root.0, "b").unwrap();
        a.append(event("a", "x")).unwrap();
        a.append(event("a", "y")).unwrap();
        b.append(event("b", "z")).unwrap();
        assert_eq!(read_seqs(&a.events_path()), vec![0, 1]);
        assert_eq!(read_seqs(&b.events_path()), vec![0]);
    }

    #[test]
    fn rejects_session_ids_that_escape_the_directory() {
        let root = TempRoot::new();
        for bad in ["", ".", "..", "a/b", "a\\b", "../etc"] {
            assert!(SessionLog::open_in(&root.0, bad).is_err(), "{bad:?}");
        }
        assert!(!root.0.join("sessions/../etc").exists());
    }

    #[test]
    fn concurrent_appends_from_threads_never_collide() {
        const THREADS: u64 = 16;
        const PER_THREAD: u64 = 8;
        let root = TempRoot::new();
        // Each thread opens its own handle, like separate hook processes would.
        let handles: Vec<_> = (0..THREADS)
            .map(|t| {
                let root = root.0.clone();
                thread::spawn(move || {
                    let mut log = SessionLog::open_in(&root, "par").unwrap();
                    for i in 0..PER_THREAD {
                        log.append(event("par", &format!("{t}-{i}"))).unwrap();
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }

        let seqs = read_seqs(&root.0.join("sessions/par/events.ndjson"));
        let total = THREADS * PER_THREAD;
        assert_eq!(seqs.len() as u64, total, "every append landed");
        let unique: BTreeSet<u64> = seqs.iter().copied().collect();
        assert_eq!(unique.len() as u64, total, "no duplicate seq");
        assert_eq!(*unique.first().unwrap(), 0);
        assert_eq!(*unique.last().unwrap(), total - 1, "no gaps");
    }
}
