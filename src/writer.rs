//! The session log writer: one append-only NDJSON file per session under
//! `$XDG_STATE_HOME/nd7/sessions/<session_id>/`.
//!
//! Each append happens under an advisory lock on `lock`, reads the chain head
//! from the `head` sidecar (`<seq> <hash>`), links the new frame to it via
//! `prev`, writes the sealed frame, then rewrites `head` atomically.
//!
//! Still pending: repair of a `head` that is missing or stale on an existing
//! log, and `verify`.

use std::{
    env,
    fmt::{self, Display},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::hook::{Event, event::genesis_prev};

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

    pub fn head_path(&self) -> PathBuf {
        self.dir.join("head")
    }

    /// Link the event to the chain, assign `seq`, and append it as one
    /// sealed NDJSON line.
    pub fn append(&mut self, mut event: Event) -> Result<()> {
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path())?;
        lock_file.lock()?;

        let (seq, prev) = match self.read_head()? {
            Some(head) => (head.seq + 1, head.hash),
            None => (0, genesis_prev(&self.session_id)),
        };
        event.seq = seq;
        event.prev = prev;
        let (line, hash) = event.seal();

        let mut f = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.events_path())?;
        f.write_all(line.as_bytes())?;

        // Head last, and atomically. A crash before this point leaves head one
        // behind the log, which a later append can detect and repair; a torn
        // head could not be told apart from a corrupt one.
        let tmp = self.dir.join("head.tmp");
        fs::write(&tmp, format!("{}\n", Head { seq, hash }))?;
        fs::rename(&tmp, self.head_path())?;
        Ok(())
    }

    /// The chain head, or `None` for a session with no `head` file yet. Any
    /// other problem propagates: an unreadable head on an existing log must
    /// fail loudly, not restart the chain.
    fn read_head(&self) -> Result<Option<Head>> {
        match fs::read_to_string(self.head_path()) {
            Ok(s) => Ok(Some(s.parse()?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// Contents of the `head` sidecar: the last frame's `seq` and `hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub hash: String,
}

impl FromStr for Head {
    type Err = Box<dyn std::error::Error>;

    fn from_str(s: &str) -> Result<Head> {
        let (seq, hash) = s
            .trim_end()
            .split_once(' ')
            .ok_or("head: expected `<seq> <hash>`")?;
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("head: hash is not 64 hex characters".into());
        }
        Ok(Head {
            seq: seq.parse()?,
            hash: hash.to_owned(),
        })
    }
}

impl Display for Head {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.seq, self.hash)
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
    use crate::hook::{HookInput, Invocation};

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
        Event::new(
            input,
            Invocation {
                ts: 1,
                host: "test".into(),
                hook_ppid: 1,
            },
        )
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
    fn frames_form_a_chain_anchored_to_the_session() {
        let root = TempRoot::new();
        let mut log = SessionLog::open_in(&root.0, "chain").unwrap();
        for i in 0..3 {
            log.append(event("chain", &i.to_string())).unwrap();
        }
        let text = fs::read_to_string(log.events_path()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let frames: Vec<Event> = lines
            .iter()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();

        assert_eq!(frames[0].prev, genesis_prev("chain"));
        for (i, line) in lines.iter().enumerate() {
            let (hashed, embedded) = crate::hook::event::split_sealed(line).expect("sealed");
            assert_eq!(
                blake3::hash(hashed.as_bytes()).to_hex().to_string(),
                embedded,
                "frame {i} hash"
            );
            assert_eq!(frames[i].hash.as_deref(), Some(embedded));
            if i > 0 {
                assert_eq!(frames[i].prev, frames[i - 1].hash.clone().unwrap(), "frame {i} prev");
            }
        }
        let head: Head = fs::read_to_string(log.head_path()).unwrap().parse().unwrap();
        assert_eq!(head.seq, 2);
        assert_eq!(Some(head.hash), frames[2].hash);
    }

    #[test]
    fn head_parses_and_prints_round_trip() {
        let h = Head { seq: 41, hash: "ab".repeat(32) };
        assert_eq!(format!("{h}").parse::<Head>().unwrap(), h);
        assert!("41".parse::<Head>().is_err());
        assert!("41 nothex".parse::<Head>().is_err());
        assert!("x 00".parse::<Head>().is_err());
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
