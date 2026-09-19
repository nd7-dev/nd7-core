//! The session log writer: one append-only NDJSON file per session under
//! `$XDG_STATE_HOME/nd7/sessions/<session_id>/`.
//!
//! Each append happens under an advisory lock on `lock`, reads the chain head
//! from the `head` sidecar (`<seq> <hash>`), links the new frame to it via
//! `prev`, writes the sealed frame, then rewrites `head` atomically.
//!
//! `verify` walks the chain (see [`SessionLog::verify`]). Still pending:
//! automatic repair of a stale `head` in `append`.

use std::{
    env,
    fmt::{self, Display},
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use serde::Deserialize;

use crate::hook::{
    Event,
    event::{genesis_prev, split_sealed},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// An open session log. Owns everything that touches the session directory.
pub struct SessionLog {
    session_id: String,
    dir: PathBuf,
}

impl SessionLog {
    /// Open the session under `$XDG_STATE_HOME/nd7` (default `~/.local/state/nd7`).
    pub fn open(session_id: &str) -> Result<Self> {
        Self::open_in(&state_root()?, session_id)
    }

    /// Open the session under an explicit nd7 state root, `<root>/sessions/<id>`.
    /// `open` is this with the XDG root; tests pass a temp dir.
    ///
    /// Opening creates nothing: a read-only command on a mistyped session id
    /// must not leave an empty session behind. [`SessionLog::append`] creates
    /// the directory when it first needs it.
    pub fn open_in(root: &Path, session_id: &str) -> Result<Self> {
        check_session_id(session_id)?;
        Ok(Self {
            session_id: session_id.to_owned(),
            dir: root.join("sessions").join(session_id),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Whether this session has a directory on disk yet.
    pub fn exists(&self) -> bool {
        self.dir.is_dir()
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
        // Idempotent and cheap; the only place that may create the session.
        fs::create_dir_all(&self.dir)?;
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

    /// Walk the log from the first frame and check the chain.
    ///
    /// For every line, in this order: it is a sealed frame (`split_sealed`),
    /// its embedded `hash` equals BLAKE3 of the bytes before the splice, its
    /// `seq` is the next expected one, and its `prev` equals the previous
    /// frame's hash (or `genesis_prev(session_id)` at seq 0). Then the tail is
    /// compared with `head`. Stops at the first failure. Takes a shared lock so
    /// a concurrent `append` cannot make the tail and `head` disagree mid-walk.
    ///
    /// An empty or missing log verifies with zero frames. What a clean result
    /// proves: the file is unchanged since its last frame was written, if
    /// `head` is trusted. It does not defend against someone who can write the
    /// directory; they can rewrite the whole chain. Callers print that caveat.
    pub fn verify(&self) -> std::result::Result<Report, ChainError> {
        if !self.exists() {
            let id = &self.session_id;
            return Err(ChainError::Io(format!("no such session: {id}")));
        }
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path())?;
        // Shared, not exclusive: readers never block each other, but no
        // `append` can land between reading the log and reading `head`. Without
        // this, a frame written in that gap makes a healthy log look truncated
        // or stale. The walk itself needs no lock; only the pair of reads does.
        lock_file.lock_shared()?;

        let bytes = match fs::read(self.events_path()) {
            Ok(b) => b,
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };

        // No frames at all. A `head` here describes frames that are not in the
        // file, which is the same damage as a truncated log, so it is reported
        // that way with `last_seq` 0 rather than as a missing head.
        if bytes.is_empty() {
            return match self.head_for_verify()? {
                None => Ok(Report {
                    frames: 0,
                    last_hash: None,
                }),
                Some(head) => Err(ChainError::Truncated {
                    head_seq: head.seq,
                    last_seq: 0,
                }),
            };
        }

        // Checked before the walk: a frame cut short still hashes cleanly,
        // since the hash never covered the trailing newline.
        if !bytes.ends_with(b"\n") {
            let complete = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
            return Err(ChainError::TornTail { seq: complete });
        }

        let mut expected_prev = genesis_prev(&self.session_id);
        let mut last_hash = String::new();
        let mut frames = 0u64;
        for (i, raw) in bytes[..bytes.len() - 1].split(|&b| b == b'\n').enumerate() {
            let seq = i as u64;
            let line = std::str::from_utf8(raw).map_err(|_| ChainError::Unsealed { seq })?;
            let (hashed, embedded) = split_sealed(line).ok_or(ChainError::Unsealed { seq })?;
            if blake3::hash(hashed.as_bytes()).to_hex().as_str() != embedded {
                return Err(ChainError::HashMismatch { seq });
            }
            // Only the two chain fields: a frame whose body no longer parses as
            // an `Event` (a newer schema, say) still has a checkable chain.
            let fields: ChainFields =
                serde_json::from_str(line).map_err(|_| ChainError::Unsealed { seq })?;
            if fields.seq != seq {
                return Err(ChainError::SeqGap {
                    expected: seq,
                    found: fields.seq,
                });
            }
            if fields.prev != expected_prev {
                return Err(ChainError::PrevMismatch { seq });
            }
            expected_prev = embedded.to_owned();
            last_hash = embedded.to_owned();
            frames += 1;
        }

        let last_seq = frames - 1;
        match self.head_for_verify()? {
            None => Err(ChainError::HeadMissing { last_seq }),
            Some(head) if head.seq < last_seq => Err(ChainError::HeadStale {
                head_seq: head.seq,
                last_seq,
            }),
            Some(head) if head.seq > last_seq => Err(ChainError::Truncated {
                head_seq: head.seq,
                last_seq,
            }),
            Some(head) if head.hash != last_hash => Err(ChainError::HeadMismatch { seq: last_seq }),
            Some(_) => Ok(Report {
                frames,
                last_hash: Some(last_hash),
            }),
        }
    }

    /// [`SessionLog::read_head`] with the errors `verify` reports: an
    /// unparseable head is a chain fault, not an I/O failure.
    fn head_for_verify(&self) -> std::result::Result<Option<Head>, ChainError> {
        match fs::read_to_string(self.head_path()) {
            Ok(s) => s
                .parse()
                .map(Some)
                .map_err(|e: Box<dyn std::error::Error>| ChainError::HeadInvalid(e.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
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

/// The two chain fields `verify` reads back out of a frame. Everything else in
/// the line is ignored, so an unknown body shape cannot fail the walk.
#[derive(Deserialize)]
struct ChainFields {
    seq: u64,
    prev: String,
}

/// Result of a clean [`SessionLog::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Number of frames checked. Zero for an empty or missing log.
    pub frames: u64,
    /// Hash of the last frame, which `head` also holds. `None` when empty.
    pub last_hash: Option<String>,
}

/// The first thing wrong with a session's chain, and where.
///
/// Every variant that concerns a frame carries its `seq` (its position in the
/// file, counted from 0), so a reader can say "intact up to N". Variants are
/// ordered from "the bytes changed" to "the bookkeeping disagrees"; later
/// checks are only meaningful once earlier ones pass, so `verify` stops at the
/// first failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The line at this position is not a sealed frame: no trailing `hash`
    /// member, or not valid UTF-8. Frames written before the chain existed
    /// land here too.
    Unsealed { seq: u64 },
    /// BLAKE3 of the frame's bytes does not match its embedded `hash`. The
    /// frame was modified after it was written.
    HashMismatch { seq: u64 },
    /// The frame's `seq` field is not the expected position. A frame was
    /// removed, inserted or reordered.
    SeqGap { expected: u64, found: u64 },
    /// The frame's `prev` is not the previous frame's hash (or the genesis
    /// value at seq 0). The frame was replaced, or the log belongs to another
    /// session.
    PrevMismatch { seq: u64 },
    /// The file does not end in a newline: the last write was cut short.
    TornTail { seq: u64 },
    /// `head` is missing although the log has frames.
    HeadMissing { last_seq: u64 },
    /// `head` could not be parsed.
    HeadInvalid(String),
    /// `head` names a frame before the last one. Benign: an append was
    /// interrupted between writing the frame and rewriting `head`.
    HeadStale { head_seq: u64, last_seq: u64 },
    /// `head` names a frame after the last one: frames were removed from the
    /// end of the log.
    Truncated { head_seq: u64, last_seq: u64 },
    /// `head` agrees on `seq` but not on `hash`.
    HeadMismatch { seq: u64 },
    /// Reading the directory failed for a reason other than the above.
    Io(String),
}

impl Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChainError::Unsealed { seq } => write!(f, "frame {seq} is not a sealed frame"),
            ChainError::HashMismatch { seq } => {
                write!(f, "frame {seq}: hash does not match its bytes")
            }
            ChainError::SeqGap { expected, found } => {
                write!(
                    f,
                    "expected seq {expected}, found {found}: a frame is missing or out of order"
                )
            }
            ChainError::PrevMismatch { seq } => {
                write!(f, "frame {seq}: prev does not match the previous frame")
            }
            ChainError::TornTail { seq } => write!(f, "frame {seq}: file ends mid-frame"),
            ChainError::HeadMissing { last_seq } => {
                write!(f, "head is missing; log ends at seq {last_seq}")
            }
            ChainError::HeadInvalid(why) => write!(f, "head is invalid: {why}"),
            ChainError::HeadStale { head_seq, last_seq } => {
                write!(
                    f,
                    "head is stale: names seq {head_seq}, log ends at seq {last_seq}"
                )
            }
            ChainError::Truncated { head_seq, last_seq } => {
                write!(
                    f,
                    "log truncated: head names seq {head_seq}, log ends at seq {last_seq}"
                )
            }
            ChainError::HeadMismatch { seq } => write!(f, "head hash does not match frame {seq}"),
            ChainError::Io(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<io::Error> for ChainError {
    fn from(e: io::Error) -> Self {
        ChainError::Io(e.to_string())
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
                assert_eq!(
                    frames[i].prev,
                    frames[i - 1].hash.clone().unwrap(),
                    "frame {i} prev"
                );
            }
        }
        let head: Head = fs::read_to_string(log.head_path())
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(head.seq, 2);
        assert_eq!(Some(head.hash), frames[2].hash);
    }

    #[test]
    fn head_parses_and_prints_round_trip() {
        let h = Head {
            seq: 41,
            hash: "ab".repeat(32),
        };
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

    /// A three-frame session, ready to be tampered with.
    fn chain_of_three(root: &TempRoot, id: &str) -> SessionLog {
        let mut log = SessionLog::open_in(&root.0, id).unwrap();
        for i in 0..3 {
            log.append(event(id, &format!("frame {i}"))).unwrap();
        }
        log
    }

    fn lines_of(log: &SessionLog) -> Vec<String> {
        fs::read_to_string(log.events_path())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_lines(log: &SessionLog, lines: &[String]) {
        let mut text = lines.join("\n");
        text.push('\n');
        fs::write(log.events_path(), text).unwrap();
    }

    fn head_of(log: &SessionLog) -> Head {
        fs::read_to_string(log.head_path())
            .unwrap()
            .parse()
            .unwrap()
    }

    /// The hash embedded in one line of the log.
    fn hash_of(line: &str) -> String {
        crate::hook::event::split_sealed(line).unwrap().1.to_owned()
    }

    #[test]
    fn verify_accepts_an_untouched_chain() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "ok");
        assert_eq!(
            log.verify().unwrap(),
            Report {
                frames: 3,
                last_hash: Some(head_of(&log).hash),
            }
        );
    }

    #[test]
    fn verify_catches_an_edit_inside_a_frame() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "edited");
        let mut lines = lines_of(&log);
        // Still valid JSON, and still the same length: only the bytes changed.
        lines[1] = lines[1].replace(r#""text":"frame 1""#, r#""text":"frame X""#);
        write_lines(&log, &lines);
        assert_eq!(log.verify(), Err(ChainError::HashMismatch { seq: 1 }));
    }

    #[test]
    fn verify_catches_a_deleted_frame() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "deleted");
        let mut lines = lines_of(&log);
        lines.remove(1);
        write_lines(&log, &lines);
        assert_eq!(
            log.verify(),
            Err(ChainError::SeqGap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn verify_catches_reordered_frames() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "swapped");
        let mut lines = lines_of(&log);
        lines.swap(1, 2);
        write_lines(&log, &lines);
        assert_eq!(
            log.verify(),
            Err(ChainError::SeqGap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn verify_catches_a_resealed_frame_with_a_forged_prev() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "forged");
        let mut lines = lines_of(&log);
        // The strongest forgery an attacker without the chain can manage: a
        // frame that hashes correctly but does not link to its predecessor.
        let mut frame: Event = serde_json::from_str(&lines[1]).unwrap();
        frame.hash = None;
        frame.prev = "0".repeat(64);
        lines[1] = frame.seal().0.trim_end().to_owned();
        write_lines(&log, &lines);
        assert_eq!(log.verify(), Err(ChainError::PrevMismatch { seq: 1 }));
    }

    #[test]
    fn verify_catches_a_log_cut_back_behind_its_head() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "cut");
        let mut lines = lines_of(&log);
        lines.pop();
        write_lines(&log, &lines);
        assert_eq!(
            log.verify(),
            Err(ChainError::Truncated {
                head_seq: 2,
                last_seq: 1
            })
        );
    }

    #[test]
    fn verify_reports_a_head_left_behind_by_an_interrupted_append() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "stale");
        let lines = lines_of(&log);
        fs::write(log.head_path(), format!("1 {}\n", hash_of(&lines[1]))).unwrap();
        assert_eq!(
            log.verify(),
            Err(ChainError::HeadStale {
                head_seq: 1,
                last_seq: 2
            })
        );
    }

    #[test]
    fn verify_reports_a_missing_invalid_or_disagreeing_head() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "head");

        fs::write(log.head_path(), format!("2 {}\n", "0".repeat(64))).unwrap();
        assert_eq!(log.verify(), Err(ChainError::HeadMismatch { seq: 2 }));

        fs::write(log.head_path(), "not a head\n").unwrap();
        assert!(matches!(log.verify(), Err(ChainError::HeadInvalid(_))));

        fs::remove_file(log.head_path()).unwrap();
        assert_eq!(log.verify(), Err(ChainError::HeadMissing { last_seq: 2 }));
    }

    #[test]
    fn verify_catches_a_frame_cut_short() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "torn");
        let mut bytes = fs::read(log.events_path()).unwrap();
        bytes.pop(); // the final newline
        fs::write(log.events_path(), bytes).unwrap();
        assert_eq!(log.verify(), Err(ChainError::TornTail { seq: 2 }));
    }

    #[test]
    fn verify_refuses_a_chain_copied_into_another_session() {
        let root = TempRoot::new();
        let a = chain_of_three(&root, "a");
        let dst = root.0.join("sessions/b");
        fs::create_dir_all(&dst).unwrap();
        for entry in fs::read_dir(a.dir).unwrap() {
            let entry = entry.unwrap();
            fs::copy(entry.path(), dst.join(entry.file_name())).unwrap();
        }
        let b = SessionLog::open_in(&root.0, "b").unwrap();
        assert_eq!(b.verify(), Err(ChainError::PrevMismatch { seq: 0 }));
    }

    #[test]
    fn verify_accepts_an_empty_session_but_not_a_missing_one() {
        let root = TempRoot::new();
        let empty = SessionLog::open_in(&root.0, "empty").unwrap();
        assert!(!empty.exists());
        assert!(matches!(empty.verify(), Err(ChainError::Io(_))));

        fs::create_dir_all(root.0.join("sessions/empty")).unwrap();
        assert_eq!(
            empty.verify().unwrap(),
            Report {
                frames: 0,
                last_hash: None
            }
        );
    }

    #[test]
    fn opening_a_session_creates_nothing() {
        let root = TempRoot::new();
        let log = SessionLog::open_in(&root.0, "untouched").unwrap();
        assert!(!log.exists());
        assert!(!root.0.join("sessions").exists());
    }
}
