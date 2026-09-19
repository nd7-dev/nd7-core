//! The session log writer: one append-only NDJSON file per session under
//! `$XDG_STATE_HOME/nd7/sessions/<session_id>/`.
//!
//! Each append happens under an advisory lock on `lock`, reads the chain head
//! from the `head` sidecar (`<seq> <hash>`), links the new frame to it via
//! `prev`, writes the sealed frame, then rewrites `head` atomically.
//!
//! `head` is never trusted on its own: every append also reads the log's last
//! frame and checks the two against each other. Two disagreements are benign
//! and repaired in place, because the log still says where the chain is: a
//! missing `head` on a log that has frames, and a `head` exactly one frame
//! behind a last frame that links to it (an append that died between writing
//! the frame and rewriting `head`). Both continue from the log's tail, and the
//! append rewrites `head` as usual. Every other disagreement -- `head` ahead of
//! the log, further behind it, or naming the last frame with a different hash
//! -- is damage this module will not paper over: `append` returns the matching
//! [`ChainError`], writes nothing and leaves both files untouched.
//!
//! `verify` walks the chain (see [`SessionLog::verify`]).

use std::{
    env,
    fmt::{self, Display},
    fs,
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

use crate::hook::{
    Event,
    event::{genesis_prev, hash_sealed_prefix, split_sealed},
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
    ///
    /// `head` and the log's last frame are read and compared on every append.
    /// A benign disagreement repairs itself (see the module docs); anything
    /// else returns a [`ChainError`] having written nothing.
    pub fn append(&mut self, mut event: Event) -> Result<()> {
        // Idempotent and cheap; the only place that may create the session.
        fs::create_dir_all(&self.dir)?;
        let lock_file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(self.lock_path())?;
        lock_file.lock()?;

        // Both reads happen under the exclusive lock, so no other appender can
        // move the tail between them.
        let head = self.read_head()?;
        let events_path = self.events_path();
        let last = match read_last_line(&events_path) {
            Ok(last) => last,
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                // The one InvalidData `read_last_line` produces: the file does
                // not end in a newline. Counting the complete frames costs a
                // full read, affordable here because the append fails anyway.
                let seq = fs::read(&events_path)?
                    .iter()
                    .filter(|&&b| b == b'\n')
                    .count() as u64;
                return Err(ChainError::TornTail { seq }.into());
            }
            Err(e) => return Err(e.into()),
        };
        let (seq, prev) = self.next_link(head, last.as_deref())?;
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
            return match self.read_head()? {
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

        // Nothing is copied out of `bytes` in this loop: `expected_prev` is the
        // previous line's hash, borrowed from the buffer, and the only String
        // built is the one the `Report` hands back.
        let genesis = genesis_prev(&self.session_id);
        let mut expected_prev: &str = &genesis;
        let mut frames = 0u64;
        for (i, line) in bytes[..bytes.len() - 1].split(|&b| b == b'\n').enumerate() {
            expected_prev = check_frame(i as u64, line, expected_prev)?;
            frames += 1;
        }
        let last_hash = expected_prev;

        let last_seq = frames - 1;
        match self.read_head()? {
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
                last_hash: Some(last_hash.to_owned()),
            }),
        }
    }

    /// Where the next frame links: its `seq` and its `prev`.
    ///
    /// `head` is a cache of the log's tail, and this is the only place that
    /// checks the cache is still right. Two disagreements are repaired, because
    /// in both the log itself is intact and `head` is merely behind it; every
    /// other one is damage, and is refused so that nothing is appended on top
    /// of it. The caller rewrites `head` after the append either way, which is
    /// what makes a repair stick.
    fn next_link(
        &self,
        head: Option<Head>,
        last: Option<&[u8]>,
    ) -> std::result::Result<(u64, String), ChainError> {
        let Some(last) = last else {
            return match head {
                // A session with neither a log nor a head: start the chain.
                None => Ok((0, genesis_prev(&self.session_id))),
                // A head naming frames the log does not have. Not repairable:
                // the frames it describes are gone, and starting over would
                // hide that. Reported as truncation, as `verify` does.
                Some(head) => Err(ChainError::Truncated {
                    head_seq: head.seq,
                    last_seq: 0,
                }),
            };
        };

        // A last line that is not a sealed frame has no `seq` to report, so the
        // one from `head` is used when there is a head, and 0 otherwise. This
        // is the legacy case: a log written before the chain existed has no
        // hash member on any line and lands here on its next append.
        let hint = ChainError::Unsealed {
            seq: head.as_ref().map_or(0, |h| h.seq),
        };
        let (_, last_hash) = split_sealed(last).ok_or_else(|| hint.clone())?;
        let (last_seq, last_prev) = chain_fields(last).ok_or(hint)?;
        let next = |hash: &str| Ok((last_seq + 1, hash.to_owned()));

        match head {
            // REPAIR: frames but no head. The log is the authority for where
            // the chain is; the head this append writes restores the cache.
            None => next(last_hash),
            // The ordinary case: the cache agrees with the log.
            Some(head) if head.seq == last_seq && head.hash == last_hash => next(last_hash),
            // REPAIR: an append died between writing its frame and rewriting
            // `head`. The head names the frame before the last one, and the
            // last frame links to exactly that hash, so the chain is whole.
            Some(head) if last_seq.checked_sub(1) == Some(head.seq) && head.hash == last_prev => {
                next(last_hash)
            }
            Some(head) if head.seq < last_seq => Err(ChainError::HeadStale {
                head_seq: head.seq,
                last_seq,
            }),
            Some(head) if head.seq > last_seq => Err(ChainError::Truncated {
                head_seq: head.seq,
                last_seq,
            }),
            // Same seq, different hash: one of the two was rewritten.
            Some(_) => Err(ChainError::HeadMismatch { seq: last_seq }),
        }
    }

    /// The chain head, or `None` for a session with no `head` file yet. An
    /// unparseable head is a chain fault, not an I/O failure; either way it
    /// must fail loudly rather than restart the chain.
    fn read_head(&self) -> std::result::Result<Option<Head>, ChainError> {
        match fs::read_to_string(self.head_path()) {
            Ok(s) => s
                .parse()
                .map(Some)
                .map_err(|e: Box<dyn std::error::Error>| ChainError::HeadInvalid(e.to_string())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }
}

/// The last complete line of `path`, without its trailing newline.
///
/// Seeks to the end and reads backwards in 64 KiB chunks until it finds the
/// newline before the final one, so the cost is one frame rather than one log:
/// `append` must not grow with the session. `None` for a missing or empty file.
///
/// A non-empty file that does not end in a newline is a torn tail, and is the
/// only [`io::ErrorKind::InvalidData`] this returns; the caller turns it into
/// [`ChainError::TornTail`]. The `seq` is not computed here because it costs a
/// full read of the file.
fn read_last_line(path: &Path) -> io::Result<Option<Vec<u8>>> {
    const CHUNK: u64 = 64 * 1024;

    let mut file = match fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let len = file.seek(SeekFrom::End(0))?;
    if len == 0 {
        return Ok(None);
    }

    // `tail` always holds the bytes from `start` to the end of the file, and
    // always ends in the file's final newline once the first chunk is checked.
    let mut tail: Vec<u8> = Vec::new();
    let mut start = len;
    loop {
        let chunk_start = start.saturating_sub(CHUNK);
        let mut buf = vec![0u8; (start - chunk_start) as usize];
        file.seek(SeekFrom::Start(chunk_start))?;
        file.read_exact(&mut buf)?;
        buf.append(&mut tail);
        tail = buf;
        start = chunk_start;

        if !tail.ends_with(b"\n") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "log does not end in a newline",
            ));
        }
        // The newline before the last one bounds the final line; without one,
        // the whole file is a single line.
        let body = &tail[..tail.len() - 1];
        if let Some(i) = body.iter().rposition(|&b| b == b'\n') {
            return Ok(Some(body[i + 1..].to_vec()));
        }
        if start == 0 {
            return Ok(Some(body.to_vec()));
        }
    }
}

/// Check one frame in isolation. Pure: depends only on this line's bytes and
/// the hash the previous line claims for itself, so frames can be checked in
/// any order or in parallel. Returns this frame's embedded hash, which is the
/// `expected_prev` of the frame after it.
///
/// The checks run cheapest-first, and each one only means anything once the
/// ones before it passed: shape, then hash, then `seq`, then `prev`.
fn check_frame<'a>(
    seq: u64,
    line: &'a [u8],
    expected_prev: &str,
) -> std::result::Result<&'a str, ChainError> {
    let (prefix, embedded) = split_sealed(line).ok_or(ChainError::Unsealed { seq })?;
    if hash_sealed_prefix(prefix).to_hex().as_str() != embedded {
        return Err(ChainError::HashMismatch { seq });
    }
    // A sealed frame with a verified hash is byte-for-byte the writer's, and
    // the writer's layout is fixed, so the fields must be where `chain_fields`
    // looks. Not finding them there means this is not one of our frames.
    let (found, prev) = chain_fields(line).ok_or(ChainError::Unsealed { seq })?;
    if found != seq {
        return Err(ChainError::SeqGap {
            expected: seq,
            found,
        });
    }
    if prev != expected_prev {
        return Err(ChainError::PrevMismatch { seq });
    }
    Ok(embedded)
}

/// The two chain fields, read straight out of a frame's bytes, without a JSON
/// parse. `None` if either field is not where the writer puts it.
///
/// Why searching bytes is sound rather than a guess at the layout: JSON escapes
/// a `"` inside a string value as `\"`, so the byte sequences `,"seq":` and
/// `,"prev":"` cannot occur inside a value, and the first occurrence of each in
/// a line is therefore the envelope member of that name. Callers run this after
/// the hash check, so the bytes are already known to be exactly what the writer
/// produced -- a frame someone hand-edited into a different shape fails earlier,
/// not here.
fn chain_fields(line: &[u8]) -> Option<(u64, &str)> {
    const SEQ: &[u8] = br#","seq":"#;
    const PREV: &[u8] = br#","prev":""#;

    let at = find(line, SEQ)? + SEQ.len();
    let digits = &line[at..];
    let end = digits.iter().position(|&b| b == b',')?;
    let seq: u64 = std::str::from_utf8(&digits[..end]).ok()?.parse().ok()?;

    let at = find(line, PREV)? + PREV.len();
    let prev = line.get(at..at.checked_add(64)?)?;
    if !prev.iter().all(u8::is_ascii_hexdigit) || line.get(at + 64) != Some(&b'"') {
        return None;
    }
    // Hex digits, so this is ASCII and the conversion cannot fail.
    Some((seq, std::str::from_utf8(prev).ok()?))
}

/// Index of the first occurrence of `needle` in `haystack`. `needle` is always
/// a short constant here, so the naive scan is the right one.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
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
    /// member, or the chain fields are not where the writer puts them.
    /// Frames written before the chain existed land here too.
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
        time::Instant,
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
            let (prefix, embedded) =
                crate::hook::event::split_sealed(line.as_bytes()).expect("sealed");
            assert_eq!(
                crate::hook::event::hash_sealed_prefix(prefix)
                    .to_hex()
                    .as_str(),
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
        crate::hook::event::split_sealed(line.as_bytes())
            .unwrap()
            .1
            .to_owned()
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

    /// The `ChainError` an append refused with.
    fn refusal(e: Box<dyn std::error::Error>) -> ChainError {
        e.downcast_ref::<ChainError>()
            .unwrap_or_else(|| panic!("expected a ChainError, got {e}"))
            .clone()
    }

    /// Append onto `log` and assert the refusal left both files alone.
    fn assert_refuses(log: &mut SessionLog, id: &str, want: ChainError) {
        let events = fs::read(log.events_path()).unwrap();
        let head = fs::read(log.head_path()).unwrap();
        let err = log.append(event(id, "after")).unwrap_err();
        assert_eq!(refusal(err), want);
        assert_eq!(fs::read(log.events_path()).unwrap(), events, "log changed");
        assert_eq!(fs::read(log.head_path()).unwrap(), head, "head changed");
    }

    #[test]
    fn chain_fields_agrees_with_a_full_parse() {
        let root = TempRoot::new();
        let log = chain_of_three(&root, "fields");
        for line in lines_of(&log) {
            let (seq, prev) = chain_fields(line.as_bytes()).expect("fast path");
            let full: Event = serde_json::from_str(&line).unwrap();
            assert_eq!((seq, prev), (full.seq, full.prev.as_str()));
        }

        let hex = "ab".repeat(32);
        // Neither field, then each one missing on its own, then a `prev` that
        // is not 64 hex digits followed by a quote.
        assert!(chain_fields(br#"{"v":0}"#).is_none());
        assert!(chain_fields(format!(r#"{{"v":0,"prev":"{hex}"}}"#).as_bytes()).is_none());
        assert!(chain_fields(br#"{"v":0,"seq":1,"ts":2}"#).is_none());
        assert!(chain_fields(br#"{"v":0,"seq":1,"ts":2,"prev":"abc"}"#).is_none());
    }

    #[test]
    fn append_repairs_a_missing_head() {
        let root = TempRoot::new();
        let mut log = chain_of_three(&root, "headless");
        fs::remove_file(log.head_path()).unwrap();

        log.append(event("headless", "four")).unwrap();
        assert_eq!(read_seqs(&log.events_path()), vec![0, 1, 2, 3]);
        assert_eq!(head_of(&log).seq, 3);
        assert_eq!(log.verify().unwrap().frames, 4);
    }

    #[test]
    fn append_repairs_a_head_one_frame_behind() {
        let root = TempRoot::new();
        let mut log = chain_of_three(&root, "behind");
        // Exactly what a crash between the frame write and the head write
        // leaves: head names frame 1, the log ends at frame 2.
        let lines = lines_of(&log);
        fs::write(log.head_path(), format!("1 {}\n", hash_of(&lines[1]))).unwrap();

        log.append(event("behind", "four")).unwrap();
        assert_eq!(read_seqs(&log.events_path()), vec![0, 1, 2, 3]);
        assert_eq!(log.verify().unwrap().frames, 4);
    }

    #[test]
    fn append_refuses_a_head_two_frames_behind() {
        let root = TempRoot::new();
        let mut log = chain_of_three(&root, "far-behind");
        let lines = lines_of(&log);
        fs::write(log.head_path(), format!("0 {}\n", hash_of(&lines[0]))).unwrap();
        assert_refuses(
            &mut log,
            "far-behind",
            ChainError::HeadStale {
                head_seq: 0,
                last_seq: 2,
            },
        );
    }

    #[test]
    fn append_refuses_a_head_ahead_of_the_log() {
        let root = TempRoot::new();
        let mut log = chain_of_three(&root, "ahead");
        let lines = lines_of(&log);
        fs::write(log.head_path(), format!("5 {}\n", hash_of(&lines[2]))).unwrap();
        assert_refuses(
            &mut log,
            "ahead",
            ChainError::Truncated {
                head_seq: 5,
                last_seq: 2,
            },
        );
    }

    #[test]
    fn append_refuses_a_head_that_disagrees_on_the_hash() {
        let root = TempRoot::new();
        let mut log = chain_of_three(&root, "disagree");
        fs::write(log.head_path(), format!("2 {}\n", "0".repeat(64))).unwrap();
        assert_refuses(&mut log, "disagree", ChainError::HeadMismatch { seq: 2 });
    }

    #[test]
    fn append_refuses_a_torn_tail() {
        let root = TempRoot::new();
        let mut log = chain_of_three(&root, "torn-append");
        let mut bytes = fs::read(log.events_path()).unwrap();
        bytes.pop(); // the final newline
        fs::write(log.events_path(), bytes).unwrap();
        assert_refuses(&mut log, "torn-append", ChainError::TornTail { seq: 2 });
    }

    #[test]
    fn append_finds_a_last_line_longer_than_a_read_chunk() {
        let root = TempRoot::new();
        let mut log = SessionLog::open_in(&root.0, "chunky").unwrap();
        log.append(event("chunky", "small")).unwrap();
        // Last frame well past the 64 KiB the tail read takes at a time, so
        // finding its start needs several passes.
        log.append(event("chunky", &"x".repeat(200_000))).unwrap();
        fs::remove_file(log.head_path()).unwrap(); // force the repair path

        log.append(event("chunky", "after")).unwrap();
        assert_eq!(read_seqs(&log.events_path()), vec![0, 1, 2]);
        assert_eq!(log.verify().unwrap().frames, 3);
    }

    /// Not a correctness test: builds a synthetic 50_000-frame session and
    /// prints how long [`SessionLog::verify`] takes to walk it. Ignored by
    /// default because it writes ~75 MB. Run it with
    /// `cargo test --release -- --ignored bench_verify_50k --nocapture`.
    #[test]
    #[ignore = "benchmark: writes ~75 MB of synthetic log"]
    fn bench_verify_50k() {
        const FRAMES: u64 = 50_000;
        let root = TempRoot::new();
        let mut log = SessionLog::open_in(&root.0, "bench").unwrap();
        // ~1.5 KB per frame once the envelope and the body are around it.
        let filler = "x".repeat(1_135);
        let built = Instant::now();
        for i in 0..FRAMES {
            log.append(event("bench", &format!("{i} {filler}")))
                .unwrap();
        }
        let bytes = fs::metadata(log.events_path()).unwrap().len();
        println!(
            "built {FRAMES} frames, {bytes} bytes ({:.1} MiB), in {:?}",
            bytes as f64 / (1024.0 * 1024.0),
            built.elapsed()
        );
        // Three rounds: the first pays for a cold page cache.
        for round in 0..3 {
            let started = Instant::now();
            let report = log.verify().unwrap();
            let elapsed = started.elapsed();
            assert_eq!(report.frames, FRAMES);
            println!(
                "verify round {round}: {elapsed:?} ({:.0} MB/s)",
                bytes as f64 / 1e6 / elapsed.as_secs_f64()
            );
        }
    }

    #[test]
    fn opening_a_session_creates_nothing() {
        let root = TempRoot::new();
        let log = SessionLog::open_in(&root.0, "untouched").unwrap();
        assert!(!log.exists());
        assert!(!root.0.join("sessions").exists());
    }
}
