//! The clear index of a batch, and the linkage rule the vault applies to it
//! (VAULT.md §6, steps 3 and 4).
//!
//! The vault never has frame bytes, so it can check only that the index it
//! was handed is a dense, correctly linked run continuing the head it holds.
//! [`build_index`] is the machine's side of the same contract: it reads the
//! four index fields straight out of the frames it is about to encrypt.
//!
//! Both functions are pure, which is the point: the machine, the vault and
//! the admin's CLI all run them over the same values and must agree.

use crate::{
    hook::event::{genesis_prev, split_sealed},
    session_log::{ChainError, Head},
    vault::wire::IndexEntry,
};

/// Read the index out of a run of newline-terminated frames.
///
/// Byte search, no JSON parse: the index of a 1500-frame session is built
/// from the bytes that are already in memory on their way into the
/// compressor, and parsing them twice would be the expensive half of
/// shipping. The `hash` comes from [`split_sealed`], which cuts the fixed
/// width member off the end of the line; the other three are found by
/// searching for `,"seq":`, `,"prev":"` and `,"ts":`. A `"` inside a JSON
/// string is escaped as `\"`, so none of those byte sequences can occur
/// inside a value, and the envelope members come before `body`, so the first
/// occurrence of each is the envelope's.
///
/// That argument holds for frames the writer produced. Callers run
/// `verify_segment` over the same bytes first, which checks every frame's
/// hash against its bytes and so establishes exactly that; an index built
/// from unverified bytes is not trustworthy and must not be shipped.
///
/// [`ChainError::Unsealed`] carries the position of the offending line within
/// `frames`, counted from 0, rather than a `seq`: a line whose fields are not
/// where the writer puts them has no `seq` to report.
pub fn build_index(frames: &[u8]) -> Result<Vec<IndexEntry>, ChainError> {
    if frames.is_empty() {
        return Ok(Vec::new());
    }
    if !frames.ends_with(b"\n") {
        let complete = frames.iter().filter(|&&b| b == b'\n').count() as u64;
        return Err(ChainError::TornTail { seq: complete });
    }
    frames[..frames.len() - 1]
        .split(|&b| b == b'\n')
        .enumerate()
        .map(|(i, line)| entry(line).ok_or(ChainError::Unsealed { seq: i as u64 }))
        .collect()
}

/// One frame's index entry, or `None` if any of the four fields is not where
/// the writer puts it.
fn entry(line: &[u8]) -> Option<IndexEntry> {
    const SEQ: &[u8] = br#","seq":"#;
    const TS: &[u8] = br#","ts":"#;
    const PREV: &[u8] = br#","prev":""#;

    let (_, hash) = split_sealed(line)?;
    Some(IndexEntry {
        seq: number(line, SEQ)?.parse().ok()?,
        prev: hex64(line, PREV)?.to_owned(),
        hash: hash.to_owned(),
        ts: number(line, TS)?.parse().ok()?,
    })
}

/// The digits of a numeric envelope member: everything between `member` and
/// the `,` that ends it.
fn number<'a>(line: &'a [u8], member: &[u8]) -> Option<&'a str> {
    let at = find(line, member)? + member.len();
    let rest = &line[at..];
    let end = rest.iter().position(|&b| b == b',')?;
    std::str::from_utf8(&rest[..end]).ok()
}

/// The 64 hex digits of a hash-valued envelope member, checked to be hex and
/// to be closed by the quote the writer puts there.
fn hex64<'a>(line: &'a [u8], member: &[u8]) -> Option<&'a str> {
    let at = find(line, member)? + member.len();
    let value = line.get(at..at.checked_add(64)?)?;
    if !value.iter().all(u8::is_ascii_hexdigit) || line.get(at + 64) != Some(&b'"') {
        return None;
    }
    // Hex digits, so this is ASCII and the conversion cannot fail.
    std::str::from_utf8(value).ok()
}

/// Index of the first occurrence of `needle` in `haystack`. `needle` is
/// always a short constant here, so the naive scan is the right one.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// What is wrong with an index, and where. Small on purpose: the vault can
/// only see `seq` and `prev`, so these are the only two ways an index can be
/// wrong, plus the empty batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkageError {
    /// The `seq` at this point is not the expected one: the run does not
    /// continue the head, or it is not dense.
    Gap { expected: u64, found: u64 },
    /// The `prev` at this `seq` is not the hash it has to be: the head's, the
    /// genesis value, or the previous entry's.
    PrevMismatch { seq: u64 },
    /// The batch has no frames at all.
    Empty,
}

impl std::fmt::Display for LinkageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkageError::Gap { expected, found } => {
                write!(f, "expected seq {expected}, found {found}")
            }
            LinkageError::PrevMismatch { seq } => {
                write!(f, "frame {seq}: prev does not match the previous hash")
            }
            LinkageError::Empty => write!(f, "batch has no frames"),
        }
    }
}

impl std::error::Error for LinkageError {}

/// Check that `index` is a dense, correctly linked run following `after`, and
/// return the head it leaves behind.
///
/// This is steps 3 and 4 of `POST .../frames` in one function. Step 3 is the
/// first entry: its `seq` must be `after.seq + 1`, or 0 for a chain the vault
/// has not seen, and its `prev` must be `after.hash`, or
/// `BLAKE3(session_id)` at genesis. Step 4 is the rest: `seq` dense and each
/// `prev` equal to the previous entry's `hash`. A failure on the first entry
/// is the `409` of step 3 and a failure after it is the `422` of step 4, so
/// the caller tells them apart by whether the reported position is the first
/// one.
///
/// Nothing here says the hashes are the hashes of any bytes. The vault has no
/// bytes; that check happens on the machine before encrypting and on the
/// admin's side after decrypting.
pub fn verify_linkage(
    after: Option<&Head>,
    session_id: &str,
    index: &[IndexEntry],
) -> Result<Head, LinkageError> {
    let Some(first) = index.first() else {
        return Err(LinkageError::Empty);
    };

    let expected = after.map_or(0, |head| head.seq + 1);
    if first.seq != expected {
        return Err(LinkageError::Gap {
            expected,
            found: first.seq,
        });
    }
    let genesis;
    let expected_prev = match after {
        Some(head) => head.hash.as_str(),
        None => {
            genesis = genesis_prev(session_id);
            &genesis
        }
    };
    if first.prev != expected_prev {
        return Err(LinkageError::PrevMismatch { seq: first.seq });
    }

    for pair in index.windows(2) {
        let (previous, current) = (&pair[0], &pair[1]);
        let expected = previous.seq + 1;
        if current.seq != expected {
            return Err(LinkageError::Gap {
                expected,
                found: current.seq,
            });
        }
        if current.prev != previous.hash {
            return Err(LinkageError::PrevMismatch { seq: current.seq });
        }
    }

    let last = &index[index.len() - 1];
    Ok(Head {
        seq: last.seq,
        hash: last.hash.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        path::PathBuf,
        sync::atomic::{AtomicU32, Ordering},
    };

    use super::*;
    use crate::{
        hook::{Event, HookInput, Invocation},
        session_log::SessionLog,
    };

    /// A fresh directory under the OS temp dir, removed on drop.
    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> TempRoot {
            static N: AtomicU32 = AtomicU32::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = env::temp_dir().join(format!("nd7-index-test-{}-{n}", std::process::id()));
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

    /// A real session of `frames` frames, and the bytes the writer produced.
    fn recorded(root: &TempRoot, id: &str, frames: u64) -> Vec<u8> {
        let mut log = SessionLog::open_in(&root.0, id).unwrap();
        for i in 0..frames {
            log.append(event(id, &format!("frame {i}"))).unwrap();
        }
        fs::read(log.events_path()).unwrap()
    }

    #[test]
    fn build_index_agrees_with_a_full_parse_of_the_writers_frames() {
        let root = TempRoot::new();
        let bytes = recorded(&root, "idx", 3);
        let index = build_index(&bytes).unwrap();

        let parsed: Vec<Event> = std::str::from_utf8(&bytes)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(index.len(), 3);
        for (entry, frame) in index.iter().zip(&parsed) {
            assert_eq!(entry.seq, frame.seq);
            assert_eq!(entry.prev, frame.prev);
            assert_eq!(Some(entry.hash.as_str()), frame.hash.as_deref());
            assert_eq!(entry.ts, frame.ts);
        }
        assert_eq!(index[0].seq, 0);
        assert_eq!(index[0].prev, genesis_prev("idx"));
        assert_eq!(index[1].prev, index[0].hash);
    }

    #[test]
    fn build_index_refuses_an_empty_batch_gracefully_and_a_torn_one_loudly() {
        assert_eq!(build_index(b"").unwrap(), Vec::new());

        let root = TempRoot::new();
        let mut bytes = recorded(&root, "torn", 2);
        bytes.pop();
        assert_eq!(build_index(&bytes), Err(ChainError::TornTail { seq: 1 }));

        assert_eq!(
            build_index(b"{\"not\":\"a frame\"}\n"),
            Err(ChainError::Unsealed { seq: 0 })
        );
    }

    /// The index of a real three-frame session, for the linkage tests.
    fn index_of_three(root: &TempRoot, id: &str) -> Vec<IndexEntry> {
        build_index(&recorded(root, id, 3)).unwrap()
    }

    #[test]
    fn verify_linkage_accepts_a_good_run_from_genesis_and_from_a_head() {
        let root = TempRoot::new();
        let index = index_of_three(&root, "good");
        let head = verify_linkage(None, "good", &index).unwrap();
        assert_eq!(head.seq, 2);
        assert_eq!(head.hash, index[2].hash);

        // The same run split in two, the second half continuing the first.
        let first = verify_linkage(None, "good", &index[..1]).unwrap();
        assert_eq!(first.seq, 0);
        assert_eq!(
            verify_linkage(Some(&first), "good", &index[1..]).unwrap(),
            head
        );
    }

    #[test]
    fn verify_linkage_rejects_an_empty_batch() {
        assert_eq!(verify_linkage(None, "empty", &[]), Err(LinkageError::Empty));
    }

    #[test]
    fn verify_linkage_rejects_a_gap_at_the_start_and_in_the_middle() {
        let root = TempRoot::new();
        let index = index_of_three(&root, "gap");

        // Does not continue the head: step 3.
        assert_eq!(
            verify_linkage(None, "gap", &index[1..]),
            Err(LinkageError::Gap {
                expected: 0,
                found: 1
            })
        );
        let head = Head {
            seq: 0,
            hash: index[0].hash.clone(),
        };
        assert_eq!(
            verify_linkage(Some(&head), "gap", &index[2..]),
            Err(LinkageError::Gap {
                expected: 1,
                found: 2
            })
        );

        // Not dense within the batch: step 4.
        let sparse = vec![index[0].clone(), index[2].clone()];
        assert_eq!(
            verify_linkage(None, "gap", &sparse),
            Err(LinkageError::Gap {
                expected: 1,
                found: 2
            })
        );
    }

    #[test]
    fn verify_linkage_rejects_a_broken_prev_and_the_wrong_session() {
        let root = TempRoot::new();
        let index = index_of_three(&root, "prev");

        let mut forged = index.clone();
        forged[1].prev = "0".repeat(64);
        assert_eq!(
            verify_linkage(None, "prev", &forged),
            Err(LinkageError::PrevMismatch { seq: 1 })
        );

        // Genesis is BLAKE3 of the session id, so the same frames offered as
        // another session's do not link.
        assert_eq!(
            verify_linkage(None, "other", &index),
            Err(LinkageError::PrevMismatch { seq: 0 })
        );

        // A head with the right seq and the wrong hash.
        let wrong = Head {
            seq: 0,
            hash: "0".repeat(64),
        };
        assert_eq!(
            verify_linkage(Some(&wrong), "prev", &index[1..]),
            Err(LinkageError::PrevMismatch { seq: 1 })
        );
    }
}
