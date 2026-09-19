//! The published chain test vectors: five real frames from the writer, each
//! with the `seq`, `prev` and `hash` a verifier must find in it.
//!
//! `tests/vectors/chain.json` is committed data. It is never regenerated
//! during a test run, because nd7-vault and the browser viewer are checked
//! against these exact bytes (docs/VAULT.md section 6): changing them is a
//! deliberate commit, not a side effect of running the suite.
//! `regenerate_vectors`, ignored, is how the file was produced.

use std::{env, fs, path::PathBuf};

use serde::Deserialize;

use nd7_core::{
    hook::event::genesis_prev,
    session_log::{ChainError, Head, verify_segment},
};

/// The session the vectors were recorded under. Their genesis `prev` is
/// `genesis_prev` of this, so verifying them under any other session id fails
/// at frame 0.
const SESSION_ID: &str = "3f2d1c48-9b7a-4e51-8c6d-0a1b2c3d4e5f";

#[derive(Debug, Deserialize)]
struct Vectors {
    session_id: String,
    genesis_prev: String,
    frames: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    seq: u64,
    prev: String,
    hash: String,
    /// The frame exactly as the writer produced it, trailing newline included.
    frame: String,
}

fn vectors_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/chain.json")
}

fn vectors() -> Vectors {
    let text = fs::read_to_string(vectors_path()).unwrap();
    serde_json::from_str(&text).unwrap()
}

/// The given frames as one run of bytes, the way they sit in the log.
fn run<'a>(frames: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
    frames.into_iter().flat_map(str::bytes).collect()
}

/// Every published frame, in order.
fn all(v: &Vectors) -> Vec<u8> {
    run(v.frames.iter().map(|f| f.frame.as_str()))
}

/// The head a vector describes, for use as `after`.
fn head(f: &Vector) -> Head {
    Head {
        seq: f.seq,
        hash: f.hash.clone(),
    }
}

#[test]
fn verify_segment_accepts_the_published_frames() {
    let v = vectors();
    assert_eq!(v.session_id, SESSION_ID);
    assert_eq!(v.genesis_prev, genesis_prev(&v.session_id));
    assert_eq!(v.frames.len(), 5);

    // The frames say about themselves what the file says about them; this is
    // the promise the other implementations verify against.
    for (i, f) in v.frames.iter().enumerate() {
        let frame: serde_json::Value = serde_json::from_str(&f.frame).unwrap();
        assert_eq!(frame["seq"].as_u64(), Some(f.seq), "frame {i} seq");
        assert_eq!(
            frame["prev"].as_str(),
            Some(f.prev.as_str()),
            "frame {i} prev"
        );
        assert_eq!(
            frame["hash"].as_str(),
            Some(f.hash.as_str()),
            "frame {i} hash"
        );
        assert_eq!(f.seq, i as u64);
    }
    assert_eq!(v.frames[0].prev, v.genesis_prev);

    let last = v.frames.last().unwrap();
    assert_eq!(
        verify_segment(&v.session_id, None, &all(&v)),
        Ok(head(last))
    );
}

#[test]
fn verify_segment_continues_from_a_head_partway_through() {
    let v = vectors();
    let tail = run(v.frames[3..].iter().map(|f| f.frame.as_str()));
    assert_eq!(
        verify_segment(&v.session_id, Some(&head(&v.frames[2])), &tail),
        Ok(head(v.frames.last().unwrap()))
    );
}

#[test]
fn verify_segment_catches_a_flipped_byte() {
    let v = vectors();
    // Same length, still valid JSON, still a sealed frame: only the bytes the
    // hash covers changed.
    let edited = v.frames[2].frame.replace("cargo test", "cargo rest");
    assert_ne!(edited, v.frames[2].frame);
    let frames = run([
        &v.frames[0].frame[..],
        &v.frames[1].frame,
        &edited,
        &v.frames[3].frame,
        &v.frames[4].frame,
    ]);
    assert_eq!(
        verify_segment(&v.session_id, None, &frames),
        Err(ChainError::HashMismatch { seq: 2 })
    );
}

#[test]
fn verify_segment_catches_a_missing_frame() {
    let v = vectors();
    let frames = run([
        &v.frames[0].frame[..],
        &v.frames[1].frame,
        &v.frames[2].frame,
        &v.frames[4].frame,
    ]);
    assert_eq!(
        verify_segment(&v.session_id, None, &frames),
        Err(ChainError::SeqGap {
            expected: 3,
            found: 4
        })
    );
}

#[test]
fn verify_segment_refuses_the_frames_under_another_session() {
    let v = vectors();
    assert_eq!(
        verify_segment("7c0e5a91-2d34-4b8f-a1e2-9f8d7c6b5a40", None, &all(&v)),
        Err(ChainError::PrevMismatch { seq: 0 })
    );
}

/// How `tests/vectors/chain.json` was produced: five realistic hook payloads
/// recorded through the ordinary writer into a temp directory, then copied out
/// byte for byte. Ignored, so a test run never rewrites the committed file.
/// Regenerate deliberately, and commit the result, with
/// `cargo test --test vectors -- --ignored regenerate_vectors`.
#[test]
#[ignore = "rewrites the committed test vectors"]
fn regenerate_vectors() {
    use nd7_core::{
        hook::{Event, HookInput, Invocation},
        session_log::SessionLog,
    };

    let transcript = "/Users/dev/.claude/projects/-Users-dev-code-nd7-core/3f2d1c48.jsonl";
    let cwd = "/Users/dev/code/nd7-core";
    let payloads = [
        format!(
            r#"{{"session_id":"{SESSION_ID}","transcript_path":"{transcript}","cwd":"{cwd}",
                 "hook_event_name":"SessionStart","source":"startup","model":"claude-opus-5"}}"#
        ),
        format!(
            r#"{{"session_id":"{SESSION_ID}","transcript_path":"{transcript}","cwd":"{cwd}",
                 "permission_mode":"default","prompt_id":"550e8400-e29b-41d4-a716-446655440000",
                 "hook_event_name":"UserPromptSubmit","prompt":"Run the tests and tell me what breaks."}}"#
        ),
        format!(
            r#"{{"session_id":"{SESSION_ID}","transcript_path":"{transcript}","cwd":"{cwd}",
                 "permission_mode":"default","prompt_id":"550e8400-e29b-41d4-a716-446655440000",
                 "hook_event_name":"PreToolUse","tool_name":"Bash",
                 "tool_input":{{"command":"cargo test --quiet","description":"Run the test suite","timeout":120000}},
                 "tool_use_id":"toolu_01VpVectorBashCall"}}"#
        ),
        format!(
            r#"{{"session_id":"{SESSION_ID}","transcript_path":"{transcript}","cwd":"{cwd}",
                 "permission_mode":"default","prompt_id":"550e8400-e29b-41d4-a716-446655440000",
                 "hook_event_name":"PostToolUse","tool_name":"Bash",
                 "tool_input":{{"command":"cargo test --quiet","description":"Run the test suite","timeout":120000}},
                 "tool_response":{{"stdout":"running 24 tests\n........................\ntest result: ok. 24 passed; 0 failed\n","stderr":"","interrupted":false,"isImage":false}},
                 "tool_use_id":"toolu_01VpVectorBashCall","duration_ms":4187}}"#
        ),
        format!(
            r#"{{"session_id":"{SESSION_ID}","transcript_path":"{transcript}","cwd":"{cwd}",
                 "hook_event_name":"SessionEnd","reason":"prompt_input_exit"}}"#
        ),
    ];

    let root = env::temp_dir().join(format!("nd7-vectors-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let mut log = SessionLog::open_in(&root, SESSION_ID).unwrap();
    for (i, payload) in payloads.iter().enumerate() {
        let input: HookInput = payload.parse().unwrap();
        // Fixed, so the same payloads always produce the same frames.
        let inv = Invocation {
            ts: 1_758_240_000_000_000_000 + i as i64 * 1_000_000_000,
            host: "vectors.example".to_owned(),
            hook_ppid: 4242,
        };
        log.append(Event::new(input, inv)).unwrap();
    }
    let lines = fs::read_to_string(log.events_path()).unwrap();
    let _ = fs::remove_dir_all(&root);

    let frames: Vec<serde_json::Value> = lines
        .lines()
        .map(|line| {
            let frame: serde_json::Value = serde_json::from_str(line).unwrap();
            serde_json::json!({
                "seq": frame["seq"],
                "prev": frame["prev"],
                "hash": frame["hash"],
                "frame": format!("{line}\n"),
            })
        })
        .collect();
    let doc = serde_json::json!({
        "session_id": SESSION_ID,
        "genesis_prev": genesis_prev(SESSION_ID),
        "frames": frames,
    });

    let path = vectors_path();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&doc).unwrap()),
    )
    .unwrap();
    println!("wrote {}", path.display());
}
