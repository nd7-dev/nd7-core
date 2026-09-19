//! The honest concurrency test: many `nd7 record` processes appending to one
//! session at the same time, the way Claude Code fires hooks for parallel tool
//! calls. Exercises the real `flock` across process boundaries.

use std::{
    collections::BTreeSet,
    env, fs,
    io::Write,
    path::PathBuf,
    process::{Command, Stdio},
};

fn payload(i: usize) -> String {
    format!(
        r#"{{"session_id":"procs","transcript_path":"/t","cwd":"/p",
            "hook_event_name":"UserPromptSubmit","prompt":"{i}"}}"#
    )
}

#[test]
fn parallel_hook_processes_get_dense_unique_seqs() {
    const N: usize = 40;
    let root: PathBuf = env::temp_dir().join(format!("nd7-procs-test-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();

    // Spawn all first so they overlap, then feed stdin and wait.
    let mut children: Vec<_> = (0..N)
        .map(|_| {
            Command::new(env!("CARGO_BIN_EXE_nd7"))
                .arg("record")
                .env("XDG_STATE_HOME", &root)
                .stdin(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect();
    for (i, child) in children.iter_mut().enumerate() {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(payload(i).as_bytes())
            .unwrap();
    }
    for child in children {
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "hook failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let log = fs::read_to_string(root.join("nd7/sessions/procs/events.ndjson")).unwrap();
    let seqs: Vec<u64> = log
        .lines()
        .map(|l| {
            serde_json::from_str::<serde_json::Value>(l).unwrap()["seq"]
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(seqs.len(), N, "every process appended exactly one frame");
    let unique: BTreeSet<u64> = seqs.iter().copied().collect();
    assert_eq!(unique.len(), N, "no duplicate seq");
    assert_eq!(
        unique.iter().copied().collect::<Vec<_>>(),
        (0..N as u64).collect::<Vec<_>>(),
        "dense 0..N"
    );

    let _ = fs::remove_dir_all(&root);
}
