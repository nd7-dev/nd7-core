//! The machine side of the vault protocol against a fake vault on loopback:
//! the acceptance tests of docs/VAULT.md §10 that need no real server.
//!
//! The vault here is a few hundred lines of hand-written HTTP/1.1 over
//! `std::net::TcpListener` with the chains in memory. It is deliberately not
//! a mock: it verifies every request signature with
//! `vault::crypto::verify_request`, checks the body hash, and runs
//! `vault::index::verify_linkage` over each batch, so a machine that signs
//! the wrong bytes or ships a batch that does not continue the chain fails
//! here exactly as it would against `nd7-vault`.
//!
//! The admin key is a fixed seed, so the tests can unwrap the chain keys and
//! read back what was stored.

use std::{
    collections::BTreeMap,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Mutex, MutexGuard},
    thread,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use nd7_core::{
    hook::event::genesis_prev,
    session_log::Head,
    vault::{
        AdminKey, BatchAad, LinkageError, RecipientSet, SealedBatch, SignedRecipientSet,
        open_batch, verify_linkage, verify_request,
        wire::{
            ConflictResponse, EnrollRequest, EnrollResponse, FramesAck, FramesRequest,
            RejectResponse,
        },
    },
};

/// The admin the tests are. Fixed, so the chain keys can be unwrapped.
const ADMIN_SEED: [u8; 32] = [7u8; 32];
/// Someone whose signature no machine has ever pinned (§10 test 12).
const STRANGER_SEED: [u8; 32] = [9u8; 32];

// -------------------------------------------------------------------------
// The fake vault
// -------------------------------------------------------------------------

/// One `frames` request as it arrived: path, headers, body.
type Captured = (String, Vec<(String, String)>, Vec<u8>);

/// One chain, as the vault holds it: ciphertext it cannot read, the clear
/// index inside each batch, the wraps, and the head.
#[derive(Default)]
struct Chain {
    head: Option<Head>,
    batches: Vec<FramesRequest>,
    wraps: BTreeMap<String, String>,
}

struct State {
    /// What `GET /v1/recipients` hands out. A test can swap it.
    recipients: SignedRecipientSet,
    machines: BTreeMap<String, [u8; 32]>,
    chains: BTreeMap<(String, String), Chain>,
    /// Every `frames` request as it arrived, for the replay test.
    requests: Vec<Captured>,
    conflicts: u32,
}

struct Vault {
    port: u16,
    state: Arc<Mutex<State>>,
    admin: AdminKey,
    /// `<fingerprint>.<secret>`, as an admin would print it (§4.2).
    token: String,
}

impl Vault {
    fn start() -> Vault {
        let admin = AdminKey::from_seed(&ADMIN_SEED);
        let set = RecipientSet {
            admins: vec![admin.public()],
            version: 1,
        };
        let token = format!("{}.opensesame", set.fingerprint());
        let state = Arc::new(Mutex::new(State {
            recipients: SignedRecipientSet::sign(set, &admin),
            machines: BTreeMap::new(),
            chains: BTreeMap::new(),
            requests: Vec::new(),
            conflicts: 0,
        }));

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let served = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let state = Arc::clone(&served);
                thread::spawn(move || {
                    let _ = handle(&mut stream, &state);
                });
            }
        });

        Vault {
            port,
            state,
            admin,
            token,
        }
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap()
    }

    /// The head the vault holds for a session, whatever host shipped it.
    fn head(&self, session_id: &str) -> Option<Head> {
        let state = self.state();
        let (_, chain) = state.chains.iter().find(|((id, _), _)| id == session_id)?;
        chain.head.clone()
    }

    fn batches(&self, session_id: &str) -> Vec<FramesRequest> {
        let state = self.state();
        match state.chains.iter().find(|((id, _), _)| id == session_id) {
            Some((_, chain)) => chain.batches.clone(),
            None => Vec::new(),
        }
    }

    /// What an admin gets out of the vault: every batch of a chain
    /// decrypted with the unwrapped chain key and concatenated, in order.
    fn plaintext(&self, session_id: &str) -> Vec<u8> {
        let state = self.state();
        let ((_, host), chain) = state
            .chains
            .iter()
            .find(|((id, _), _)| id == session_id)
            .expect("the vault holds this chain");
        let wrapped = chain
            .wraps
            .get(&self.admin.public().fingerprint())
            .expect("the chain key is wrapped to this admin");
        let key = self.admin.unwrap(wrapped).unwrap();

        let mut out = Vec::new();
        for batch in &chain.batches {
            let aad = BatchAad {
                session_id: session_id.to_owned(),
                host: host.clone(),
                first_seq: batch.first_seq,
                last_seq: batch.last_seq,
            };
            let sealed = SealedBatch {
                nonce: B64.decode(&batch.nonce).unwrap().try_into().unwrap(),
                ciphertext: B64.decode(&batch.ciphertext).unwrap(),
            };
            out.extend(open_batch(&key, &aad, &sealed).unwrap());
        }
        out
    }
}

/// Read one request, answer it, close. No keep-alive: the answer says so.
fn handle(stream: &mut TcpStream, state: &Mutex<State>) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut start = String::new();
    if reader.read_line(&mut start)? == 0 {
        return Ok(());
    }
    let mut words = start.split_whitespace();
    let method = words.next().unwrap_or_default().to_owned();
    let path = words.next().unwrap_or_default().to_owned();

    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_lowercase(), value.trim().to_owned()));
        }
    }
    let length: usize = header(&headers, "content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; length];
    reader.read_exact(&mut body)?;

    let (status, answer) = route(state, &method, &path, &headers, &body);
    write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        answer.len()
    )?;
    stream.write_all(&answer)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn json<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

/// The four endpoints of §6, in the order the spec lists their checks.
fn route(
    state: &Mutex<State>,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut state = state.lock().unwrap();

    // `enroll` is the one unsigned endpoint: the machine has no key yet.
    if (method, path) == ("POST", "/v1/enroll") {
        let request: EnrollRequest = serde_json::from_slice(body).unwrap();
        let public_key: [u8; 32] = B64.decode(&request.public_key).unwrap().try_into().unwrap();
        let machine_id = format!("machine-{}", state.machines.len() + 1);
        state.machines.insert(machine_id.clone(), public_key);
        let answer = EnrollResponse {
            machine_id,
            recipients: state.recipients.clone(),
        };
        return (201, json(&answer));
    }

    // Step 1 and step 2: the signature, then the body hash (§6).
    if !signed(&state, method, path, headers, body) {
        return (401, json(&serde_json::json!({"error": "bad signature"})));
    }

    let parts: Vec<&str> = path.split('/').filter(|p| !p.is_empty()).collect();
    match (method, parts.as_slice()) {
        ("GET", ["v1", "recipients"]) => (200, json(&state.recipients)),
        ("GET", ["v1", "chains", session_id, host, "head"]) => {
            let key = ((*session_id).to_owned(), (*host).to_owned());
            match state.chains.get(&key).and_then(|c| c.head.clone()) {
                Some(head) => (200, json(&head)),
                None => (404, json(&serde_json::json!({"error": "no such chain"}))),
            }
        }
        ("POST", ["v1", "chains", session_id, host, "frames"]) => {
            let (session_id, host) = ((*session_id).to_owned(), (*host).to_owned());
            frames(&mut state, &session_id, &host, path, headers, body)
        }
        _ => (404, json(&serde_json::json!({"error": "no such endpoint"}))),
    }
}

fn signed(
    state: &State,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> bool {
    let (Some(machine_id), Some(timestamp), Some(body_hash), Some(signature)) = (
        header(headers, "x-nd7-machine"),
        header(headers, "x-nd7-timestamp"),
        header(headers, "x-nd7-body"),
        header(headers, "x-nd7-signature"),
    ) else {
        return false;
    };
    let (Some(public_key), Ok(timestamp)) =
        (state.machines.get(machine_id), timestamp.parse::<i64>())
    else {
        return false;
    };
    if body_hash != blake3::hash(body).to_hex().as_str() {
        return false;
    }
    verify_request(
        public_key, method, path, machine_id, timestamp, body_hash, signature,
    )
}

/// `POST .../frames`, steps 3 to 5 of §6 and the idempotency rule under them.
fn frames(
    state: &mut State,
    session_id: &str,
    host: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    state
        .requests
        .push((path.to_owned(), headers.to_vec(), body.to_vec()));
    let Ok(request) = serde_json::from_slice::<FramesRequest>(body) else {
        return (400, json(&serde_json::json!({"error": "not a batch"})));
    };
    let admins: Vec<String> = state
        .recipients
        .set
        .admins
        .iter()
        .map(|admin| admin.fingerprint())
        .collect();

    let chain = state
        .chains
        .entry((session_id.to_owned(), host.to_owned()))
        .or_default();
    let answer = match chain.head.clone() {
        // At or before the head: identical means already stored, anything
        // else is a machine whose log was rewritten after shipping.
        Some(head) if request.first_seq <= head.seq => {
            if chain.batches.iter().any(|b| b.index == request.index) {
                (
                    200,
                    json(&FramesAck {
                        acked_seq: head.seq,
                    }),
                )
            } else {
                (
                    409,
                    json(&ConflictResponse {
                        expected_seq: head.seq + 1,
                        head_hash: head.hash,
                    }),
                )
            }
        }
        // An unseen chain must carry a wrap for every current admin.
        None if request
            .wraps
            .as_ref()
            .is_none_or(|w| admins.iter().any(|fp| !w.contains_key(fp))) =>
        {
            (
                409,
                json(&ConflictResponse {
                    expected_seq: 0,
                    head_hash: genesis_prev(session_id),
                }),
            )
        }
        _ => store(chain, session_id, request),
    };
    if answer.0 == 409 {
        state.conflicts += 1;
    }
    answer
}

/// Steps 3, 4 and 5: linkage, then store. A break at the first entry is the
/// `409` of step 3, one after it the `422` of step 4.
fn store(chain: &mut Chain, session_id: &str, request: FramesRequest) -> (u16, Vec<u8>) {
    match verify_linkage(chain.head.as_ref(), session_id, &request.index) {
        Ok(head) => {
            let acked_seq = head.seq;
            chain.head = Some(head);
            if let Some(wraps) = &request.wraps {
                chain.wraps.extend(wraps.clone());
            }
            chain.batches.push(request);
            (200, json(&FramesAck { acked_seq }))
        }
        Err(e) => {
            let at = match e {
                LinkageError::Gap { found, .. } => Some(found),
                LinkageError::PrevMismatch { seq } => Some(seq),
                LinkageError::Empty => None,
            };
            match at.filter(|seq| Some(*seq) != request.index.first().map(|e| e.seq)) {
                Some(seq) => (
                    422,
                    json(&RejectResponse {
                        seq,
                        error: e.to_string(),
                    }),
                ),
                None => (
                    409,
                    json(&ConflictResponse {
                        expected_seq: chain.head.as_ref().map_or(0, |head| head.seq + 1),
                        head_hash: chain
                            .head
                            .as_ref()
                            .map_or_else(|| genesis_prev(session_id), |head| head.hash.clone()),
                    }),
                ),
            }
        }
    }
}

/// Send one request verbatim, bypassing the client: the replay test (§10
/// test 8) has to reuse headers that were signed a moment ago.
fn replay(port: u16, path: &str, headers: &[(String, String)], body: &[u8]) -> u16 {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    write!(stream, "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n").unwrap();
    for (name, value) in headers {
        if name.starts_with("x-nd7-") || name == "content-type" {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
    }
    write!(stream, "Content-Length: {}\r\n\r\n", body.len()).unwrap();
    stream.write_all(body).unwrap();

    let mut answer = String::new();
    BufReader::new(stream).read_line(&mut answer).unwrap();
    answer
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()
        .expect("a status line")
}

// -------------------------------------------------------------------------
// Driving the real binary
// -------------------------------------------------------------------------

/// A fresh `XDG_STATE_HOME`, removed on drop.
struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> TempRoot {
        let dir = std::env::temp_dir().join(format!("nd7-ship-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        TempRoot(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn session(&self, session_id: &str) -> PathBuf {
        self.0.join("nd7/sessions").join(session_id)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn nd7(root: &TempRoot, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nd7"))
        .args(args)
        .env("XDG_STATE_HOME", root.path())
        .output()
        .unwrap()
}

/// One frame through the real recorder, from a synthetic hook payload.
fn record(root: &TempRoot, session_id: &str, i: u64) {
    let payload = format!(
        r#"{{"session_id":"{session_id}","transcript_path":"/t","cwd":"/p",
             "hook_event_name":"UserPromptSubmit","prompt":"frame {i}"}}"#
    );
    feed(root, &payload);
}

fn feed(root: &TempRoot, payload: &str) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_nd7"))
        .arg("record")
        .env("XDG_STATE_HOME", root.path())
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(payload.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success() && out.stderr.is_empty(),
        "record failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A `session_end` frame, the one that closes a chain (§7).
fn record_session_end(root: &TempRoot, session_id: &str) {
    let payload = format!(
        r#"{{"session_id":"{session_id}","transcript_path":"/t","cwd":"/p",
             "hook_event_name":"SessionEnd","reason":"logout"}}"#
    );
    feed(root, &payload);
}

fn record_many(root: &TempRoot, session_id: &str, range: std::ops::Range<u64>) {
    for i in range {
        record(root, session_id, i);
    }
}

fn enroll(root: &TempRoot, vault: &Vault) {
    let out = nd7(root, &["enroll", &vault.url(), &vault.token]);
    assert!(
        out.status.success(),
        "enroll failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn local_head(root: &TempRoot, session_id: &str) -> Head {
    fs::read_to_string(root.session(session_id).join("head"))
        .unwrap()
        .parse()
        .unwrap()
}

fn frames_file(root: &TempRoot, session_id: &str) -> Vec<u8> {
    fs::read(root.session(session_id).join("events.ndjson")).unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Rewrite one frame's bytes, the way someone covering their tracks would.
fn tamper(root: &TempRoot, session_id: &str, seq: u64) {
    let path = root.session(session_id).join("events.ndjson");
    let log = fs::read_to_string(&path).unwrap();
    let rewritten: Vec<String> = log
        .lines()
        .map(|line| {
            if line.contains(&format!(r#","seq":{seq},"#)) {
                line.replace(&format!("frame {seq}"), "frame ..")
            } else {
                line.to_owned()
            }
        })
        .collect();
    fs::write(&path, rewritten.join("\n") + "\n").unwrap();
}

// -------------------------------------------------------------------------
// The tests (docs/VAULT.md §10)
// -------------------------------------------------------------------------

/// §10 test 1: a vault whose recipient set does not match the fingerprint in
/// the token is refused, and nothing at all is stored locally.
#[test]
fn enroll_refuses_a_recipient_set_the_token_does_not_pin() {
    let vault = Vault::start();
    let root = TempRoot::new("fingerprint");

    let out = nd7(
        &root,
        &[
            "enroll",
            &vault.url(),
            &format!("{}.secret", "ab".repeat(32)),
        ],
    );
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("the token pins"), "{}", stderr(&out));
    assert!(
        !root.path().join("nd7/vault").exists(),
        "a refused enrolment writes nothing"
    );

    // The right token still works, against the same vault, and everything
    // it stores is readable by nobody else (§4.4).
    enroll(&root, &vault);
    assert_eq!(
        fs::read(root.path().join("nd7/vault/machine.key"))
            .unwrap()
            .len(),
        32
    );
    for name in ["machine.key", "machine.id", "server", "recipients"] {
        let mode = fs::metadata(root.path().join("nd7/vault").join(name))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "{name}");
    }
}

/// §10 tests 2 and 3: fifty frames ship, the vault's head is the local head,
/// what it stored decrypts to the local file byte for byte, and the next
/// twenty go in one request that starts at seq 50.
#[test]
fn a_session_ships_and_then_only_what_is_new() {
    let vault = Vault::start();
    let root = TempRoot::new("ships");
    enroll(&root, &vault);

    record_many(&root, "s2", 0..50);
    let out = nd7(&root, &["ship"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    let head = local_head(&root, "s2");
    assert_eq!(head.seq, 49);
    assert_eq!(vault.head("s2"), Some(head.clone()));
    assert_eq!(
        vault.plaintext("s2"),
        frames_file(&root, "s2"),
        "the vault's ciphertext decrypts to the local log"
    );
    assert_eq!(
        fs::read_to_string(root.session("s2").join("shipped")).unwrap(),
        format!("{head}\n")
    );

    record_many(&root, "s2", 50..70);
    let out = nd7(&root, &["ship"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));

    let batches = vault.batches("s2");
    assert_eq!(batches.len(), 2, "one request per run");
    assert_eq!((batches[1].first_seq, batches[1].last_seq), (50, 69));
    assert_eq!(vault.head("s2"), Some(local_head(&root, "s2")));
    assert_eq!(vault.plaintext("s2"), frames_file(&root, "s2"));
}

/// §10 test 4: an acknowledgement that never reached the machine. The vault
/// has the batch, `shipped` does not know it, and more frames were recorded
/// since. One `409`, one recovery, no duplicate frames.
#[test]
fn a_lost_acknowledgement_is_recovered_without_duplicates() {
    let vault = Vault::start();
    let root = TempRoot::new("lost-ack");
    enroll(&root, &vault);

    record_many(&root, "s4", 0..5);
    assert_eq!(nd7(&root, &["ship"]).status.code(), Some(0));
    let first_run = fs::read_to_string(root.session("s4").join("shipped")).unwrap();

    record_many(&root, "s4", 5..10);
    assert_eq!(nd7(&root, &["ship"]).status.code(), Some(0));
    assert_eq!(vault.state().conflicts, 0);

    // Roll `shipped` back one batch, as a process killed after the ack but
    // before the rename would leave it, and record more.
    fs::write(root.session("s4").join("shipped"), &first_run).unwrap();
    record_many(&root, "s4", 10..13);

    let out = nd7(&root, &["ship"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(vault.state().conflicts, 1, "exactly one 409");
    assert_eq!(vault.head("s4"), Some(local_head(&root, "s4")));
    assert_eq!(
        vault.plaintext("s4"),
        frames_file(&root, "s4"),
        "recovery left no duplicated and no missing frame"
    );
    let seqs: Vec<(u64, u64)> = vault
        .batches("s4")
        .iter()
        .map(|b| (b.first_seq, b.last_seq))
        .collect();
    assert_eq!(seqs, vec![(0, 4), (5, 9), (10, 12)]);
}

/// §10 test 5: one byte of a frame rewritten locally. The run exits 1 naming
/// the frame and the vault stores nothing.
///
/// The frame is one the vault has not acknowledged yet. A frame it already
/// holds is not re-read by `ship` at all: rewriting one of those is caught
/// on the next push, as a `409`, which is §10 test 6 and the vault's half of
/// the contract rather than this one's.
#[test]
fn a_rewritten_frame_stops_the_session_and_stores_nothing() {
    let vault = Vault::start();
    let root = TempRoot::new("rewritten");
    enroll(&root, &vault);

    record_many(&root, "s5", 0..5);
    assert_eq!(nd7(&root, &["ship"]).status.code(), Some(0));
    let head = vault.head("s5");

    record_many(&root, "s5", 5..8);
    tamper(&root, "s5", 6);

    let out = nd7(&root, &["ship"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("s5") && stderr(&out).contains("frame 6"),
        "{}",
        stderr(&out)
    );
    assert_eq!(vault.head("s5"), head, "the vault is untouched");
    assert_eq!(vault.batches("s5").len(), 1);
}

/// §10 test 8: an accepted request replayed verbatim is answered `200` and
/// stores nothing, which is why the protocol needs no nonce cache (§5).
#[test]
fn replaying_an_accepted_request_stores_nothing() {
    let vault = Vault::start();
    let root = TempRoot::new("replay");
    enroll(&root, &vault);

    record_many(&root, "s8", 0..5);
    assert_eq!(nd7(&root, &["ship"]).status.code(), Some(0));

    let (path, headers, body) = vault.state().requests.last().cloned().unwrap();
    let before = vault.batches("s8");
    assert_eq!(replay(vault.port, &path, &headers, &body), 200);
    assert_eq!(vault.batches("s8").len(), before.len());
    assert_eq!(vault.head("s8"), Some(local_head(&root, "s8")));
    assert_eq!(vault.state().conflicts, 0);
}

/// §10 test 12: a vault that hands out a recipient set signed by a key the
/// machine never pinned. Nothing ships and the run exits 1.
#[test]
fn a_recipient_set_from_an_unknown_key_ships_nothing() {
    let vault = Vault::start();
    let root = TempRoot::new("substituted");
    enroll(&root, &vault);
    record_many(&root, "s12", 0..3);

    // The same admins, signed by someone else: a valid signature by a key
    // that is not in the pinned set is exactly the attack (§4.3).
    {
        let mut state = vault.state();
        let set = state.recipients.set.clone();
        state.recipients = SignedRecipientSet::sign(set, &AdminKey::from_seed(&STRANGER_SEED));
    }

    let out = nd7(&root, &["ship"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(
        stderr(&out).contains("not signed by a pinned admin key"),
        "{}",
        stderr(&out)
    );
    assert!(vault.batches("s12").is_empty(), "no batch was sent");
    assert!(!root.session("s12").join("shipped").exists());
}

/// §10 test 14: `--prune-after 0s` removes a session the vault has all of
/// and leaves the one this run stopped.
#[test]
fn prune_removes_a_shipped_session_and_keeps_a_stopped_one() {
    let vault = Vault::start();
    let root = TempRoot::new("prune");
    enroll(&root, &vault);

    record_many(&root, "clean", 0..4);
    record_many(&root, "stopped", 0..4);
    tamper(&root, "stopped", 2);

    let out = nd7(&root, &["ship", "--prune-after", "0s"]);
    assert_eq!(out.status.code(), Some(1), "the stopped session exits 1");
    assert_eq!(vault.head("clean").map(|h| h.seq), Some(3));
    assert!(
        !root.session("clean").exists(),
        "a fully shipped session is pruned"
    );
    assert!(
        root.session("stopped").exists(),
        "a stopped session is never pruned"
    );
    assert!(vault.batches("stopped").is_empty());
}

/// §7: once the vault holds a chain that ends in a `session_end`, the
/// machine deletes its chain key and keeps nothing that opens it.
#[test]
fn a_closed_chain_leaves_no_key_behind() {
    let vault = Vault::start();
    let root = TempRoot::new("closed");
    enroll(&root, &vault);

    record_many(&root, "s7", 0..3);
    assert_eq!(nd7(&root, &["ship"]).status.code(), Some(0));
    assert!(root.session("s7").join("chain.key").exists());

    record_session_end(&root, "s7");
    let out = nd7(&root, &["ship"]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(vault.head("s7"), Some(local_head(&root, "s7")));
    assert!(
        !root.session("s7").join("chain.key").exists(),
        "the key of a closed chain is deleted"
    );
    assert_eq!(vault.plaintext("s7"), frames_file(&root, "s7"));
}
