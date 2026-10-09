//! The machine's half of the vault protocol: `nd7 enroll` and `nd7 ship`
//! (docs/VAULT.md §4.4, §5, §6, §7).
//!
//! This is where the filesystem and the network meet the pure types in
//! [`crate::vault`]. Nothing here invents wire format or cryptography: the
//! signing bytes, the associated data, the index and the linkage rule all
//! come from that module, so the vault cannot disagree with this code about
//! what was sent.
//!
//! Blocking `std` I/O throughout, one request at a time, no runtime and no
//! threads; `nd7 record` still never touches the network. What this module
//! keeps on disk, all mode `0600`:
//!
//! ```text
//! $XDG_STATE_HOME/nd7/vault/machine.key   Ed25519 seed, 32 raw bytes
//! $XDG_STATE_HOME/nd7/vault/machine.id    vault-assigned id
//! $XDG_STATE_HOME/nd7/vault/server        base URL
//! $XDG_STATE_HOME/nd7/vault/recipients    pinned SignedRecipientSet, JSON
//! $XDG_STATE_HOME/nd7/sessions/<id>/shipped    "<seq> <hash>\n", last ack
//! $XDG_STATE_HOME/nd7/sessions/<id>/chain.key  chain key while the chain is open
//! ```

use std::{
    collections::BTreeMap,
    fs, io,
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};

use crate::{
    hook::{Invocation, invocation::now_ns},
    session_log::{
        Head, SessionLog, TS, Tail, find, number, read_head, state_root, verify_segment,
    },
    vault::{
        BatchAad, ChainKey, MachineKey, SignedRecipientSet, build_index, seal_batch,
        wire::{
            ConflictResponse, EnrollRequest, EnrollResponse, FramesRequest, HEADER_BODY,
            HEADER_MACHINE, HEADER_SIGNATURE, HEADER_TIMESTAMP, IndexEntry, RecipientsResponse,
            RejectResponse,
        },
    },
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

/// Most frame bytes, before compression, in one batch (§6). The client
/// splits at frame boundaries.
const MAX_BATCH: usize = 8 * 1024 * 1024;

/// How long one request may take in total before it counts as unreachable.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Bind this machine to a vault and pin its admin keys (§4.4).
///
/// The recipient set comes back in the enrolment response rather than from
/// `GET /v1/recipients`, which is signed and therefore not available to a
/// machine that has no key yet. It is accepted only if it hashes to the
/// fingerprint the token carries; if it does not, nothing at all is written,
/// because a machine that pins the wrong keys encrypts everything to an
/// attacker. Returns the vault-assigned machine id.
pub fn enroll(server: &str, token: &str, rotate: bool) -> Result<String> {
    let server = server.trim_end_matches('/');
    let (fingerprint, _) = token
        .split_once('.')
        .ok_or("token: expected <fingerprint>.<secret>")?;

    let dir = vault_dir()?;
    if dir.join("machine.key").exists() && !rotate {
        return Err("this machine is already enrolled; pass --rotate to register a new key".into());
    }

    let key = MachineKey::generate();
    let body = serde_json::to_vec(&EnrollRequest {
        token: token.to_owned(),
        public_key: B64.encode(key.public_key()),
        host: Invocation::now().host,
        rotate,
    })?;
    let (status, answer) = send(&agent(), None, "POST", server, "/v1/enroll", body)?;
    if status != 201 {
        return Err(format!("the vault answered {status}: {}", text(&answer)).into());
    }
    let enrolled: EnrollResponse = serde_json::from_slice(&answer)?;

    let found = enrolled.recipients.set.fingerprint();
    if found != fingerprint {
        return Err(format!(
            "the vault's admin keys hash to {found}, the token pins {fingerprint}: nothing written"
        )
        .into());
    }

    fs::create_dir_all(&dir)?;
    write_private(&dir.join("machine.id"), enrolled.machine_id.as_bytes())?;
    write_private(&dir.join("server"), server.as_bytes())?;
    write_private(
        &dir.join("recipients"),
        &serde_json::to_vec(&enrolled.recipients)?,
    )?;
    // Last, so a run interrupted halfway is not mistaken for an enrolment.
    write_private(&dir.join("machine.key"), &key.to_seed())?;
    Ok(enrolled.machine_id)
}

/// Push every session's pending frames, once or on a timer (§7).
///
/// The exit code: 1 when a session stopped on a divergence or a local
/// verification failure, because neither resolves itself and both want a
/// human. A vault that cannot be reached is not that. One shot returns 1 so
/// that a cron job or a systemd timer notices the machine is falling behind;
/// `--every`, which tries again in a moment, returns 0 and keeps looping.
/// Either way the state on disk is left alone and the frames go next run.
///
/// `--every` sleeps between runs and has nothing to clean up, so an
/// interrupt ends it wherever it is: the session lock is released with the
/// process and every write is a rename. It also ends on the one failure
/// that is not worth retrying, a recipient set no pinned admin signed.
pub fn ship(every: Option<Duration>, prune_after: Option<Duration>) -> Result<u8> {
    let unreachable_code = if every.is_some() { 0 } else { 1 };
    loop {
        let code = run_once(prune_after, unreachable_code)?;
        let Some(interval) = every else {
            return Ok(code);
        };
        thread::sleep(interval);
    }
}

/// One pass over every session. `Err` is a reason to stop shipping at all:
/// this machine is not enrolled, or the vault handed out a recipient set
/// nobody pinned has signed.
fn run_once(prune_after: Option<Duration>, unreachable_code: u8) -> Result<u8> {
    let mut machine = Machine::load()?;

    // §7 step 1. A vault that cannot be reached is retried next run; a
    // recipient set that is not signed by a pinned admin is an attempt to
    // make this machine encrypt to someone else's key, and nothing ships.
    let fetched = match machine.fetch_recipients() {
        Ok(set) => set,
        Err(e) => {
            eprintln!("nd7 ship: {e}");
            return Ok(unreachable_code);
        }
    };
    if !fetched.verify_against(&machine.recipients.set) {
        return Err("the vault's recipient set is not signed by a pinned admin key".into());
    }
    machine.pin(fetched)?;

    let root = state_root()?;
    let entries = match fs::read_dir(root.join("sessions")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e.into()),
    };

    let (mut stopped, mut unreachable) = (false, false);
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let Some(session_id) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let log = SessionLog::open_in(&root, &session_id)?;
        // A session reports its own failures: anything unexpected on the
        // local side stops this session rather than the run, because the next
        // session's frames are unaffected.
        let outcome = session(&machine, &log, prune_after).unwrap_or_else(|e| {
            eprintln!("nd7 ship: {}: {e}", log.session_id());
            Outcome::Stopped
        });
        match outcome {
            Outcome::Done => {}
            Outcome::Unreachable => unreachable = true,
            Outcome::Stopped => stopped = true,
        }
    }

    Ok(match (stopped, unreachable) {
        (true, _) => 1,
        (false, true) => unreachable_code,
        (false, false) => 0,
    })
}

/// How one session's run ended. The exit code and whether the session may be
/// pruned both follow from it (§7 steps 8 and 9).
enum Outcome {
    /// Everything the vault was missing reached it, or there was nothing.
    Done,
    /// The vault could not be reached, or refused for a reason that is not
    /// the chain's: state untouched, tried again next run.
    Unreachable,
    /// A divergence, a local verification failure or a local I/O failure.
    /// Never resolved automatically, and never pruned.
    Stopped,
}

/// §7 steps 2 to 9 for one session.
///
/// The exclusive lock is taken for local work only and never held across a
/// request: every `nd7 record` hook waits on the same lock, and a vault
/// that takes a second to answer must not cost the agent a second. So the
/// run reads `head`, `shipped`, the pending bytes and `chain.key` under the
/// lock, releases it, then verifies, encrypts and pushes with no lock held,
/// and takes it again only to write `shipped`. An append in between adds
/// bytes after everything that was read, so nothing read under the lock
/// goes stale; the frames it added ship on the next run.
fn session(machine: &Machine, log: &SessionLog, prune_after: Option<Duration>) -> Result<Outcome> {
    let shipped_path = log.dir().join("shipped");
    let key_path = log.dir().join("chain.key");
    // §7 step 7 recovers from one lost acknowledgement per session per run.
    // A vault that keeps answering 409 with the same head therefore stops
    // the session instead of spinning.
    let mut recover = true;

    let outcome = loop {
        let Some(pending) = read_pending(log, &shipped_path, &key_path)? else {
            break Outcome::Done;
        };
        match push(machine, log, &shipped_path, &pending, recover)? {
            Some(outcome) => break outcome,
            // An acknowledgement that never arrived: `shipped` has been
            // caught up, so the directory is read afresh and this goes again.
            None => recover = false,
        }
    };

    if matches!(outcome, Outcome::Done) {
        finish(log, &shipped_path, &key_path, prune_after)?;
    }
    Ok(outcome)
}

/// What one session has for the vault: §7 steps 2 and 3, and the chain key,
/// all read under the exclusive lock. `None` when the vault already has
/// everything the session holds.
struct Pending {
    /// The last frame the vault acknowledged, `None` for a chain it has never
    /// seen.
    shipped: Option<Head>,
    /// The bytes of every frame after it.
    frames: Vec<u8>,
    key: ChainKey,
}

fn read_pending(log: &SessionLog, shipped_path: &Path, key_path: &Path) -> Result<Option<Pending>> {
    let _lock = log.lock_exclusive()?;
    // A session directory with no head has no frames to ship.
    let Some(head) = log.read_head()? else {
        return Ok(None);
    };
    let shipped = read_head(shipped_path)?;
    if shipped.as_ref() == Some(&head) {
        return Ok(None);
    }

    // The pending bytes, found by reading backwards from the end.
    let frames = match &shipped {
        None => fs::read(log.events_path())?,
        Some(shipped) => log.read_after_seq(shipped.seq)?.ok_or_else(|| {
            format!(
                "the log no longer holds frame {}, the last one the vault acknowledged",
                shipped.seq
            )
        })?,
    };
    // Nothing after the shipped frame although `head` is a different frame:
    // the two sidecars disagree, which no batch can fix.
    if frames.is_empty() {
        return Err(format!(
            "`shipped` and `head` name frame {} with different hashes",
            head.seq
        )
        .into());
    }

    // The chain key is generated with the chain's first batch, which is the
    // one nothing has been shipped before, and deleted when the chain closes
    // (§4.1). Missing on a chain that has already started means the chain was
    // closed by a `session_end` and these frames were appended after it; §7
    // leaves them local.
    let key = match read_chain_key(key_path)? {
        Some(key) => key,
        None if shipped.is_none() => {
            let key = ChainKey::generate();
            write_private(key_path, key.as_bytes())?;
            key
        }
        None => {
            return Err(
                "this chain is closed: its key was deleted after the session_end \
                        the vault acknowledged, so these frames cannot ship to it"
                    .into(),
            );
        }
    };
    Ok(Some(Pending {
        shipped,
        frames,
        key,
    }))
}

/// Verify, encrypt and push the pending frames: §7 steps 4 to 9, with the
/// lock held only for the `shipped` write of step 6.
///
/// `Ok(None)` asks the caller to run the session again: the vault answered
/// `409` holding a frame of ours that `shipped` did not know about, and
/// `shipped` has been caught up to it (§7 step 7). `recover` is false once
/// that has happened, so a vault that keeps answering `409` stops the session
/// instead of spinning.
fn push(
    machine: &Machine,
    log: &SessionLog,
    shipped_path: &Path,
    pending: &Pending,
    recover: bool,
) -> Result<Option<Outcome>> {
    // §7 steps 4 and 5, with no lock held. A verification failure here is a
    // local rewrite and stops the session.
    verify_segment(log.session_id(), pending.shipped.as_ref(), &pending.frames)?;

    let index = build_index(&pending.frames)?;
    let host = member(&pending.frames, "host")
        .ok_or("the first pending frame carries no host")?
        .to_owned();

    for (bytes, entries) in batches(&pending.frames, &index) {
        let last = &entries[entries.len() - 1];
        let aad = BatchAad {
            session_id: log.session_id().to_owned(),
            host: host.clone(),
            first_seq: entries[0].seq,
            last_seq: last.seq,
        };
        let sealed = seal_batch(&pending.key, &aad, bytes);
        let body = serde_json::to_vec(&FramesRequest {
            first_seq: aad.first_seq,
            last_seq: aad.last_seq,
            index: entries.to_vec(),
            // The first batch of a chain carries the chain key, sealed to
            // every pinned admin (§6 step 3).
            wraps: (aad.first_seq == 0).then(|| wraps(&pending.key, &machine.recipients)),
            nonce: B64.encode(sealed.nonce),
            ciphertext: B64.encode(&sealed.ciphertext),
        })?;
        let path = format!("/v1/chains/{}/{host}/frames", log.session_id());

        let (status, answer) = match machine.send("POST", &path, body) {
            Ok(answer) => answer,
            Err(e) => {
                eprintln!("nd7 ship: {}: {e}", log.session_id());
                return Ok(Some(Outcome::Unreachable));
            }
        };
        match status {
            // §7 step 6, the one write this needs the lock for.
            200 => {
                let _lock = log.lock_exclusive()?;
                write_private(shipped_path, shipped_line(last).as_bytes())?;
            }
            // §7 steps 7 and 8.
            409 => {
                let conflict: ConflictResponse = serde_json::from_slice(&answer)?;
                let ours = conflict
                    .expected_seq
                    .checked_sub(1)
                    .filter(|&seq| pending.shipped.as_ref().is_none_or(|head| seq > head.seq))
                    .and_then(|seq| index.iter().find(|entry| entry.seq == seq))
                    .filter(|entry| entry.hash == conflict.head_hash);
                if let (true, Some(entry)) = (recover, ours) {
                    let _lock = log.lock_exclusive()?;
                    write_private(shipped_path, shipped_line(entry).as_bytes())?;
                    return Ok(None);
                }
                let seq = conflict.expected_seq.saturating_sub(1);
                let local = local_hash(&index, pending.shipped.as_ref(), seq);
                eprintln!(
                    "nd7 ship: {}: the chain diverges at seq {seq}: the vault holds {}, \
                     this machine has {local}",
                    log.session_id(),
                    conflict.head_hash
                );
                return Ok(Some(Outcome::Stopped));
            }
            // §7 step 8: an index that does not link up within itself.
            422 => {
                let rejected: RejectResponse = serde_json::from_slice(&answer)?;
                eprintln!(
                    "nd7 ship: {}: the vault rejected the batch at seq {}: {}",
                    log.session_id(),
                    rejected.seq,
                    rejected.error
                );
                return Ok(Some(Outcome::Stopped));
            }
            // §7 step 9, and anything else the vault says: the state on disk
            // is untouched and the batch goes out again next run.
            other => {
                eprintln!(
                    "nd7 ship: {}: the vault answered {other}: {}",
                    log.session_id(),
                    text(&answer)
                );
                return Ok(Some(Outcome::Unreachable));
            }
        }
    }
    Ok(Some(Outcome::Done))
}

/// Close the chain and prune the session, for a run that ended `Done` (§7
/// steps 8 and 9).
///
/// Local work, so it takes the lock again. Whether the vault now has every
/// frame has to be read again rather than assumed: a hook may have appended
/// while a batch was in flight, and those frames are not shipped yet.
fn finish(
    log: &SessionLog,
    shipped_path: &Path,
    key_path: &Path,
    prune_after: Option<Duration>,
) -> Result<()> {
    let _lock = log.lock_exclusive()?;
    let complete = read_head(shipped_path)? == log.read_head()?;
    let last = match log.last_frame()? {
        Tail::Frame(frame) => Some(frame),
        Tail::Empty => None,
        Tail::Torn => return Err("the log ends mid-frame".into()),
    };

    // A chain the vault holds all of, ending in a `session_end`, is closed:
    // the machine keeps no key for it (§7).
    if complete
        && last
            .as_deref()
            .and_then(|frame| member(frame, "kind"))
            .is_some_and(|kind| kind == "session_end")
    {
        // Gone already if an earlier run deleted it.
        if let Err(e) = fs::remove_file(key_path)
            && e.kind() != io::ErrorKind::NotFound
        {
            return Err(e.into());
        }
    }

    // Prune, when it is on: only a session the vault has every frame of,
    // whose last frame is older than the threshold, and which this run did
    // not stop (§7). A threshold longer than `ts` can express is clamped, so
    // an absurd `--prune-after` prunes nothing rather than everything.
    let threshold = prune_after.map(|after| i64::try_from(after.as_nanos()).unwrap_or(i64::MAX));
    if let Some(threshold) = threshold
        && complete
        && last
            .as_deref()
            .and_then(frame_ts)
            .is_some_and(|ts| now_ns().saturating_sub(ts) >= threshold)
    {
        fs::remove_dir_all(log.dir())?;
    }
    Ok(())
}

/// Split verified frame bytes into batches of at most [`MAX_BATCH`], never
/// cutting a frame, each with the slice of `index` that describes it. A
/// single frame larger than the limit is a batch of its own.
fn batches<'a>(frames: &'a [u8], index: &'a [IndexEntry]) -> Vec<(&'a [u8], &'a [IndexEntry])> {
    let mut out = Vec::new();
    let (mut start, mut first, mut at) = (0, 0, 0);
    for (i, line) in frames.split_inclusive(|&b| b == b'\n').enumerate() {
        if at > start && at - start + line.len() > MAX_BATCH {
            out.push((&frames[start..at], &index[first..i]));
            (start, first) = (at, i);
        }
        at += line.len();
    }
    if at > start {
        out.push((&frames[start..at], &index[first..]));
    }
    out
}

/// The chain key sealed to every pinned admin, keyed by fingerprint (§6).
fn wraps(key: &ChainKey, recipients: &SignedRecipientSet) -> BTreeMap<String, String> {
    recipients
        .set
        .admins
        .iter()
        .map(|admin| (admin.fingerprint(), key.wrap_for(admin)))
        .collect()
}

/// What this machine holds at `seq`, for the divergence line: the frame in
/// the pending run, or `shipped` when the vault's head is older than it.
fn local_hash(index: &[IndexEntry], shipped: Option<&Head>, seq: u64) -> String {
    if let Some(entry) = index.iter().find(|entry| entry.seq == seq) {
        return entry.hash.clone();
    }
    match shipped {
        Some(head) if head.seq == seq => head.hash.clone(),
        _ => "no such frame".to_owned(),
    }
}

/// One line of `shipped`: the same two fields and the same format as `head`.
fn shipped_line(entry: &IndexEntry) -> String {
    format!(
        "{}\n",
        Head {
            seq: entry.seq,
            hash: entry.hash.clone(),
        }
    )
}

/// The chain key of an open chain, or `None` when the chain has none yet.
fn read_chain_key(path: &Path) -> Result<Option<ChainKey>> {
    match fs::read(path) {
        Ok(raw) => {
            let key: [u8; 32] = raw.try_into().map_err(|_| "chain.key is not 32 bytes")?;
            Ok(Some(ChainKey::from_bytes(key)))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Everything `$XDG_STATE_HOME/nd7/vault/` holds, read once per run.
struct Machine {
    dir: PathBuf,
    /// Base URL with no trailing slash, as `enroll` stored it.
    server: String,
    id: String,
    key: MachineKey,
    /// The pinned admin key set (§4.2), as last accepted.
    recipients: SignedRecipientSet,
    agent: ureq::Agent,
}

impl Machine {
    fn load() -> Result<Machine> {
        let dir = vault_dir()?;
        let seed = fs::read(dir.join("machine.key")).map_err(|e| {
            format!("this machine is not enrolled with a vault ({e}); run `nd7 enroll`")
        })?;
        let seed: [u8; 32] = seed.try_into().map_err(|_| "machine.key is not 32 bytes")?;
        let server = fs::read_to_string(dir.join("server"))?.trim().to_owned();
        // Checked once per run as well as per request, so a bad `server` file
        // fails the run instead of being refused again on every `--every` tick.
        check_server(&server)?;
        Ok(Machine {
            id: fs::read_to_string(dir.join("machine.id"))?
                .trim()
                .to_owned(),
            key: MachineKey::from_seed(&seed),
            recipients: serde_json::from_slice(&fs::read(dir.join("recipients"))?)?,
            server,
            dir,
            agent: agent(),
        })
    }

    /// The vault's current admin key set. Whether it may replace the pinned
    /// one is the caller's question, not this one's.
    fn fetch_recipients(&self) -> Result<SignedRecipientSet> {
        let (status, answer) = self.send("GET", "/v1/recipients", Vec::new())?;
        if status != 200 {
            return Err(format!("recipients: the vault answered {status}").into());
        }
        Ok(serde_json::from_slice::<RecipientsResponse>(&answer)?)
    }

    /// Pin a recipient set the caller has checked against the current one.
    fn pin(&mut self, recipients: SignedRecipientSet) -> Result<()> {
        write_private(
            &self.dir.join("recipients"),
            &serde_json::to_vec(&recipients)?,
        )?;
        self.recipients = recipients;
        Ok(())
    }

    /// Send one signed request (§5) and return its status and body.
    fn send(&self, method: &str, path: &str, body: Vec<u8>) -> Result<(u16, Vec<u8>)> {
        send(
            &self.agent,
            Some((&self.key, self.id.as_str())),
            method,
            &self.server,
            path,
            body,
        )
    }
}

/// One request to the vault, signed unless this is the enrolment that has no
/// key yet.
///
/// The four `X-Nd7` headers are built here and nowhere else: the body hash is
/// BLAKE3 of the bytes as sent, an empty body included, and the signature
/// covers the method, the path with no host, the machine id, the timestamp
/// and that hash. The URL is checked again on every request, not only when
/// it was stored, because the file it came from can be edited.
fn send(
    agent: &ureq::Agent,
    signer: Option<(&MachineKey, &str)>,
    method: &str,
    server: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<(u16, Vec<u8>)> {
    check_server(server)?;
    let mut request = ureq::http::Request::builder()
        .method(method)
        .uri(format!("{server}{path}"))
        .header("Content-Type", "application/json");
    if let Some((key, machine_id)) = signer {
        let body_hash = blake3::hash(&body).to_hex().to_string();
        let timestamp = now_ns() / 1_000_000_000;
        request = request
            .header(HEADER_MACHINE, machine_id)
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(
                HEADER_SIGNATURE,
                key.sign_request(method, path, machine_id, timestamp, &body_hash),
            )
            .header(HEADER_BODY, body_hash);
    }
    let response = agent.run(request.body(body)?)?;
    let status = response.status().as_u16();
    Ok((status, response.into_body().read_to_vec()?))
}

/// Statuses are the protocol's answer, not an error, so they are returned
/// rather than raised; a request that takes too long is a vault that cannot
/// be reached.
fn agent() -> ureq::Agent {
    ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .http_status_as_error(false)
            .timeout_global(Some(TIMEOUT))
            .build(),
    )
}

/// Refuse any URL the transport rules do not allow (§5): HTTPS with ordinary
/// certificate verification, and plain HTTP only to loopback, so the vault
/// can be run in development without certificates. There is no flag that
/// widens this.
fn check_server(url: &str) -> Result<()> {
    let loopback = |rest: &str| {
        let authority = rest.split(['/', '?']).next().unwrap_or(rest);
        let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);
        host == "localhost" || host == "127.0.0.1"
    };
    if url.starts_with("https://") {
        return Ok(());
    }
    if let Some(rest) = url.strip_prefix("http://")
        && loopback(rest)
    {
        return Ok(());
    }
    Err(format!("refusing {url}: the vault must be https, or http on localhost").into())
}

fn vault_dir() -> Result<PathBuf> {
    Ok(state_root()?.join("vault"))
}

/// Write a file nobody else can read, atomically. Every file this module owns
/// goes through here, so a half-written key or a half-written `shipped` cannot
/// be read back.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    crate::session::write_atomic(path, bytes, 0o600)
}

/// A string-valued envelope member, read straight out of a frame's bytes.
///
/// Byte search, no JSON parse, for the reason [`crate::vault::build_index`]
/// gives: a `"` inside a JSON string is escaped, so `,"host":"` cannot occur
/// inside a value, and the envelope comes before `body`, so the first
/// occurrence is the envelope's. Callers only run this over frames
/// `verify_segment` has already accepted.
fn member<'a>(frame: &'a [u8], name: &str) -> Option<&'a str> {
    let needle = format!(",\"{name}\":\"").into_bytes();
    let at = find(frame, &needle)? + needle.len();
    let rest = &frame[at..];
    let end = rest.iter().position(|&b| b == b'"')?;
    std::str::from_utf8(&rest[..end]).ok()
}

/// A frame's `ts`: Unix epoch nanoseconds, read the same way.
fn frame_ts(frame: &[u8]) -> Option<i64> {
    number(frame, TS)?.parse().ok()
}

/// A response body in an error message: whatever of it is text, trimmed to
/// one line's worth.
fn text(body: &[u8]) -> String {
    String::from_utf8_lossy(&body[..body.len().min(200)])
        .replace('\n', " ")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_https_and_loopback_http_are_accepted() {
        for ok in [
            "https://vault.example.com",
            "https://vault.example.com:8443/base",
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1:8080/base",
        ] {
            assert!(check_server(ok).is_ok(), "{ok}");
        }
        for refused in [
            "http://vault.example.com",
            "http://localhost.evil.com:8080",
            "http://127.0.0.1.evil.com",
            "ftp://localhost",
            "vault.example.com",
            "",
        ] {
            assert!(check_server(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn batches_split_at_frame_boundaries() {
        let entry = |seq| IndexEntry {
            seq,
            prev: "aa".repeat(32),
            hash: "bb".repeat(32),
            ts: 1,
        };
        let line = vec![b'x'; MAX_BATCH / 3];
        let mut frames = Vec::new();
        for _ in 0..5 {
            frames.extend_from_slice(&line);
            frames.push(b'\n');
        }
        let index: Vec<IndexEntry> = (0..5).map(entry).collect();

        let split = batches(&frames, &index);
        assert_eq!(
            split.len(),
            3,
            "five third-of-limit frames make three batches"
        );
        for (bytes, entries) in &split {
            assert!(bytes.len() <= MAX_BATCH);
            assert!(bytes.ends_with(b"\n"), "frames are never cut");
            assert_eq!(bytes.len(), entries.len() * (line.len() + 1));
        }
        let seqs: Vec<u64> = split
            .iter()
            .flat_map(|(_, entries)| entries.iter().map(|e| e.seq))
            .collect();
        assert_eq!(seqs, (0..5).collect::<Vec<u64>>(), "dense and in order");

        // One frame over the limit still goes, on its own.
        let big = vec![b'y'; MAX_BATCH + 1];
        let mut frames = big.clone();
        frames.push(b'\n');
        assert_eq!(batches(&frames, &index[..1]).len(), 1);
    }

    #[test]
    fn envelope_members_are_read_out_of_frame_bytes() {
        let frame = br#"{"v":0,"session_id":"s","seq":3,"ts":1700000000000000001,"host":"laptop","source":"intent:claude-code","kind":"session_end","prev":"00","body":{"host":"other","kind":"prompt"},"hash":"ff"}"#;
        assert_eq!(member(frame, "host"), Some("laptop"));
        assert_eq!(member(frame, "kind"), Some("session_end"));
        assert_eq!(frame_ts(frame), Some(1_700_000_000_000_000_001));
        assert_eq!(member(b"{}", "host"), None);
        assert_eq!(frame_ts(b"{}"), None);
    }
}
