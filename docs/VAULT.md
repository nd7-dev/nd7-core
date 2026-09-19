# nd7-vault and `nd7 ship`

This is the contract between the recorder in this repo and the server that
keeps a copy of its logs. The server is a separate project, `nd7-vault`, in
`../nd7-vault`. This document is owned here because the frame format and the
chain rules it depends on are owned here. Change it deliberately and record
why in [DECISIONS.md](DECISIONS.md) (ADR-0005).

Status: proposed. Nothing in this document is implemented.

## 1. Why ship at all

`nd7 verify` proves a session log is unchanged since its last frame was
written, if the verifier trusts the head. Anyone who can write the file can
rewrite the whole chain. A prompt copy on a machine the agent cannot reach
turns that self-check into evidence: a rewritten local chain no longer matches
the copy. The viewer is secondary. The copy is the point.

## 2. Threat model

The frames are the agent's full view of the work: file contents, command
output, credentials it read, prompts. Assume:

- The vault host, its database and its backups will be stolen or dumped at
  some point. That must yield nothing readable.
- The vault operator is not trusted with plaintext. This includes us when
  we host it for others.
- A leaked key must expose at most what that key was issued for: one admin's
  access to one organisation, or one chain. Never a second organisation.
- The machine that records is trusted to record honestly at the time it
  records; the attacker is someone who later rewrites its logs.
- TLS may be terminated by a proxy the vault does not control.

Consequences: frames are encrypted on the machine before they leave it, to
keys the vault does not have. The vault stores ciphertext and a small clear
index. Verification of frame bytes happens where plaintext exists: on the
machine and on the admin's side. The vault verifies only chain linkage.

## 3. Scope

In scope for the first version:

- `nd7 enroll`: bind this machine to a vault, with a signing key and the
  pinned set of recipient keys for its organisation.
- `nd7 ship`: encrypt and push unshipped frames in batches, resume after
  failure, optionally prune sessions the vault has fully acknowledged.
- `nd7-vault`: receive batches, verify chain linkage, store ciphertext,
  serve a minimal viewer that decrypts in the admin's browser.
- `nd7-vault admin` subcommands: bootstrap an organisation and its login
  provider, create an admin key, add or remove an admin, rekey, and
  download, decrypt and verify a chain from the command line.

Out of scope, deliberately: search, dashboards, alerting, secret detection,
role hierarchies beyond admin, multi-region, and any change to the frame
format.

Rule carried over from [VISION.md](VISION.md): nothing in the engine may
assume a vault exists. `nd7 record` never talks to the network. A machine
that is never enrolled behaves exactly as today.

## 4. Keys

Primitives, all from libsodium or an audited Rust equivalent, none invented
here: Ed25519 for signatures, X25519 sealed boxes for key wrapping,
XChaCha20-Poly1305 for symmetric encryption, BLAKE3 for hashes (already the
chain hash). No password hashing: the vault stores no passwords (§4.5).

### 4.1 Hierarchy

```
admin key        X25519 pair per admin. Private half never on the vault.
                 Held in the admin's OS keychain or a hardware token.
                 Public half registered with the vault, fingerprinted.

chain key        Random 256-bit XChaCha20 key per (session_id, host),
                 generated on the machine the first time it ships that chain.
                 Wrapped once per admin of the organisation (sealed box to
                 the admin's public key). The wraps travel with the first
                 batch. The machine keeps it in the session directory
                 while the chain is open, then deletes it.

machine key      Ed25519 pair per machine. Signs every request. Not an
                 encryption key. Leaking it lets an attacker push frames
                 as that machine, never read any.
```

There is no organisation key and no vault master key. What a leak exposes:

| leaked                     | exposes |
|----------------------------|---------|
| vault database and disk    | ciphertext, hashes, timestamps, session ids, hostnames, admin public keys |
| one admin's private key    | that organisation's chains, for as long as the wraps to that key exist |
| one chain key              | that chain |
| one machine key            | nothing readable; the ability to push signed garbage as that machine |
| vault operator credentials | the same as the database |

The honest limit: an admin key opens everything in its organisation. That is
what an admin is. Mitigations are hardware-backed admin keys, few admins, and
removal (§4.3) as soon as a key is suspected.

### 4.2 Pinning recipients

A machine encrypts to the admin public keys of its organisation. It fetches
them from the vault. A malicious vault could substitute its own key. The
defence: the enrolment token embeds a BLAKE3 fingerprint of the current admin
key set, and `nd7 enroll` refuses to complete if the keys it fetches do not
hash to that fingerprint. The fingerprint is printed when the admin creates
the token, so it can be compared out of band. After enrolment the pinned set
is stored in `$XDG_STATE_HOME/nd7/vault/recipients` and only changes through
§4.3.

### 4.3 Adding and removing admins

Adding an admin: an existing admin runs `nd7-vault admin add <pubkey>`. The
CLI, holding the existing admin's private key, unwraps every chain key of the
organisation and wraps each to the new key, uploading the new wraps. The vault
records the new admin and the new fingerprint of the key set. Enrolled
machines pick the change up on their next `nd7 ship`: the vault returns the
new set signed by the admin who made the change, using that admin's Ed25519
key derived from the same seed as the X25519 key. The machine accepts the new
set only if that signature verifies against a key already in its pinned set.

Removing an admin: delete their wraps and their public key. Chains they
already decrypted are already known to them; nothing can undo that. New
chains are never wrapped to them. Existing chains are not rekeyed in v1;
if the removal is because of a suspected leak, an admin runs
`nd7-vault admin rekey` which generates a new chain key per chain, re-encrypts, and
rewraps. That is expensive and rare, and it is an admin's explicit act.

### 4.4 Machine enrolment

```
nd7 enroll https://vault.example.com <token>
```

Generates the machine key pair, fetches the recipient set, checks it against
the fingerprint in the token, sends the public signing key and hostname, and
stores, all mode `0600` under `$XDG_STATE_HOME/nd7/vault/`:

```
machine.key      Ed25519 private key
machine.id       vault-assigned id
server           base URL
recipients       pinned admin public keys with the signed set metadata
```

Tokens expire after one hour and are consumed on first use. Re-enrolling a
machine that already has a key is refused unless `--rotate` is passed, which
registers a new signing key under the same machine id and retires the old.

### 4.5 Admin identity and login

The vault stores no passwords, ever. An admin is identified by
`(provider, subject)` where `provider` is a login provider configured for
their organisation and `subject` is the stable id that provider asserts.
Login gives access to the clear index and to ciphertext. Reading a frame
additionally needs the admin's private key, which is used in the browser
(§9) or in the CLI and never sent to the vault.

Login is behind one trait, so providers are added without touching the rest
of the server:

```rust
pub trait AuthProvider {
    /// Start a login: returns where to send the browser and any state to
    /// keep in the session (nonce, PKCE verifier).
    fn begin(&self, redirect_uri: &Url) -> Result<(Url, AuthState), AuthError>;
    /// Finish a login from the provider's callback. Returns the asserted
    /// identity or an error; never a partial identity.
    fn complete(&self, callback: &CallbackParams, state: &AuthState)
        -> Result<Identity, AuthError>;
}

pub struct Identity { pub subject: String, pub email: Option<String>, pub claims: serde_json::Value }
```

Providers are configured per organisation, in the database, by an admin
with the CLI. One organisation can have several. The first version ships
two implementations:

- `oidc`: OpenID Connect authorization code flow with PKCE, discovery from
  the issuer URL. The client secret, when the IdP requires one, is a
  server-side secret needed at every login, so it is stored in the
  database with file permissions as the control and documented as such.
  Public clients (PKCE only, no secret) are preferred when the IdP allows.
  This one provider covers Google Workspace, Okta, Microsoft Entra,
  Auth0, Keycloak and every enterprise IdP that matters.
- `dev`: a form that accepts an email and asserts it as the subject. Enabled
  only when the server is bound to loopback and `ND7_VAULT_DEV_LOGIN=1` is
  set; the server refuses to start with it on any other bind address. It
  exists for development and the acceptance tests.

Designed for, not in v1: SAML, GitHub, and enterprise-specific mappings such
as group claims to organisation membership. Each is one more implementation
of the trait and one more row type in the provider table.

An admin's first login creates nothing. Admins are created by the CLI or by
an existing admin, keyed by provider and subject or, before the subject is
known, by provider and email; the first matching login binds the subject.
The bootstrap admin of a new organisation is created by
`nd7-vault admin bootstrap`, which also creates the organisation and its
first provider.

Sessions are a random 256-bit id in an HttpOnly, Secure, SameSite=Strict
cookie, stored server-side with the admin id and an expiry of 12 hours.

The admin CLI does not log in through a provider. It authenticates each
request with the admin's Ed25519 key (the one derived from the same seed as
the X25519 key, §4.3) using exactly the request-signing scheme machines use
(§5), with `X-Nd7-Admin: <fingerprint>` in place of `X-Nd7-Machine`. The
vault accepts a signed admin request only if the fingerprint belongs to a
non-removed admin with a registered public key. An admin registers their
public key once, from the browser after a provider login (`POST /api/me/key`),
or the bootstrap command sets it. There is therefore no API token, no
service account and no second kind of secret anywhere in the system.

## 5. Transport

HTTPS only, TLS 1.3 minimum, standard certificate verification. The one
exception is `http://localhost` and `http://127.0.0.1`, accepted for
development so the vault can be run without certificates. There is no flag
to disable verification against any other host. Because frames are already
ciphertext, TLS here protects the index metadata and the signatures, not the
content.

Every request from a machine carries:

| header               | value |
|----------------------|-------|
| `X-Nd7-Machine`      | `machine.id` |
| `X-Nd7-Timestamp`    | Unix seconds, from the machine's clock |
| `X-Nd7-Body`         | BLAKE3 of the request body bytes as sent, hex |
| `X-Nd7-Signature`    | Ed25519 over `method \n path \n machine \n timestamp \n body-hash`, base64 |

The vault rejects a timestamp more than five minutes from its own clock
(401). It does not keep a nonce cache: every write endpoint is idempotent
(§6), so replaying a captured request changes nothing.

## 6. Protocol

Paths are under `/v1`.

### `POST /v1/enroll`

Body: `{"token": "...", "public_key": "<base64>", "host": "<hostname>"}`.
Unsigned. Response `201 {"machine_id": "...", "recipients": {...}}` where
`recipients` is the current admin key set and its signed metadata.
Errors: `401` bad or used token, `409` host already enrolled and no `--rotate`.

### `GET /v1/recipients`

Signed. Returns the current admin key set with the signature described in
§4.3. Called by `nd7 ship` at the start of every run.

### `GET /v1/chains/{session_id}/{host}/head`

Signed. Response `200 {"seq": <u64>, "hash": "<hex>"}` or `404`.

### `POST /v1/chains/{session_id}/{host}/frames`

Signed. Body, `Content-Encoding: zstd` applied to the plaintext before
encryption is not possible, so compression happens first and encryption
second on the machine. The body is one encrypted batch:

```
{
  "first_seq": <u64>,
  "last_seq":  <u64>,
  "index":     [ {"seq": n, "prev": "<hex>", "hash": "<hex>", "ts": <i64>} , ... ],
  "wraps":     { "<admin fingerprint>": "<sealed chain key, base64>", ... }   (first batch of a chain only)
  "nonce":     "<24 bytes, base64>",
  "ciphertext": "<XChaCha20-Poly1305 over zstd(frames), base64>"
}
```

The associated data for the AEAD is `session_id \n host \n first_seq \n last_seq`
so a ciphertext cannot be moved to another chain or position. `index` is
the only content the vault can read: envelope hashes and timestamps, no
`kind`, no body.

Limit: 8 MiB of frames before compression per batch. The client splits at
frame boundaries.

The vault, in order:

1. Verifies the signature and timestamp (401).
2. Checks `X-Nd7-Body` against the received bytes (400).
3. Loads its head. Expects `first_seq == head.seq + 1` and
   `index[0].prev == head.hash`. For an unseen chain, expects `first_seq`
   0, `index[0].prev == BLAKE3(session_id)`, and a `wraps` entry for every
   current admin. On mismatch: `409 {"expected_seq": n, "head_hash": "..."}`,
   nothing stored.
4. Verifies linkage within the index: `seq` dense, each `prev` equal to the
   previous `hash`. `422 {"seq": n}` on the first break, nothing stored.
5. Stores the batch as received, updates the head to the last index entry,
   records machine id and receipt time, returns `200 {"acked_seq": last}`.

The vault cannot check that `hash` is the BLAKE3 of the frame bytes, because
it does not have the bytes. That check happens on the admin side at read
time (§9) and on the machine before shipping. What the vault's linkage check
does guarantee is that a later local rewrite, which changes hashes, is
detected on the next push as a `409`.

Idempotency: a batch whose `first_seq` is at or before the head is compared
by index against what is stored. Identical index returns `200` with the
current head, nothing stored. A differing `hash` at the same `seq` is a
divergence: `409` with the stored head, and the vault logs a security event,
since the machine's log was rewritten after shipping.

### Segment verification in this repo

The machine verifies each batch before encrypting it, and the admin verifies
after decrypting, with the same function. This repo must expose it:

```rust
/// Verify one contiguous run of frames claimed to follow `after`
/// (`None` at genesis). Returns the new head.
pub fn verify_segment(
    session_id: &str,
    after: Option<&Head>,
    frames: &[u8],
) -> Result<Head, ChainError>;
```

`SessionLog::verify` becomes a caller of it over the whole file. The vault
depends on `nd7_core` only for `Head`, `ChainError`, and the index linkage
rule; the browser viewer reimplements the byte-hash check in JavaScript
against the same test vectors, which this repo publishes under `tests/`.

## 7. `nd7 ship`

One-shot by default. `--every <duration>` loops. It is not started from
`nd7 record` and never runs inside a hook.

```
nd7 ship                      push everything pending, exit 0 if all acked
nd7 ship --every 30s          loop; for launchd or systemd, prefer a timer
                              running the one-shot form
nd7 ship --prune-after 30d    after shipping, delete sessions fully acked
                              whose last frame is older than 30 days
```

Per-session state, in the session directory next to `head`:

```
shipped          "<seq> <hash>\n", last frame the vault acknowledged
chain.key        the chain key, 0600, present while the chain is open
```

Algorithm, per session directory, under the session's `lock`:

1. Refresh recipients (§6). Refuse to ship anything if the set changed and
   the change is not signed by a pinned key.
2. Read `head` and `shipped`. If equal, nothing to do.
3. Seek to the byte offset after the shipped frame (reading backwards from
   the end, as `append` does) and read to end of file.
4. Run `verify_segment` over the bytes against `shipped`. A failure here is
   a local corruption or rewrite: stop this session, report, exit 1 at the
   end of the run.
5. Split into batches of at most 8 MiB at frame boundaries. For each:
   compress, encrypt with `chain.key` (generating and wrapping it on the
   first batch of a chain), build the index, push. Stop at the first failure.
6. On `200`, write `shipped` via `shipped.tmp` and rename.
7. On `409` with `expected_seq` ahead of `shipped`, an acknowledgement was
   lost: set `shipped` to the server head if the local frame at that `seq`
   has the same hash, and go to 3. If the hash differs, treat as 8.
8. On `409` with a differing hash, or `422`: stop shipping this session,
   leave `shipped` untouched, write one stderr line naming session, `seq`
   and both hashes, exit 1 at the end of the run. Never auto-resolved.
9. On network errors, leave state as is and retry next run.

When a session's last frame is `session_end` and `shipped == head`, delete
`chain.key`. The machine then holds no key for that chain. A resumed session
that appends after that point cannot ship to the same chain; `nd7 ship`
reports it and the frames stay local. Revisit if resumption after
`session_end` turns out to be common.

Prune, when enabled, removes a session directory only if `shipped` equals
`head` and the last frame's `ts` is older than the threshold. It never
prunes a session stopped under rule 8.

Cost against recorded data: the largest session so far is 1487 frames over
about ten hours, 4.8 MB uncompressed. With `--every 30s` that is roughly
1200 wake-ups, almost all of which find `head == shipped` and cost one
`stat`. Frames reach the vault at most 30 seconds after being written.

## 8. Storage

The vault stores what it receives: encrypted batches as opaque blobs, the
clear index rows, wraps, heads, machines, organisations and their login
providers, admins with their provider subject and public key, sessions, and
a receipt log. Nothing is re-serialised. A dump of the
storage is a dump of ciphertext and metadata, per §4.1.

Metadata the vault can see and an attacker with the database learns:
session ids, hostnames, machine ids, frame counts, frame timestamps, and
therefore when people work and how much. If that is unacceptable for a
deployment, `ts` can be moved out of the index at the cost of the sessions
list showing receipt times instead; not a v1 decision.

## 9. Viewer

Admins, after login through their organisation's provider, get three pages. Frame content is decrypted in the
browser with the admin's private key, loaded from a file or a hardware token
through WebAuthn PRF where available. The key never goes to the server.

- Sessions: one row per `session_id`, from the clear index: hosts, first and
  last `ts`, frame count, machine, linkage status.
- Session: the browser fetches the chain's batches and the wrap for this
  admin, unseals the chain key, decrypts, decompresses, runs the byte-hash
  verification against the index, and renders frames in `seq` order, one
  line each with `ts`, `kind`, and a summary; each expands to raw JSON.
  A hash mismatch is shown in red at the frame where it occurs.
- Verify: for one chain, the linkage result from the vault, the byte-hash
  result from the browser, and the receipt log (which machine, when).

Nothing else.

## 10. Acceptance tests

Driven by a script against a real `nd7` binary from this repo:

1. Enrol with a fresh token. Same token again is refused. Enrol against a
   vault whose recipient set does not match the token fingerprint is
   refused and stores nothing locally.
2. Record 50 frames, ship, confirm the vault head equals the local head and
   that an admin CLI can download, decrypt, and byte-verify the chain to an
   identical file.
3. Record 20 more frames, ship, confirm one request with `first_seq` 50.
4. Kill `nd7 ship` after the acknowledgement but before `shipped` is
   written. Run again. Confirm one `409`, recovery, no duplicates.
5. Edit one byte of a shipped frame locally and ship. Confirm exit 1 naming
   the `seq`, nothing stored on the vault.
6. Push a batch whose first `prev` does not match the head. Confirm `409`.
7. Push with a valid signature from an unknown key. Confirm `401`.
8. Replay an accepted request verbatim. Confirm `200`, nothing stored.
9. Dump the database and disk. Confirm a string known to be inside a frame
   is not present, and that no key material is present.
10. Two organisations, one admin each. Admin A's key decrypts none of B's
    chains and vice versa; the attempt fails at unseal, not at fetch.
11. Add a second admin to A. They can decrypt chains shipped before they
    were added. Remove the first admin; a new chain shipped afterwards has
    no wrap for them and their key fails to unseal it.
12. A vault that returns a substituted recipient set unsigned by a pinned
    key: `nd7 ship` refuses to ship and exits 1.
13. The viewer, with admin A's key, shows chain content and a green
    byte-verify for tests 2 and 3, and a red frame for a chain whose stored
    ciphertext was tampered on disk.
14. `nd7 ship --prune-after 0s` removes a fully shipped session and leaves
    the one stopped in test 5.

## 11. Implementation notes for `nd7-vault`

- Rust. Depends on `nd7_core` for `Head`, `ChainError`, the linkage rule,
  and the batch and crypto types in its `vault` module, so machine and
  vault cannot disagree about the wire format. RustCrypto crates
  (`ed25519-dalek`, `crypto_box`, `chacha20poly1305`, `blake3`) on both
  sides; the browser uses libsodium.js, which is wire-compatible.
- Single binary, single process, SQLite for metadata, blobs on disk in a
  directory tree keyed by chain. Postgres is a later decision.
- Configuration is a handful of environment variables: bind address, data
  directory, public base URL for OIDC redirects, `ND7_VAULT_DEV_LOGIN`.
  There is no master key to configure, by design.
- No background jobs.
- The browser viewer uses libsodium.js and the published test vectors; it
  is a static bundle served by the same binary.

## 12. What this document does not decide

- Whether the vault countersigns heads so a third party can verify linkage
  without trusting the vault's database. The request signature makes it
  possible.
- Retention on the vault side.
- How a remote host in Phase 2b enrols, and whether it ships directly or via
  the originating machine.
- Whether `ts` stays in the clear index (§8).
- Anything about Codex or other producers; they ship the same frames.
