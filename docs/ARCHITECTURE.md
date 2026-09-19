# Architecture (Phase 1)

Phase 1 is three small pieces around one file format: a hook entry point, a
log writer, and a reader. Everything else in the diagram is a later phase and
is shown only to prove the seams exist.

```
                         Phase 1                          later phases (dashed)
  ┌───────────────┐   hook JSON    ┌──────────────┐
  │  Claude Code  │ ───stdin────▶  │  nd7 record  │
  │  (hooks)      │                │  (intent)    │
  └───────────────┘                └──────┬───────┘
                                          │ Event{source: intent:claude-code}
  ┌ ─ ─ ─ ─ ─ ─ ─ ┐                       │
  │  Codex hooks  │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│ intent:codex
  └ ─ ─ ─ ─ ─ ─ ─ ┘                       │
  ┌ ─ ─ ─ ─ ─ ─ ─ ┐  ┌ ─ ─ ─ ─ ─ ─ ─ ┐    │
  │ macOS ES      │─▶│ nd7 collector │ ─ ▶│ effect:es
  │ Linux fanotify│  │ (daemon)      │    │ effect:fanotify
  └ ─ ─ ─ ─ ─ ─ ─ ┘  └ ─ ─ ─ ─ ─ ─ ─ ┘    │
  ┌ ─ ─ ─ ─ ─ ─ ─ ┐                       │
  │ remote nd7    │ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─▶│ effect:remote  (same session_id)
  └ ─ ─ ─ ─ ─ ─ ─ ┘                       ▼
                                   ┌──────────────┐
                                   │  log writer  │  seq, ts, prev-hash, hash
                                   │  (append)    │
                                   └──────┬───────┘
                                          ▼
                     $XDG_STATE_HOME/nd7/sessions/<session_id>/events.ndjson
                                          │
                                          ▼
                                   ┌──────────────┐        ┌ ─ ─ ─ ─ ─ ─ ┐
                                   │  nd7 show    │        │ upload /    │
                                   │  nd7 verify  │        │ org storage │
                                   └──────────────┘        └ ─ ─ ─ ─ ─ ─ ┘
```

## Hook entry point: `nd7 record`

Claude Code runs the configured command for each hook event and pipes one JSON
object to its stdin (verified against https://code.claude.com/docs/en/hooks).
The binary is `nd7`, registered in exec
form (`"command": "nd7", "args": ["record"]`) so no shell sits between Claude
Code and the recorder. It does the following, in order, and nothing else:

1. Take the invocation facts: wall-clock timestamp at nanosecond resolution,
   hostname, parent pid (`hook::Invocation::now`). Before reading stdin, so `ts`
   marks when the hook fired.
2. Read stdin to EOF and parse the JSON into the typed payload model
   (`hook::HookInput`, via `FromStr`). All 33 documented events are typed;
   the payload is also kept whole.
3. Transform into one event (`Event::new`). Six kinds have typed bodies;
   everything else, including event names this build has never seen, becomes
   a `hook` event carrying the raw payload, so an upgrade of Claude Code never
   causes silent data loss.
4. Append the event to the session log (`session_log::SessionLog::append`).
5. Exit 0 with no stdout.

The crate is a library, `nd7_core`, plus binary targets. `hook` is pure and
never touches the filesystem; `session_log` is the only module that knows where
events live. The binary is the composition point, about ten lines.

Rules:

- Always exit 0. Never print JSON to stdout. Claude Code interprets stdout
  JSON and exit code 2 as control decisions; `nd7` must never make one.
- If anything fails (bad JSON, unwritable directory), write one line to
  stderr and exit 0. Losing one event is better than blocking the agent.
- Budget: a few milliseconds. Rust startup plus one small file append is well
  under that. No network, no threads, no config parsing beyond environment
  variables.

Why a library plus thin binaries: the writer and the event model are shared by
every future producer (Codex hooks, the kernel collector) and by the reader.
Cargo binaries cannot import each other, so shared code lives in `src/lib.rs`.
Adding a tool is one `[[bin]]` entry.

Why no async runtime and no daemon: the hook is a straight line, read stdin,
transform, one append. Measurements (ADR-0003) put process spawn at ~4 ms and
the append at ~1 ms; a daemon could only remove the latter while adding
lifecycle, durability and version-skew problems. Revisit when the Phase 2
collector, which is long-running anyway, becomes the natural single writer.

Why not `async: true` in the hook config: async hooks are not awaited, so an
event could be appended after a later event's hook already ran, which breaks
sequence ordering. Synchronous with a tight timeout is simpler and, at our
cost, equally invisible. Revisit if measurements say otherwise.

## Log writer

One append-only file per session. The writer:

1. Resolves the session directory from `session_id`.
2. Takes an exclusive advisory lock on the directory's `lock` file
   (`std::fs::File::lock`, `flock` underneath). Claude Code can run several
   tool calls, and thus several hooks, at the same time; without the lock,
   sequence numbers and the hash chain race. **Done.** Verified by a
   16-thread unit test and a 40-process integration test, both of which fail
   when the lock line is removed.
3. Reads the chain head (`head`: last `seq` and last `hash`) from a small
   sidecar file, so appending does not require scanning the log. **Done.**
   A missing `head` means a fresh session; genesis `prev` is
   `BLAKE3(session_id)`. A `head` that is missing, or exactly one frame behind
   with its hash equal to the last frame's `prev`, is repaired from the log's
   last frame (read backwards from the end, not scanned). Any other
   disagreement is refused: nothing is appended and the error is reported,
   because appending onto an inconsistent chain would look exactly like
   tampering.
4. Fills in `seq`, `prev`, computes `hash`, serializes the frame, appends it
   with a single `write` on an `O_APPEND` file descriptor. **Done.** The frame
   is serialized once with `hash` absent, those bytes are hashed, and the hash
   is spliced in as the last member (`Event::seal`), so `verify` needs no
   serializer, only the same cut (`split_sealed`).
5. Rewrites `head` via `head.tmp` and `rename`, releases the lock. **Done.**

Crash safety: if the process dies between 4 and 5, `head` is stale by one
event. The writer detects this on the next append by checking that the last
frame in the file matches `head`, and repairs `head` from the file's tail.
The log itself is never rewritten. Implemented 2026-09-19.

Session start: the first event for an unknown `session_id` creates the
directory. There is no separate "open session" step because hooks can arrive
in any order after a crash or a resumed session, and `SessionStart` may fire
with `source: resume` or `compact` for an existing log.

## Session layout on disk

```
$XDG_STATE_HOME/nd7/                 (default ~/.local/state/nd7)
├── sessions/
│   └── <session_id>/
│       ├── events.ndjson            append-only event log, one frame per line
│       ├── head                     "<seq> <hash>\n", chain head for fast append
│       ├── lock                     empty, flock target
│       ├── shipped                  "<seq> <hash>\n", last frame the vault acked
│       └── chain.key                0600, present while the chain is open
└── vault/                           only on an enrolled machine, all 0600
    ├── machine.key                  Ed25519 seed, signs every request
    ├── machine.id                   vault-assigned id
    ├── server                       base URL
    └── recipients                   pinned admin public keys, signed
```

`shipped`, `chain.key` and the `vault` directory appear only once the
machine has been enrolled with a vault; see "Shipping to a vault" below.

`session_id` is used verbatim as the directory name. Claude Code session ids
are UUIDs (verify: format is not documented, only shown as `abc123` in
examples). The writer rejects ids containing path separators or `..`.

Why per-session files, not one big log: sessions are the unit of reading,
shipping and deleting. Per-session files make `show`, `verify`, retention and
upload trivially scoped and let concurrent sessions never contend.

Why XDG state, not data or cache: this is machine-local state that should
survive reboots but is not user-authored data and is not safely discardable.
nono uses the same location class for its audit logs.

## Reader: `nd7 show`, `nd7 sessions`, `nd7 verify`

- `sessions`: list session directories with first/last timestamp, event count
  and cwd of the first event.
- `show <id>`: stream the file, decode frames, print a timeline. One line per
  event by default (time, kind, summary), `-v` for full payloads, `--json` for
  raw frames. Pairs `tool_call`/`tool_result` via `tool_use_id` to show
  durations and statuses inline.
- `verify <id>`: recompute the chain from the first frame and report the first
  divergence, if any. In Phase 1 this proves only that the file has not been
  edited since it was written by *this* machine; anyone with write access can
  rewrite the whole chain. Signing (Phase 2+) closes that gap. The reader says
  so in its output. Implemented: checks, in order, that each line is a sealed
  frame, that its hash matches its bytes, that `seq` matches its position,
  that `prev` matches the previous hash (genesis: BLAKE3 of the session id),
  then compares the tail to `head`; stops at the first failure and exits 1.

The reader is the only component that reads the log. Nothing in the hook path
depends on it.

## Shipping to a vault: `nd7 enroll`, `nd7 ship`

A second reader of the log, and the only component that uses the network.
`enroll` binds the machine to a vault: it generates an Ed25519 signing key,
checks the vault's admin public keys against the fingerprint in the
enrolment token, and stores the four files above. `ship` encrypts every
frame the vault has not acknowledged, in batches of at most 8 MiB, to a
per-chain key wrapped to those admin keys, and pushes them; the vault sees
ciphertext, hashes and timestamps and never plaintext. It runs the same
`verify_segment` the reader does over each batch before encrypting it, and
stops the session rather than shipping anything that does not verify.

`vault` holds the wire format and the cryptography, and is pure: no
sockets, no files, no clock, so the server can depend on it. `ship` holds
the filesystem and the network. Nothing in the hook path depends on either,
and `nd7 record` never opens a socket. The contract, the algorithm and the
acceptance tests are [VAULT.md](VAULT.md).

## Where future sources attach

Every producer, present or future, builds the same `Event` struct and hands it
to the same writer. The writer does not know or care about `source`. This is
the whole seam:

- **Codex / other agents**: a new `nd7 record --from codex` (or a separate
  subcommand) parses a different payload into the same event kinds with
  `source: intent:codex`.
- **Kernel effects**: a long-running `nd7 collector` subscribes to Endpoint
  Security (macOS) or fanotify/seccomp-notify (Linux), attributes events to a
  process tree, and appends `effect:*` events to the session whose intent
  events it matches. The match uses the join keys stored since Phase 1:
  timestamp window, cwd, argv, and the hook process's parent pid.
- **Remote hosts**: a remote `nd7` appends to a local log with the same
  `session_id` and the local reader merges the two files by timestamp. The
  frame format carries `host` in the envelope from Phase 1 for this reason.

Things Phase 1 must *not* do because they would make these harder:

- Put agent-specific field names in the envelope. Everything Claude Code
  specific lives inside the event body.
- Assume one process appends to a session. Hence the lock and `head` file.
- Assume the log is read on the machine that wrote it. Hence self-describing
  frames and absolute paths recorded as given, not normalized.
