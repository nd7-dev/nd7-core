# Decisions

One entry per settled decision, newest last. Never edit an accepted entry;
supersede it with a new one and link both ways.

## Template

```
## ADR-NNNN: <short title>

- Date: YYYY-MM-DD
- Status: proposed | accepted | superseded by ADR-MMMM

### Context
What forced the decision. Facts, constraints, links.

### Decision
What we chose, in one or two sentences.

### Alternatives considered
Each with the reason it lost.

### Consequences
What becomes easier, what becomes harder, what we must revisit and when.
```

---

## ADR-0001: Start with hooks-captured intent, kernel effects later

- Date: 2026-09-17
- Status: accepted

### Context

The goal is an independent record of what an AI coding agent did. The
strongest evidence is kernel-observed effects (Endpoint Security on macOS,
fanotify/seccomp-notify on Linux) attributed to the agent's process tree. The
weakest is the agent runtime's own account of its intent, exposed by Claude
Code through hooks that deliver a JSON payload per event.

Kernel collection needs entitlements or root, a long-running daemon, per-OS
code, and a process-attribution model. Hook collection needs a settings.json
entry and a binary that reads stdin.

The competitor we compare against, nono, went the other way: confine first,
and log policy decisions and session boundaries rather than operations
(see COMPETITIVE-NOTES.md).

### Decision

Phase 1 records intent only, from Claude Code hooks, into the final log
format. Every event carries a `source` that names its evidence class
(`intent:*` vs `effect:*`), and the schema stores the join keys (`ts`, `cwd`,
`argv`, `paths`, `hook_ppid`, `tool_use_id`, `host`) that kernel attribution
will need, so effect events can be added to the same log without a format
change.

### Alternatives considered

- **Kernel effects first.** Stronger evidence, but weeks before a first
  readable session, platform-specific from day one, and the schema would be
  designed without seeing what agents actually do. Lost on time to feedback.
- **Both at once.** Doubles the surface while the schema is still moving.
- **Intent only, forever (a transcript exporter).** Cheap, but it is just a
  restatement of the agent's own transcript and cannot support enforcement or
  undo. Lost on vision.

### Consequences

- Easier: ships in days, runs anywhere Claude Code runs, forces the schema and
  storage decisions early and against real data.
- Harder: every Phase 1 claim must be qualified. The log and the reader must
  say "intent, not effect" explicitly, or users will over-trust it.
- Must revisit: when the first effect source lands, check that the join keys
  chosen here are sufficient. If a key is missing (likely candidates: the
  agent's own pid rather than the hook's ppid, or a per-tool-call nonce in
  the environment), add it in a minor schema version.

## ADR-0002: Phase 1 hook set, frame writer and registration form

- Date: 2026-09-18
- Status: accepted

### Context
SCHEMA.md §6 left four questions open that blocked writing the first frames:
whether to subscribe to `PostToolUseFailure`, whether `Stop` is default,
which frame format the writer emits, and (found while installing) how the
hook must be registered for `hook_ppid` to be useful.

### Decision
Subscribe to `PostToolUseFailure` and record it as `tool_result` with
`ok: false` and the `error` string as `tool_response`. Record `Stop` as
`turn_end` by default. Write NDJSON frames now (SCHEMA.md §5 option A), with
option C, a packed container produced from the same bytes, as the stated
plan. Register the hook in exec form (`"command": "nd7", "args": ["hook"]`).

### Alternatives considered
- Ignore `PostToolUseFailure`: silent gaps where a command failed; the success
  response carries no exit code (verified), so failures would be invisible.
- `Stop` opt-in: loses the turn boundary that groups tool calls for readers.
- Binary frames from day one: nothing standard reads them while the schema is
  still moving.
- Shell-form registration: measured ~6 ms extra per hook for `sh -c`, and
  `hook_ppid` becomes the shell's pid instead of the agent's.

### Consequences
- Easier: every failed command is in the log with its exit code; readers can
  pair call/result by `tool_use_id` and show status.
- Harder: `last_assistant_message` and `bashEditDiff` make frames large;
  the content policy (SCHEMA.md §6.1) must be decided before M7.
- Must revisit: when the packed container lands, hashes must be computed over
  the NDJSON bytes so packing does not change them.

## ADR-0003: Library plus thin binaries, no async runtime, no daemon

- Date: 2026-09-18
- Status: accepted

### Context
The first binary used a tokio runtime and a spawned thread for a blocking
stdin read and one file append. While installing the hook we asked whether a
long-running daemon holding the log's file descriptor would cut latency, and
measured where a hook invocation actually spends its time on this laptop
(debug build, 200 iterations, ~0.4 ms loop overhead included):

| step | cost |
|---|---|
| spawn any process | ~3.6 to 3.9 ms |
| `sh -c` wrapper (shell-form registration) | ~6 ms on top |
| nd7 startup, stdin, parse, runtime init | ~3 ms on top |
| open, append, close the log | ~1 ms |
| counting lines for `seq` on a 5k-line log | ~8 ms on top |

A `nc` client that only spawns and connects to a socket cost ~8 ms, the same
as the whole nd7 binary. A release build was not measurably faster.

### Decision
Structure the crate as a library, `nd7_core`, with thin binary targets
(`nd7audit` first). Use plain blocking std I/O in the hook path; no tokio.
Do not build a daemon for latency. Register hooks in exec form. Remove the
seq scan with the `head` sidecar (M4) rather than with a resident process.

### Alternatives considered
- **Daemon with a thin client.** Saves at most the ~1 ms append; the client
  still pays spawn and connect. Adds lifecycle, crash durability (buffered
  events lost, or an ack round trip), and version skew: the daemon keeps old
  code in memory, which breaks the rebuild-and-go workflow.
- **Keep tokio.** Nothing in the hook is concurrent; the runtime is startup
  cost and binary size for no work.
- **`async: true` hooks.** Removes the wait from the agent entirely but `-p`
  sessions kill async hooks at teardown and completion order is not
  guaranteed. Kept as an option for noisy, low-value events only.

### Consequences
- Easier: the binary is ten lines; every `cargo build` is live on the next
  hook; the writer is reusable by any producer.
- Harder: nothing. The seam for a future single-writer daemon is the
  `SessionLog` type: a socket-backed implementation with a build-id handshake
  and direct-write fallback fits behind it when the Phase 2 collector arrives.
- Must revisit: after `head` lands, remeasure against the 5 ms p99 target.

## ADR-0004: One binary, `nd7`, with `record` as the hook command

- Date: 2026-09-19
- Status: accepted; refines the naming in ADR-0002 and ADR-0003

### Context
ADR-0003 introduced a library plus thin binaries and named the first binary
`nd7audit`, installed on `PATH` as `nd7` through a symlink, with `hook` as
its only subcommand. Once `verify`, `sessions` and `show` were in sight it
was clear there is one user-facing tool, not several, and that `hook`
described how Claude Code calls us rather than what we do.

### Decision
The binary is `nd7`. Its subcommands are verbs: `record` (what hooks call),
`verify`, `sessions`, `show`. `hook` remains an accepted alias of `record`
until M8. Other kinds of program that arrive later, such as the Phase 2
collector daemon, get their own names (`nd7d` or `nd7-collector`) rather
than becoming faces of the CLI.

### Alternatives considered
- Keep `nd7audit` and the symlink: one more install step and a name that
  does not match what users type.
- Keep `hook` as the command: accurate for Claude Code, wrong for the Codex
  and collector producers that will feed the same writer.

### Consequences
- `cargo install --path .` yields `nd7` directly; the README loses the
  symlink step.
- `nd7 record` always exits 0, reporting failures on stderr, as the
  architecture requires; unknown commands exit 2 with usage.
- ADR-0002 and ADR-0003 keep their original wording per this log's rule.


---

## ADR-0005: Ship logs to a vault the machine encrypts for, not the vault

- Date: 2026-09-19
- Status: proposed

### Context
The hash chain proves a log is unchanged only if the verifier trusts the
head; whoever can write the file can rewrite the chain. A prompt copy on a
server the agent cannot reach turns the chain into evidence. The frames hold
everything the agent saw, including secrets, so a stolen server or a
compromised operator must yield nothing readable, and a single leaked key
must not expose more than one organisation.

### Decision
`nd7 ship` batches unshipped frames per session, verifies them locally,
compresses, and encrypts each batch with a per-chain key wrapped to the
public keys of the organisation's admins. The server, `nd7-vault`
(separate repo), stores ciphertext plus a clear index of `seq`, `prev`,
`hash`, `ts`, verifies chain linkage only, and never holds a decryption key.
Machines authenticate with a per-machine Ed25519 key that signs every
request over HTTPS. Admins log in through pluggable providers (OIDC first);
no passwords are stored. The full contract is [VAULT.md](VAULT.md).

### Alternatives considered
- Server-side encryption under a vault master key: one key opens
  everything; a dumped database plus that key is total loss.
- Per-organisation key held by the server: still readable by the operator
  and by anyone with the database and the key file.
- One request per frame: hundreds of round trips per session for no gain;
  frames stay the addressable unit, batches the transfer unit.
- Shipping from inside the hook: network in a path budgeted in milliseconds.
- Password login with Argon2id: another secret to protect and the wrong
  shape for organisations that already have an identity provider.

### Consequences
- The vault cannot check that a frame's bytes hash to its `hash`; only the
  machine (before shipping) and the admin (after decrypting) can. Linkage
  checks on the index still catch every local rewrite on the next push.
- This repo grows a `vault` module with the batch format, crypto and
  request signing, so the machine and the server share one definition.
- Admin keys open a whole organisation; the mitigations are hardware-backed
  keys, few admins, and rekeying on suspicion.
- `ts` is readable on the vault; revisit if working-hours metadata is
  itself sensitive for a deployment.
