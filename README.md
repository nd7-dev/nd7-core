# nd7

A flight recorder for AI coding agents. `nd7` records what an agent did during a
session (first what it *intended* to do, later what *actually happened* on the
machine) in a compact, append-only, hash-chained log that a human can read
afterwards and that tooling can act on. The engine is open source; the log
format is the contract.

## Phase 1: what this repo does today

- A library crate, `nd7_core`, and one binary, `nd7`, whose `record` command
  is what Claude Code hooks call.
- Every hook invocation reads the hook JSON from stdin, parses it into a typed
  model of all 33 documented Claude Code hook events, transforms it into one
  nd7 event, and appends it as one NDJSON line to the session's log under an
  XDG state directory.
- Appends are serialized with an advisory lock per session, so Claude Code's
  parallel tool calls cannot produce duplicate sequence numbers. Verified by a
  test that fires 40 hook processes at one session at once.
- Six event kinds have typed bodies: `session_start`, `prompt`, `tool_call`,
  `tool_result` (success and failure), `session_end`, `turn_end`. Every other
  hook event is kept whole under `kind: hook`, so a Claude Code upgrade never
  loses data.
- Frames are hash-chained. Each frame ends with its BLAKE3 `hash`, computed
  over the exact bytes written, and carries `prev`, the hash of the frame
  before it; the first frame's `prev` is the hash of the session id. A `head`
  sidecar holds the last `seq` and `hash`, so an append reads two small files
  instead of scanning the log.
- `nd7 verify <session-id>` walks the chain and exits 1 at the first break,
  naming the frame. Each frame is checked independently against its own bytes
  and the previous frame's stored hash, so the walk can be parallelised later
  without changing the checks. `append` repairs a `head` left one frame behind
  by an interrupted write, and refuses to append onto any other
  inconsistency.

Not there yet: the reader (`sessions`, `show`). See
[docs/PHASE-1.md](docs/PHASE-1.md).

Phase 1 records **intent only**: what Claude Code said it was about to do and
what it reported back. It is not proof of what ran on the machine. See
[docs/VISION.md](docs/VISION.md) for where kernel-observed effects, remote
hosts, enforcement and undo fit in.

Non-goals right now: Endpoint Security, Seatbelt, enforcement, undo, remote
hosts, server, UI, a daemon.

## Install

Build and put the binary on your `PATH`:

```sh
cargo install --path .
```

For development, symlink `~/.cargo/bin/nd7` to `target/debug/nd7` instead.
Hooks are spawned fresh per event, so every `cargo build` is picked up by the
next hook without restarting Claude Code.

Register the hook in your Claude Code settings (`~/.claude/settings.json` for
all projects, or `.claude/settings.json` in a project). Use **exec form**
(`command` plus `args`): it skips the `sh -c` wrapper, which we measured at
about 6 ms per hook, and it makes the recorded parent pid the `claude` process
itself rather than an intermediate shell. One entry per event you want:

```json
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "PreToolUse":         [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "PostToolUse":        [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "PostToolUseFailure": [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "Stop":               [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "SessionEnd":         [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 1 }] }]
  }
}
```

Any of the other documented events (`SubagentStart`, `SubagentStop`,
`Notification`, `PreCompact`, `CwdChanged`, …) can be added the same way and
will be recorded as `kind: hook`. Two are worth leaving out unless you need
them: `MessageDisplay` fires per batch of streamed assistant text and was 37%
of all frames in a test session, and `PostToolBatch` repeats every tool
response of a batch.

Notes, from the Claude Code hooks reference (https://code.claude.com/docs/en/hooks):

- Omitting `matcher` matches every tool. `timeout` is in seconds.
- A hook that exits non-zero (other than 2) or times out does not block the
  agent; the action proceeds. `nd7 record` never prints to stdout, so it cannot
  make a control decision.
- `SessionEnd` hooks share a 1.5 s budget, hence the shorter timeout.
- Hook payloads carry no timestamp; `nd7` stamps events at invocation time,
  before reading stdin.

## Read a session

Logs live in `$XDG_STATE_HOME/nd7/sessions/<session-id>/` (default
`~/.local/state/nd7/sessions/`), one `events.ndjson` plus a `lock` file per
session. Until the reader exists, standard tools work:

```sh
ls ~/.local/state/nd7/sessions/
tail -f ~/.local/state/nd7/sessions/<session-id>/events.ndjson \
  | jq -c '{seq, kind, ev: .body.hook_event_name, tool: .body.tool_name}'
```

```sh
nd7 verify <session-id>   # recompute the hash chain, exit 1 at the first break
```

A clean result proves only that the log has not been edited since its last
frame was written by this machine; anyone with write access could still
rewrite the whole chain.

Planned commands, not yet implemented:

```sh
nd7 sessions              # list recorded sessions, newest first
nd7 show <session-id>     # human-readable timeline
nd7 show <session-id> --json   # raw events, one per line
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the layout and
[docs/SCHEMA.md](docs/SCHEMA.md) for the event format.

## Layout

```
src/lib.rs            nd7_core: everything the binaries share
src/hook/input.rs     typed model of every Claude Code hook payload (FromStr)
src/hook/event.rs     the nd7 envelope and body
src/hook/invocation.rs  invocation facts: ts, host, parent pid. Event::new joins them
src/session_log.rs    the per-session append-only log: lock, head, chain, verify
src/bin/nd7.rs        the command line; `record` is parse, transform, append
tests/                multi-process concurrency test against the real binary
bench/                reproducible record/verify benchmark (Python, stdlib only)
```

The hook path is plain blocking I/O with no async runtime; see ADR-0003 for
the measurements behind that and behind not running a daemon.

## Documents

- [docs/VISION.md](docs/VISION.md): the four-phase roadmap and the open-core model.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Phase 1 components and where future sources attach.
- [docs/SCHEMA.md](docs/SCHEMA.md): event envelope, event kinds, frame format options.
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md): measured cost of record and verify, and how to rerun.
- [docs/PHASE-1.md](docs/PHASE-1.md): milestone checklist.
- [docs/DECISIONS.md](docs/DECISIONS.md): decision log.
- [docs/COMPETITIVE-NOTES.md](docs/COMPETITIVE-NOTES.md): comparison with nono.

## Status

Pre-alpha. The schema is a draft and will change until it is marked `v1`.
Frames carry `prev` and `hash`, and `nd7 verify` checks them.
