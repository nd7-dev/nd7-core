# nd7

A flight recorder for AI coding agents. `nd7` records what an agent did during a
session (first what it *intended* to do, later what *actually happened* on the
machine) in a compact, append-only, hash-chained log that a human can read
afterwards and that tooling can act on. The engine is open source; the log
format is the contract.

## Phase 1: what this repo does today

- A library crate, `nd7_core`, and one binary target, `nd7audit`, invoked by
  Claude Code hooks as `nd7 hook`.
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

Not there yet, in order of arrival: repair of a missing or stale `head` on an
existing log, the `verify` command, and the reader (`sessions`, `show`). See
[docs/PHASE-1.md](docs/PHASE-1.md).

Phase 1 records **intent only**: what Claude Code said it was about to do and
what it reported back. It is not proof of what ran on the machine. See
[docs/VISION.md](docs/VISION.md) for where kernel-observed effects, remote
hosts, enforcement and undo fit in.

Non-goals right now: Endpoint Security, Seatbelt, enforcement, undo, remote
hosts, server, UI, a daemon.

## Install

Build and put the binary on your `PATH` under the name `nd7`:

```sh
cargo build --release
ln -s "$PWD/target/release/nd7audit" ~/.cargo/bin/nd7
```

For development, point the symlink at `target/debug/nd7audit` instead. Hooks
are spawned fresh per event, so every `cargo build` is picked up by the next
hook without restarting Claude Code.

Register the hook in your Claude Code settings (`~/.claude/settings.json` for
all projects, or `.claude/settings.json` in a project). Use **exec form**
(`command` plus `args`): it skips the `sh -c` wrapper, which we measured at
about 6 ms per hook, and it makes the recorded parent pid the `claude` process
itself rather than an intermediate shell. One entry per event you want:

```json
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 5 }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 5 }] }],
    "PreToolUse":         [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 5 }] }],
    "PostToolUse":        [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 5 }] }],
    "PostToolUseFailure": [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 5 }] }],
    "Stop":               [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 5 }] }],
    "SessionEnd":         [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["hook"], "timeout": 1 }] }]
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
  agent; the action proceeds. `nd7 hook` never prints to stdout, so it cannot
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

Planned commands, not yet implemented:

```sh
nd7 sessions              # list recorded sessions, newest first
nd7 show <session-id>     # human-readable timeline
nd7 show <session-id> --json   # raw events, one per line
nd7 verify <session-id>   # recompute the hash chain
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the layout and
[docs/SCHEMA.md](docs/SCHEMA.md) for the event format.

## Layout

```
src/lib.rs            nd7_core: everything the binaries share
src/hook/input.rs     typed model of every Claude Code hook payload (FromStr)
src/hook/event.rs     the nd7 envelope and body
src/hook/invocation.rs  invocation facts: ts, host, parent pid. Event::new joins them
src/writer.rs         the per-session append-only log, lock included
src/bin/nd7audit.rs   the hook binary: parse, transform, append
tests/                multi-process concurrency test against the real binary
```

The hook path is plain blocking I/O with no async runtime; see ADR-0003 for
the measurements behind that and behind not running a daemon.

## Documents

- [docs/VISION.md](docs/VISION.md): the four-phase roadmap and the open-core model.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Phase 1 components and where future sources attach.
- [docs/SCHEMA.md](docs/SCHEMA.md): event envelope, event kinds, frame format options.
- [docs/PHASE-1.md](docs/PHASE-1.md): milestone checklist.
- [docs/DECISIONS.md](docs/DECISIONS.md): decision log.
- [docs/COMPETITIVE-NOTES.md](docs/COMPETITIVE-NOTES.md): comparison with nono.

## Status

Pre-alpha. The schema is a draft and will change until it is marked `v1`.
Frames carry `prev` and `hash`; nothing verifies them yet, `verify` is next.
