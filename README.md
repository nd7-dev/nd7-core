# nd7

A flight recorder for AI coding agents. `nd7` records what an agent did during a
session (first what it *intended* to do, later what *actually happened* on the
machine) in a compact, append-only, hash-chained log that a human can read
afterwards and that tooling can act on. The engine is open source; the log
format is the contract.

## Phase 1: what this repo does today

- A small Rust binary, `nd7`, invoked by Claude Code hooks.
- Each hook invocation reads the hook JSON from stdin and appends one event to
  the session's log under an XDG state directory.
- Events are BLAKE3 hash-chained, so truncation or edits are detectable.
- `nd7 show <session-id>` prints a session as a human-readable timeline.

Phase 1 records **intent only**: what Claude Code said it was about to do and
what it reported back. It is not proof of what ran on the machine. See
[docs/VISION.md](docs/VISION.md) for where kernel-observed effects, remote
hosts, enforcement and undo fit in.

Non-goals right now: Endpoint Security, Seatbelt, enforcement, undo, remote
hosts, server, UI.

## Install

Build and put the binary on your `PATH`:

```sh
cargo install --path .
```

Add the hooks to your Claude Code settings (`~/.claude/settings.json` for all
projects, or `.claude/settings.json` in a project). Each entry runs `nd7 hook`,
which reads the event from stdin and returns immediately.

```json
{
  "hooks": {
    "SessionStart":     [{ "hooks": [{ "type": "command", "command": "nd7 hook", "timeout": 5 }] }],
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "nd7 hook", "timeout": 5 }] }],
    "PreToolUse":       [{ "hooks": [{ "type": "command", "command": "nd7 hook", "timeout": 5 }] }],
    "PostToolUse":      [{ "hooks": [{ "type": "command", "command": "nd7 hook", "timeout": 5 }] }],
    "Stop":             [{ "hooks": [{ "type": "command", "command": "nd7 hook", "timeout": 5 }] }],
    "SessionEnd":       [{ "hooks": [{ "type": "command", "command": "nd7 hook", "timeout": 1 }] }]
  }
}
```

Notes, from the Claude Code hooks reference (https://code.claude.com/docs/en/hooks):

- Omitting `matcher` matches every tool. `timeout` is in seconds.
- A hook that exits non-zero (other than 2) or times out does not block the
  agent; the action proceeds. `nd7 hook` always exits 0 and never prints
  decisions, so it cannot interfere with the session.
- `SessionEnd` hooks share a 1.5 s budget, hence the shorter timeout.
- Hook payloads carry no timestamp; `nd7` stamps events at invocation time.

The `Stop` hook is optional. It gives a turn boundary and the last assistant
message; drop it if you want a smaller log.

## Read a session

```sh
nd7 sessions              # list recorded sessions, newest first
nd7 show <session-id>     # human-readable timeline
nd7 show <session-id> --json   # raw events, one per line
nd7 verify <session-id>   # recompute the hash chain
```

Logs live in `$XDG_STATE_HOME/nd7/sessions/<session-id>/` (default
`~/.local/state/nd7/sessions/`). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the layout and [docs/SCHEMA.md](docs/SCHEMA.md) for the event format.

## Documents

- [docs/VISION.md](docs/VISION.md): the four-phase roadmap and the open-core model.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Phase 1 components and where future sources attach.
- [docs/SCHEMA.md](docs/SCHEMA.md): event envelope, event kinds, frame format options.
- [docs/PHASE-1.md](docs/PHASE-1.md): milestone checklist.
- [docs/DECISIONS.md](docs/DECISIONS.md): decision log.
- [docs/COMPETITIVE-NOTES.md](docs/COMPETITIVE-NOTES.md): comparison with nono.

## Status

Pre-alpha. The schema is a draft and will change until it is marked `v1`.
