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

