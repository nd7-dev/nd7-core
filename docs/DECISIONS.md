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
