# Phase 1 milestones

Each milestone is one sitting. Each ends with something runnable. Order
matters only where noted.

- [~] **M0. Settle the schema and frame format.** (ADR-0002 settled `PostToolUseFailure`, `Stop`, NDJSON, exec form; content policy and genesis binding still open) Decide the open questions in
  [SCHEMA.md](SCHEMA.md) §5–6, record them in DECISIONS.md, mark the schema
  `v0`. No code.

- [x] **M1. One event in, one event out.** (2026-09-18; `nd7 show` pending, see M5) `cargo new nd7`. `nd7 record` reads
  stdin, parses the common hook fields plus `hook_event_name`, builds an
  envelope with `seq`, `ts`, `source`, `kind`, appends one NDJSON line to
  `$XDG_STATE_HOME/nd7/sessions/<id>/events.ndjson`. `nd7 show <id>` prints
  each line as `ts  kind  summary`. No hashing, no locking yet. Test by piping
  the docs' example `PreToolUse` JSON into it.

- [~] **M2. Install into a real Claude Code session.** (installed globally in exec form 2026-09-18; `Bash` response shape and `hook_ppid` verified in SCHEMA.md; `Write`/`Edit`/`Read` fixtures still to capture) Add the settings.json
  snippet, run a short session, read it back. Capture real payloads for
  `PostToolUse` (`tool_response` shape for `Bash`, `Edit`, `Read`),
  `SessionStart`, `SessionEnd`, `Stop` into `docs/payloads/` as fixtures.
  Resolve every `(verify)` in SCHEMA.md that a real payload can answer,
  including `hook_ppid`.

- [x] **M3. All Phase 1 event kinds.** (2026-09-18; tests use the docs' examples, real-payload fixtures pending M2) Typed bodies for `session_start`,
  `prompt`, `tool_call`, `tool_result`, `session_end`, `turn_end`, plus the
  `hook` catch-all. Hoist `argv` and `paths`. Unit tests from the fixtures.

- [x] **M4. Hash chain.** (2026-09-18/19: flock, head sidecar, BLAKE3 prev/hash with genesis bound to session_id, verify, and stale-head repair; every ChainError variant has a mutation test) `prev`/`hash` with BLAKE3, `head` sidecar, `flock`
  on append, stale-head repair. `nd7 verify` recomputes the chain and prints
  the trust caveat. Test: tamper with a byte, verify fails at the right seq.

- [ ] **M5. Reader worth reading.** `nd7 sessions`, `show` pairing
  `tool_call`/`tool_result` by `tool_use_id` with durations, `-v` for full
  payloads, `--json` for raw frames, colour off when not a TTY.

- [x] **M6. Never slow the agent.** (measured 2026-09-19, see BENCHMARKS.md: record ~5.0 ms wall of which ~3.4 ms is process spawn, O(1) in log size; verify 470 MB/s; error paths exit 0 with one stderr line) Measure `nd7 record` wall time on a 1k-event
  session (target: p99 under 5 ms on this laptop). Confirm behaviour when the
  state dir is unwritable, stdin is empty, JSON is malformed: stderr line, exit
  0. Confirm `SessionEnd` fits the 1.5 s budget.

- [ ] **M7. Size check.** Record a realistic hour-long session. Report bytes
  per event and total. Decide whether the content policy from M0 holds or
  needs revisiting. Record numbers in DECISIONS.md.

- [ ] **M8. Release hygiene.** `cargo install` works from a clean checkout,
  `--help` is accurate, README install steps verified end to end, CI runs
  tests on macOS and Linux, licence file chosen.

Deferred to Phase 2 (not on this list): signing, compression, interning,
binary container, Codex adapter, a long-running writer daemon (ADR-0003).
`PostToolUseFailure` was chosen in ADR-0002 and is in.

Legend: `[x]` done, `[~]` partly done with the remainder noted, `[ ]` not started.
