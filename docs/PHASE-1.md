# Phase 1 milestones

Each milestone is one sitting. Each ends with something runnable. Order
matters only where noted.

- [x] **M0. Settle the schema and frame format.** (ADR-0002 settled `PostToolUseFailure`, `Stop`, NDJSON, exec form; genesis binding decided 2026-09-19; content policy decided 2026-09-19, stored verbatim, ADR-0006) Decide the open questions in
  [SCHEMA.md](SCHEMA.md) §5–6, record them in DECISIONS.md, mark the schema
  `v0`. No code.

- [x] **M1. One event in, one event out.** (2026-09-18; `nd7 show` never landed and is dropped with M5) `cargo new nd7`. `nd7 record` reads
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

- [-] **M5. Reader worth reading.** Dropped 2026-09-19 by the owner's
  decision: the consumers of the log are a program, policy derivation, and
  the vault viewer, not a terminal timeline. `nd7 sessions`, `show` pairing
  `tool_call`/`tool_result` by `tool_use_id` with durations, `-v` for full
  payloads, `--json` for raw frames, colour off when not a TTY.

- [x] **M6. Never slow the agent.** (measured 2026-09-19, see BENCHMARKS.md: record ~5.0 ms wall of which ~3.4 ms is process spawn, O(1) in log size; verify 470 MB/s; error paths exit 0 with one stderr line) Measure `nd7 record` wall time on a 1k-event
  session (target: p99 under 5 ms on this laptop). Confirm behaviour when the
  state dir is unwritable, stdin is empty, JSON is malformed: stderr line, exit
  0. Confirm `SessionEnd` fits the 1.5 s budget.

- [x] **M7. Size check.** (numbers in SCHEMA.md §6: a 116-event working
  session of about 1.5 h, median frame 1.5 KB, largest 49.7 KB, 365 KB
  total; the largest session recorded since is 1487 frames over about ten
  hours, 4.8 MB uncompressed. The content policy from M0 holds; ADR-0006.)
  Record a realistic hour-long session. Report bytes
  per event and total. Decide whether the content policy from M0 holds or
  needs revisiting. Record numbers in DECISIONS.md.

- [~] **M8. Release hygiene.** (CI added 2026-09-19 in both repos: `cargo
  fmt --check`, `cargo clippy --all-targets -- -D warnings` and `cargo test`
  on ubuntu-latest and macos-latest, plus the viewer's Node test in
  nd7-vault. Still open: choose a licence — there is no LICENSE file in
  either repo and both READMEs say so.) `cargo install` works from a clean
  checkout, `--help` is accurate, README install steps verified end to end,
  CI runs tests on macOS and Linux, licence file chosen.

- [~] **M9. Ship to a vault.** (2026-09-19. The contract is
  [VAULT.md](VAULT.md), owned here. `nd7 enroll` and `nd7 ship` are in
  `src/ship.rs` over `src/vault/`; the server and the browser viewer are in
  `../nd7-vault`, where the admin CLI is landing as this is written. What is
  left after it is the acceptance run of VAULT.md §10 end to end against a
  real vault and a real `nd7`, and whatever it finds.) A local chain is evidence only once a copy of it lives
  where the recording agent has no credentials; the vault holds that copy as
  ciphertext it can link but not read.

Deferred to Phase 2 (not on this list): signing, compression, interning,
binary container, Codex adapter, a long-running writer daemon (ADR-0003).
`PostToolUseFailure` was chosen in ADR-0002 and is in.

Legend: `[x]` done, `[~]` partly done with the remainder noted, `[ ]` not
started, `[-]` dropped with the reason noted.
