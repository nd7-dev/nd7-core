# Vision

`nd7` answers one question about an AI coding agent: *what did it do?* Today
the honest answer is "whatever the transcript says it did", which is the agent's
own account. We want an independent record: compact, tamper-evident, readable
by a human, and consumable by tools that enforce policy or undo damage.

The work is staged so that each phase produces something useful on its own and
each later phase is *generated from* the data of the earlier ones.

## Phase 1: Audit (intent)

Record what the agent intended, as reported by the agent runtime. For Claude
Code this is the hook stream: prompts, tool calls with full inputs, tool
results, session boundaries. Each event is stamped, sequenced and hash-chained
with BLAKE3 into an append-only per-session log.

This is deliberately the weakest form of evidence. A hook-recorded command is
what the agent *said* it would run. The log marks every event with its
`source` so no reader can mistake intent for effect.

Why start here: it needs no privileges, works on every platform Claude Code
runs on, ships in days, and forces the schema and storage decisions that
everything else depends on. Codex and other agents attach at the same layer
with a different `source` value.

## Phase 2: Audit (effects)

Observe what actually happened, attributed to the agent's process tree, from
the kernel:

- macOS: Endpoint Security (process exec/fork/exit, file open/write/rename/
  unlink, network via the Network Extension API where needed).
- Linux: fanotify for file events, seccomp-notify or eBPF for exec and
  network, chosen per kernel version.

Effect events land in the *same* session log as intent events, with
`source: effect:*`. The join keys stored since Phase 1 (timestamp, cwd, argv,
process identifiers where available) let a reader line up "agent said `rm -rf
build/`" with "process 4812, child of the agent, unlinked 213 files under
`/home/me/proj/build`". Where they disagree, the log shows it.

## Phase 2b: Cross-machine continuity

Agents SSH into other hosts. When they do, the session should continue there:
a remote `nd7` instance records with `source: effect:remote` (or intent, if
the agent runtime moves too) and streams or ships events back so the session
remains one timeline under one `session_id`. This is why `session_id` is the
top-level key and why the frame format must be streamable.

## Phase 3: Enforcement

Once we have recorded sessions we can *derive* confinement instead of writing
it by hand: which paths a workflow touched, which hosts it connected to, which
binaries it executed. Those become Seatbelt profiles on macOS and Landlock
rulesets on Linux, plus credential proxying and network filtering. Policies
generated from observed behaviour are tighter and less wrong than hand-written
ones, and the log tells you exactly why each rule exists.

## Phase 4: Undo

Revert what an agent did. File contents first, via pre-image snapshots taken
at the moment an effect event shows a write is about to happen (not a
whole-tree snapshot at session start). Later, service and system state:
restore the config *and* reload nginx. The log must report honestly what
cannot be reversed: a sent email, a pushed commit, a deleted remote branch.

## Why this order

Observe, then enforce, then undo. Enforcement without observation means
hand-written allow-lists that are either too loose or break the agent. Undo
without observation means whole-session snapshots that cannot tell you which
change was the agent's. Observation is the cheapest to build, the least
intrusive to run, and the input to both of the others.

The competitor we measure against, nono, started from the opposite end
(confine first, log decisions). See [COMPETITIVE-NOTES.md](COMPETITIVE-NOTES.md).

## Open core

The engine (recorder, format, reader, verifier, later the kernel collectors
and policy generators) is open source. A future paid product is
per-organization secure storage, access control and search over these logs.

Consequences for the code now:

- The log format is the contract and must be stable, versioned, streamable
  and self-describing from day one. Every frame says what schema it is.
- Nothing in the open engine may assume a server exists. Local files are the
  first-class store; upload is a later, separate component.
- Signing, compression and dictionary interning are designed for in the
  format (reserved fields, versioning) but not implemented in Phase 1.
