# Competitive notes: nono

Facts below are taken from nono's public documentation as read on 2026-09-17.
Quotes are theirs. Where a page was ambiguous, that is said. This is a
comparison of documented behaviour, not a judgement of the product.

Sources:

- Product site: https://nono.sh, feature pages https://nono.sh/audit-trail
  and https://nono.sh/undo
- Audit docs: https://nono.sh/docs/cli/features/audit.md
- Rollback docs: https://nono.sh/docs/cli/features/atomic-rollbacks.md
- Enforcement internals: https://nono.sh/docs/cli/internals/seatbelt.md,
  https://nono.sh/docs/cli/internals/landlock.md,
  https://nono.sh/docs/cli/internals/overview.md
- Repository: https://github.com/nolabs-ai/nono

## What nono is

A kernel-enforced sandbox for running agents such as Claude Code, using
"Landlock (Linux) and Seatbelt (macOS)" (core overview), with composable JSON
policies for filesystem, network, credential proxying with L7 filtering, and
child sandboxes for delegated tools (README). Its starting point is
confinement.

## nono's audit trail

Per the audit docs, an audit event is "One recorded fact within that session,
such as `session_started`, `session_ended`, a capability decision, or a
supervisor-observed URL-open event." The feature page lists categories
("File reads, writes, creates, and deletes", "Network connection attempts
(allowed and denied)", "Command executions (allowed and denied)", supervisor
prompts, policy violations) and says each Merkle leaf holds "the operation
type, target, timestamp, and disposition". Note the tension: the feature page
reads like an operation log, the docs page describes decision and lifecycle
records. Either way, disposition (allowed/denied) is the central fact.

Executable identity: "Only the main executable (`argv[0]` after resolution) is
hashed. For `bash script.sh`, this commits `/bin/bash`, not `script.sh`".

Integrity: a "hash-chain head over the ordered event stream, and a Merkle root
over all recorded event leaves", committed at session end, with an optional
"keyed DSSE signature" checked by `nono audit verify`.

Storage: `$XDG_STATE_HOME/nono/audit/` with `audit-events.ndjson`
(append-only), `session.json`, optional `audit-attestation.bundle`.

CLI: `nono audit list|show|verify|cleanup`.

## nono's rollback

Per the rollback docs, nono "Takes a baseline snapshot of all files in tracked
directories before the command starts" and "Takes a final snapshot after the
command exits." Content is SHA-256 addressed and deduplicated; restore is
"atomic rename per file"; snapshots are indexed 0 (baseline) and 1 (final).
Scope is files in tracked directories, with profile and `.gitignore`
exclusions. Retention defaults: 10 sessions, 5 GB.

## Gaps we are targeting

1. **Operations, not decisions.** nono's unit of record is a policy outcome
   inside a sandbox it controls. Ours is what the agent did: every prompt,
   tool call and result now; every process, file and network operation later.
   A denied action is one row in their log; for us the interesting rows are
   the allowed ones, because that is where damage happens.

2. **Intent and effect, side by side, honestly labelled.** nono records what
   its supervisor decided. We record what the agent said (`intent:*`) and,
   later, what the kernel saw (`effect:*`), in one timeline, with the log
   stating which is which. Disagreement between the two is a finding.

3. **Per-operation undo, not per-session.** Two snapshots per session cannot
   revert the third of seven edits, and cannot tell an agent's change from a
   concurrent human one. Pre-image capture at the moment of each observed
   write can. Service and system state (reload a daemon after restoring its
   config) is out of nono's stated scope and in ours, with explicit reporting
   of what cannot be reversed.

4. **No sandbox required to get a record.** nono's trail exists only for
   commands launched through nono. Ours starts from hooks, needs no wrapper
   and no privileges, and the same log later gains kernel evidence without a
   format change. Enforcement, when we add it, is generated from recorded
   sessions rather than authored as profiles.

5. **Cross-machine sessions.** Nothing in nono's docs addresses an agent that
   SSHes elsewhere. Our `session_id` and `host` envelope fields are there for
   this from day one.

## Where nono is ahead, and what we borrow

- They enforce today; we do not, and will not for two phases.
- Their integrity story (hash chain plus Merkle root plus DSSE signature and
  `verify`) is more complete than our Phase 1 BLAKE3 chain. Our `sig` field is
  reserved for the same reason.
- Their choice of XDG state and append-only NDJSON for the raw event stream is
  sound; we make the same choice for Phase 1 independently and should not
  pretend otherwise.
- Executable-identity hashing (`argv[0]` after resolution) is a good idea for
  our effect layer and is noted for Phase 2.
