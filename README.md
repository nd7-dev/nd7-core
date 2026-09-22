# nd7

A kernel sandbox and secure audit log for AI coding agents. `nd7` records what an agent did during a
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

There is no terminal reader. The log's consumers are programs: the policy
derivation of later phases and the vault viewer. During development, `jq`
and `tail -f` on the NDJSON file are enough. See
[docs/PHASE-1.md](docs/PHASE-1.md).

Phase 1 records **intent only**: what Claude Code said it was about to do and
what it reported back. It is not proof of what ran on the machine. See
[docs/VISION.md](docs/VISION.md) for where kernel-observed effects, remote
hosts, enforcement and undo fit in.

The first piece of enforcement is in: `nd7 run claude` puts Claude Code and
everything it spawns under a kernel sandbox, with a policy you can widen
while the session runs. See [Sandbox](#sandbox-macos) below.

Non-goals right now: Endpoint Security, undo, remote hosts, server, UI, a
daemon.

## Install

macOS. You need a Rust toolchain (https://rustup.rs). One command installs
both binaries, `nd7` and `nd7-exec`, into `~/.cargo/bin`:

```sh
cargo install --locked --git https://github.com/nd7-dev/nd7-core
```

From a checkout, `cargo install --locked --path .` does the same. For
development, symlink `~/.cargo/bin/nd7` and `~/.cargo/bin/nd7-exec` to the
`target/debug/` binaries instead; hooks are spawned fresh per event, so every
`cargo build` is picked up by the next hook without restarting Claude Code.

The two binaries must stay next to each other: `nd7 run` finds `nd7-exec` by
looking beside itself, and refuses to start if it is missing or writable by
anyone but you.

Then register nd7 with the agents, once:

```sh
nd7 init                     # both; `nd7 init claude` or `nd7 init codex` for one
```

That writes into `~/.claude/settings.json` and `~/.codex/config.toml`: one
`record` hook per event, which is what the log is made of, and the `PreToolUse`
hook that routes Bash through `nd7-exec`, so `nd7 run` no longer passes it per
invocation. Everything already in those files is kept, and running it again
writes nothing; an agent with no directory of its own under `~` is skipped.
`--project` writes `.claude/settings.json` in this directory instead (Claude
Code only). It also records Codex's approval of the hooks it wrote — the hash
Codex stores when you accept them — so Codex does not ask about them at its
next start.

`nd7 init` also writes `~/.nd7/aliases.sh` —

```sh
alias claude='nd7 run claude'
alias codex='nd7 run codex'
```

— and adds one line to `~/.zshrc`, and to `~/.bashrc` if you have one, that
loads it, so typing `claude` starts a sandboxed session. `--no-alias` skips
that part. The aliases live under `~/.nd7`, which no session may write to, so
a session cannot take them away, and they do not recurse: `nd7 run` looks its
program up on `PATH`, where the shell's aliases do not reach.

Outside `nd7 run` the installed `PreToolUse` hook stays silent — there is no
session, so there is nothing to route a command through — and the `record`
hooks go on recording.

<details>
<summary>What <code>nd7 init</code> writes for Claude Code</summary>

`command` is the absolute path of the `nd7` that wrote it. That is **exec
form** (`command` plus `args`): it skips the `sh -c` wrapper, which we measured
at about 6 ms per hook, and it makes the recorded parent pid the `claude`
process itself rather than an intermediate shell.

```json
{
  "hooks": {
    "SessionStart":       [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "UserPromptSubmit":   [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "PreToolUse":         [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] },
                           { "matcher": "Bash", "hooks": [{ "type": "command", "command": "nd7 hook-prefix" }] }],
    "PostToolUse":        [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "PostToolUseFailure": [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "Stop":               [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 5 }] }],
    "SessionEnd":         [{ "hooks": [{ "type": "command", "command": "nd7", "args": ["record"], "timeout": 1 }] }]
  }
}
```

The same events go into `~/.codex/config.toml` as `[[hooks.<Event>]]` tables,
where the command is one string, `nd7 record`; Codex has no
`PostToolUseFailure`, so it gets the other six.

</details>

Any of the other documented events (`SubagentStart`, `SubagentStop`,
`Notification`, `PreCompact`, `CwdChanged`, …) can be added by hand the same
way and will be recorded as `kind: hook`. Two are worth leaving out unless you
need them: `MessageDisplay` fires per batch of streamed assistant text and was
37% of all frames in a test session, and `PostToolBatch` repeats every tool
response of a batch.

Notes, from the Claude Code hooks reference (https://code.claude.com/docs/en/hooks):

- Omitting `matcher` matches every tool. `timeout` is in seconds.
- A hook that exits non-zero (other than 2) or times out does not block the
  agent; the action proceeds. `nd7 record` never prints to stdout, so it cannot
  make a control decision.
- `SessionEnd` hooks share a 1.5 s budget, hence the shorter timeout.
- Hook payloads carry no timestamp; `nd7` stamps events at invocation time,
  before reading stdin.

## Sandbox (macOS)

```sh
cd your-project
nd7 run claude
```

That is the whole setup. `nd7 run` applies a Seatbelt profile to `claude` and
every process it spawns, then starts it with the flags it needs: a
`PreToolUse` hook that routes every Bash command through `nd7-exec`, its own
sandbox turned off (the kernel refuses a second profile anyway), and one
paragraph in the system prompt so a denial is reported as nd7's policy rather
than as Claude Code's permission rules. Nothing in your Claude Code settings
changes; the flags apply to that session only.

```sh
nd7 run codex
```

The same setup for Codex CLI: its own Seatbelt sandbox off with
`-s danger-full-access` (the kernel refuses a second profile anyway, and this
leaves Codex's approval prompts alone), the same `PreToolUse` hook, and the
same note as `developer_instructions`. Without `nd7 init` the hook is passed
per invocation, which needs `--dangerously-bypass-hook-trust` — only a hook
Codex discovered in a configuration file carries the trust hash it checks — and
Codex warns about it at every start; after `nd7 init` neither the flag nor the
warning is there. For an unattended `codex exec`, add
`-c approval_policy="never"` yourself; interactively, Codex keeps asking as it
normally does.

Any other program works the same way, `nd7 run zsh` for instance, without the
agent-specific flags.

What the session may do, from the start:

| | allowed |
|---|---|
| write | the project directory, the temp dir, `~/.claude`, `~/.codex`, Claude Code's scratch under `/private/tmp/claude-*` |
| read | everything except `~/.ssh`, `~/.aws` and `~/.nd7` |
| network | HTTPS (port 443) and DNS. `git` over HTTPS works; over SSH it does not |
| run | anything, inside the same boundary |

Widen it while the session runs, from another terminal:

```sh
nd7 allow ~/data      # writable from the next Bash command on
nd7 deny  ~/data      # taken back
```

No restart. Grants are per session and vanish when it ends. Paths under
`~/.nd7` can never be granted. If several sessions are running, add
`--session <pid>`; the pid is printed when `nd7 run` starts.

How it holds. The profile is applied once, to the whole process tree, and
the kernel lets a confined process apply no other profile, so nothing inside
can loosen it: not the model, not a compromised dependency, not Claude
Code's own sandbox. The one program allowed out is `nd7-exec`, which applies
the session's current policy to itself and becomes the shell for the command;
it takes nothing from the caller's arguments, cwd or environment, and it
refuses to run at all if it cannot find its session or its policy. A command
that skips the prefix runs under the floor, which is never wider. The full
argument, with the measurements and the alternatives that were rejected, is
in [docs/DECISIONS.md](docs/DECISIONS.md) (ADR-0007) and the spike reports
under [docs/spikes/](docs/spikes/).

Known limits: Write and Edit run inside the `claude` process, so `nd7 allow`
widens Bash but not those tools (restart `nd7 run claude --resume <id>` for
that), and Codex's `apply_patch` sees only the floor in the same way; on a
machine whose Codex policy sets `allow_managed_hooks_only`, the per-invocation
hook is refused and Codex runs under the floor alone; `ps` and `pgrep` are
denied; Seatbelt filters network by port, not hostname; Linux is Tier 2 and
not yet built.

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

## Ship to a vault

A local chain proves nothing against someone who can write the directory. A
copy on a machine the agent cannot reach does. `nd7 enroll` binds this
machine to a vault: it generates the signing key that authenticates every
request, checks the vault's admin public keys against the fingerprint
embedded in the enrolment token, and refuses to store anything if they
disagree. Nothing is sent to a vault until that succeeds, and `nd7 record`
never talks to the network either way.

```sh
nd7 enroll https://vault.example.com <token>   # --rotate to replace the key
nd7 ship                     # push everything pending, exit 0 if all acked
nd7 ship --every 30s         # loop; prefer a timer running the one-shot form
nd7 ship --prune-after 30d   # after shipping, delete fully acked sessions
```

`nd7 ship` verifies each run of unshipped frames against the chain, then
compresses and encrypts it, in batches of at most 8 MiB, to a per-session
key wrapped to the admin keys pinned at enrolment. The vault stores
ciphertext, the hashes and the timestamps; it never holds a key that opens
them. A local rewrite makes the run exit 1 naming the frame, and a chain
that has diverged from the vault's copy is reported and never resolved
automatically. The protocol, the algorithm and the threat model are
[docs/VAULT.md](docs/VAULT.md).

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the layout and
[docs/SCHEMA.md](docs/SCHEMA.md) for the event format.

## Layout

```
src/lib.rs            nd7_core: everything the binaries share
src/hook/input.rs     typed model of every Claude Code hook payload (FromStr)
src/hook/event.rs     the nd7 envelope and body
src/hook/invocation.rs  invocation facts: ts, host, parent pid. Event::new joins them
src/session_log.rs    the per-session append-only log: lock, head, chain, verify
src/vault/            wire format and cryptography shared with the vault server; pure
src/ship.rs           `enroll` and `ship`: the session directory, the vault files, the network
src/policy.rs         a session's rules, rendered as the floor and the per-command profile
src/session.rs        the directory one `nd7 run` owns, where `nd7-exec` finds its policy
src/sandbox.rs        Seatbelt: apply a profile in pre_exec, or to the calling process
src/hook_prefix.rs    the PreToolUse reply that routes a Bash command through `nd7-exec`
src/agent_config.rs   `nd7 init`: nd7's hooks in an agent's own config, and the shell aliases
src/bin/nd7.rs        the command line; `record` is parse, transform, append; `run`, `allow`, `deny`
src/bin/nd7-exec.rs   the one program the floor lets out: apply the policy, become the shell
tests/                multi-process concurrency test and a fake vault, against the real binary
bench/                reproducible record/verify benchmark (Python, stdlib only)
```

The hook path is plain blocking I/O with no async runtime; see ADR-0003 for
the measurements behind that and behind not running a daemon.

## Documents

- [docs/VISION.md](docs/VISION.md): the four-phase roadmap and the open-core model.
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): Phase 1 components and where future sources attach.
- [docs/SCHEMA.md](docs/SCHEMA.md): event envelope, event kinds, frame format options.
- [docs/VAULT.md](docs/VAULT.md): the vault protocol, its keys and its threat model.
- [docs/BENCHMARKS.md](docs/BENCHMARKS.md): measured cost of record and verify, and how to rerun.
- [docs/PHASE-1.md](docs/PHASE-1.md): milestone checklist.
- [docs/DECISIONS.md](docs/DECISIONS.md): decision log.
- [docs/COMPETITIVE-NOTES.md](docs/COMPETITIVE-NOTES.md): comparison with nono.
- [docs/spikes/](docs/spikes/): the sandbox spikes, with every measurement behind ADR-0007.

## Status

Pre-alpha. The schema is a draft and will change until it is marked `v1`.
Frames carry `prev` and `hash`, and `nd7 verify` checks them. The sandbox
is new and tested on macOS 26 with Claude Code 2.1.x; the policy will
tighten as recorded sessions show what is actually needed.

Licence: MIT. See [LICENSE](LICENSE).
