# Event schema (draft 0)

This document is the contract. Change it deliberately and record why in
[DECISIONS.md](DECISIONS.md). Until the schema is marked `v1`, fields may
change; after that, only additive changes within a major version.

Field sources are marked:

- **hook**: copied from the Claude Code hook payload (verified against
  https://code.claude.com/docs/en/hooks on 2026-09-17).
- **nd7**: computed by the recorder.
- **(verify)**: believed true, not confirmed against docs or a real payload.

## 1. Envelope

Every event, from every source, present or future, has exactly these top-level
fields. Agent-specific data never appears here; it goes in `body`.

| field        | type            | req | source | meaning |
|--------------|-----------------|-----|--------|---------|
| `v`          | u16             | yes | nd7    | Schema version of this frame. `0` while drafting. |
| `session_id` | string          | yes | hook   | Top-level grouping key. Claude Code's `session_id` verbatim. |
| `seq`        | u64             | yes | nd7    | Position in this session's log on this host, starting at 0. Dense. |
| `ts`         | i64 (ns)        | yes | nd7    | Wall-clock time at recorder invocation, Unix epoch nanoseconds, UTC. |
| `mono`       | u64 (ns)        | opt | nd7    | Monotonic clock at invocation. Ordering aid within one host boot; not comparable across hosts. |
| `host`       | string          | yes | nd7    | Hostname (or configured host id) of the machine that produced the event. Needed for remote continuity. |
| `source`     | string          | yes | nd7    | Producer and evidence class. Phase 1: `intent:claude-code`. Reserved: `intent:codex`, `effect:es`, `effect:fanotify`, `effect:remote`. Format is `<class>:<producer>`. |
| `kind`       | string          | yes | nd7    | Event kind, see section 2. |
| `prev`       | string (hex)    | yes | nd7    | BLAKE3 hash of the previous frame in this file. All-zero for `seq` 0. |
| `hash`       | string (hex)    | yes | nd7    | BLAKE3 over this frame's canonical bytes with `hash` absent (section 4). |
| `sig`        | string          | opt | nd7    | Reserved for a signature over `hash`. Never emitted in Phase 1. |
| `body`       | object          | yes | mixed  | Kind-specific fields, section 2. |

Why `ts` is ours, not the agent's: the hook payload carries no timestamp
(verified: none in the documented common or per-event fields). `ts` is the
moment `nd7 hook` started, which is after Claude Code decided to act and, for
`PreToolUse`, before the tool runs. Effect events from the kernel will carry
their own `ts`; matching them to intent means matching within a window, not
on equality.

Why `seq` is per host: two machines cannot agree on a dense counter without
coordination. Merging a remote log uses `(host, seq)` for identity and `ts`
for display order.

Why `v` is per frame and not per file: a log file may span an `nd7` upgrade
mid-session, and a stream has no header to consult.

## 2. Phase 1 event kinds

All bodies for `source: intent:claude-code` carry these common fields taken
from the hook payload's common section:

| field             | type   | req | source | notes |
|-------------------|--------|-----|--------|-------|
| `cwd`             | string | yes | hook   | Agent's working directory at the hook. **Join key** for effects. |
| `transcript_path` | string | yes | hook   | Path to Claude Code's own transcript. Lets a reader cross-check our record against the agent's. |
| `hook_event_name` | string | yes | hook   | Recorded even though `kind` is derived from it, so an unknown or renamed event is never lost. |
| `permission_mode` | string | opt | hook   | `default`, `plan`, `acceptEdits`, `auto`, `dontAsk`, `bypassPermissions`. Absent on `SessionEnd` per docs. |
| `prompt_id`       | string | opt | hook   | UUID of the user turn. Absent before the first prompt; needs Claude Code ≥ 2.1.196 per docs. Groups the tool calls of one turn. |
| `agent_id`        | string | opt | hook   | Present only inside a subagent. |
| `agent_type`      | string | opt | hook   | Present only inside a subagent, e.g. `Explore`. |
| `hook_ppid`       | u32    | opt | nd7    | Parent pid of the `nd7 hook` process. **Join key** for the future process-tree attribution. (verify) Whether the parent is the Claude Code process or an intermediate shell depends on how Claude Code spawns command hooks; if `args` is set the docs say the command is spawned without a shell. |
| `raw`             | object | opt | hook   | The full hook payload, kept only when a field we did not model is present or under `--raw`. Off by default to keep the log small. |

### `session_start`  (hook: `SessionStart`)

| field    | type   | req | source | notes |
|----------|--------|-----|--------|-------|
| `reason` | string | yes | hook   | Payload field `source`: `startup`, `resume`, `clear`, `compact`, `fork`. Renamed to avoid clashing with the envelope's `source`. |

A `resume`, `compact` or `fork` start on an existing session appends to the
existing log; it does not start a new file.

### `prompt`  (hook: `UserPromptSubmit`)

| field  | type   | req | source | notes |
|--------|--------|-----|--------|-------|
| `text` | string | yes | hook   | Payload `prompt`, verbatim. |

### `tool_call`  (hook: `PreToolUse`)

| field         | type   | req | source | notes |
|---------------|--------|-----|--------|-------|
| `tool_use_id` | string | yes | hook   | Pairs this with its `tool_result`. |
| `tool_name`   | string | yes | hook   | `Bash`, `Edit`, `Write`, `Read`, `mcp__…`, etc. |
| `tool_input`  | object | yes | hook   | Full input, verbatim. For `Bash` this includes `command`, the full argv string. **Join key.** For `Write`/`Edit` it includes file paths and content. |
| `argv`        | string | opt | nd7    | Copy of `tool_input.command` when `tool_name` is `Bash`, hoisted so effect matching does not need to know tool shapes. |
| `paths`       | array  | opt | nd7    | File paths hoisted from `tool_input` for known tools (`file_path`, `notebook_path`, …). Same reason. |

### `tool_result`  (hook: `PostToolUse`)

| field           | type   | req | source | notes |
|-----------------|--------|-----|--------|-------|
| `tool_use_id`   | string | yes | hook   | |
| `tool_name`     | string | yes | hook   | |
| `tool_input`    | object | opt | hook   | Repeated by the payload. Stored by default; dropping it in favour of the `tool_call` copy is an open size trade-off. |
| `tool_response` | any    | yes | hook   | Shape is tool-specific and undocumented beyond "the output/response". For `Bash` it is expected to contain stdout, stderr and an exit status (verify against a real payload). |
| `ok`            | bool   | yes | nd7    | `true` for `PostToolUse`. Claude Code has a separate `PostToolUseFailure` event; whether Phase 1 subscribes to it is open (section 6). |

### `session_end`  (hook: `SessionEnd`)

| field    | type   | req | source | notes |
|----------|--------|-----|--------|-------|
| `reason` | string | yes | hook   | `clear`, `resume`, `logout`, `prompt_input_exit`, `other`. |

`SessionEnd` hooks share a 1.5 s budget (docs). The writer must not do extra
work here. Absence of a `session_end` event means the session ended without
Claude Code firing the hook (crash, kill), which the reader should say.

### `turn_end`  (hook: `Stop`), optional in Phase 1

| field                    | type   | req | source | notes |
|--------------------------|--------|-----|--------|-------|
| `last_assistant_message` | string | opt | hook   | Final assistant text of the turn. Potentially large. |
| `stop_hook_active`       | bool   | yes | hook   | |

### `hook` (catch-all)

Any `hook_event_name` we do not model is stored with `kind: hook` and
`body.raw` set to the full payload. This keeps the recorder forward compatible
with Claude Code releases.

## 3. Join keys stored on purpose

These are recorded now for the Phase 2 kernel layer even though nothing
consumes them yet:

| key                       | where                        | used later for |
|---------------------------|------------------------------|----------------|
| `ts` (ns)                 | envelope                     | time-window match of intent to effect |
| `body.cwd`                | every body                   | resolving relative paths in effects; scoping |
| `body.argv`               | `tool_call`                  | matching exec events' argv |
| `body.paths`              | `tool_call`                  | matching file-open events |
| `body.hook_ppid`          | every body                   | anchoring the agent's process tree |
| `body.tool_use_id`        | `tool_call` / `tool_result`  | bracketing the effect window (call ts .. result ts) |
| `host`                    | envelope                     | remote continuity |
| `session_id`              | envelope                     | everything |

## 4. Hashing

`hash = BLAKE3(canonical_bytes(frame without "hash"))`, where the frame already
contains `prev`. The chain is therefore over frames, not over bodies, so
reordering, dropping or editing any envelope field is detected too.

Canonical bytes: **the exact bytes written to the file**, with the `hash`
field appended last. Rationale: hashing the written bytes means `verify`
needs no canonicalization library and cannot disagree with the writer about
whitespace or key order. The writer guarantees a deterministic field order and
no insignificant whitespace. The alternative, RFC 8785 JSON canonicalization,
buys hash stability across re-serializers at the cost of a dependency and a
second serialization pass; we do not need that in Phase 1 because only `nd7`
writes frames.

Genesis: `prev` for `seq` 0 is 64 hex zeros. Consider binding `session_id`
into the genesis `prev` so a chain cannot be transplanted between sessions;
cheap, and I recommend it.

What the chain proves and does not prove: it proves the file has not been
modified since it was written, *if* the verifier trusts the head. Without a
signature or a remote anchor, someone who can write the file can rewrite the
chain. `verify` must print this caveat. `sig` is reserved for Phase 2+.

## 5. Frame format: options for you to choose

Requirements: append-only, streamable, self-describing, versioned, cheap to
write from a short-lived process, readable with standard tools during
development, and able to grow signing, compression and dictionary interning.

### Option A: NDJSON, one JSON object per line

- Pros: `jq`, `grep`, `tail -f` work today. Zero decoder to write. Trivially
  streamable. Easy to debug the first real sessions.
- Cons: 3–5× larger than a binary encoding before compression; per-event
  compression is poor (small frames), so "tens of bytes per event" needs
  file-level compression at rest or a later re-encode. A corrupted line is
  detectable (hash) but resync is "next newline", which is fine.
- Migration: `v` in each frame plus a distinct file extension lets a later
  binary writer coexist; the reader dispatches on the first byte (`{` vs a
  magic byte).

### Option B: Length-prefixed binary frames (CBOR or MessagePack) from day one

- Pros: compact now, interning and compression slot in as frame-level flags.
  One format for the life of the project.
- Cons: nothing standard reads it; every look at a session needs `nd7 show`.
  Slower iteration while the schema is still moving. Serde support is good for
  both encodings, so the code cost is small but the debugging cost is real.

### Option C: NDJSON now, binary container later, both first-class

- Same as A for Phase 1, with the commitment that the reader accepts both and
  that a `nd7 pack` command re-encodes a finished session into the binary
  container (compressed, interned, signed). The NDJSON file is the hot write
  path; the packed file is the storage and upload format.
- Cons: two formats to maintain forever, and the hash chain must be defined
  so that packing does not change hashes (hash the canonical JSON bytes, store
  them or re-derive them exactly).

My recommendation is C with A's writer today, but the decision is yours. The
one thing all options share is the envelope above, so choosing later costs
nothing before milestone 3.

## 6. Open questions for you

1. **Content policy.** `Write` and `Edit` inputs carry full file content, and
   `Read` responses carry file contents. "Events, not content" and "record
   everything the payload gives us" conflict here. Options: store verbatim;
   store verbatim up to N KiB then hash and truncate with a marker; store a
   hash only for known content fields. Storing verbatim is the simplest and
   the most useful for undo later, but a heavy session will not stay under a
   few MB.
2. **`PostToolUseFailure`.** The docs list it as a separate event. Subscribing
   gives us `ok: false` results instead of silence. I recommend yes.
3. **`Stop` hook.** Useful turn boundary and the assistant's final text, but
   the text can be large. Include by default, or opt-in?
4. **Frame format**, section 5.
5. **Genesis binding** of `session_id` into `prev`, section 4.
