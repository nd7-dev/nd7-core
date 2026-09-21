# Spike C: per-call Seatbelt without nesting (the trampoline)

All experiments run on Darwin 25.6.0, Claude Code 2.1.278, nd7 at HEAD (56a9fc8). Nothing committed.
Artifacts: scratchpad/ext/ (profiles, tramp/ binary, ext_child.py, e2e.json, policy/tramp.log).

## Discoveries (each verified here)

1. `(allow process-exec (with no-sandbox) (literal "<bin>"))` compiles and works through sandbox_init.
   Exec of that one binary leaves the sandbox entirely; the child can apply any fresh profile
   (a nested sandbox-exec inside it succeeds, proving it is unsandboxed). Every other exec stays confined.
2. CLAUDE_CODE_SHELL_PREFIX: Claude Code passes every Bash-tool command to the prefix as ONE argv
   element, with its snapshot preamble already prepended. Its own strings describe the trust
   condition: "an absolute wrapper outside what the session can write".
3. 1 + 2 = per-call profiles. Outer profile confines claude; each Bash call execs the trampoline
   (unsandboxed), which reads the CURRENT session policy and runs the command under it in a fresh
   tree. Live demo in one claude -p session: write under $HOME -> FAIL (policy 587 B);
   policy widened by appending one rule; same write 8 s later -> OK (policy 658 B). Claude reported
   the asymmetry correctly. Cost per brokered call: ~23 ms (one sandbox_init).
4. App Sandbox extension tokens work under our profile: sandbox_extension_issue_file outside,
   sandbox_extension_consume inside, denied write becomes allowed, child processes inherit.
   Second dynamic mechanism; not needed for Bash; cannot reach node (Write/Edit) since nothing
   there consumes tokens.
5. A direct trampoline call from Bash (bypassing the prefix) still gets the policy applied.

## Trust anchor, found by attacking the spike trampoline

- ESCAPED via cwd: trampoline took PROJ from caller cwd; `cd / && tramp 'echo > ~/x'` wrote.
- ESCAPED via HOME: policy's `(subpath HOME)/.claude` with caller HOME=/private/tmp.
- Fix: parameters never come from the caller. Outer `nd7 run` writes a session record
  (root pid -> policy + resolved PROJ/HOME/TMP) under a directory the profile denies writes to;
  trampoline finds its session by walking ppid ancestry (unforgeable) and uses the record.
  Caller cwd is only used as cwd.
- Trampoline binary and policy dir must be unwritable from the sandbox. In the spike the policy
  sat under /private/tmp/claude-* which the base profile allows (CC scratch); production: ~/.nd7.
- Never no-sandbox a shell, an interpreter, or /usr/bin/sandbox-exec.
- MCP servers and hooks live in the outer profile and may call the trampoline; same policy applies.

## Operational findings

- Outer profile needs `(allow signal)` for CC to kill a timed-out command. `(target children)`
  reaches the trampoline but not its sandboxed grandchild (orphan). `same-sandbox` does not match
  the unsandboxed trampoline. Reduce orphaning: trampoline applies the profile to ITSELF and execs
  the shell in-process (no grandchild).
- ps/pgrep denied under deny-default (sysmond mach service); check whether CC needs it.
- `(allow file-ioctl)` for any terminal use. `(trace)` is dead on this OS; use `log show`.
- CC's own sandbox still must be off (--settings). No loss: the trampoline IS the per-call layer,
  and it can carry CC-style denial hints and a `nd7 allow` grant flow. Same dependency as before
  on CC keeping the opt-out.
- Grant UX without a UI: `nd7 allow <path>` edits the session policy; takes effect on the next
  Bash call, no restart. PreToolUse `permissionDecision: ask` could borrow CC's prompt (untested).
- Write/Edit stay under the static outer profile. Hook redirect (B1) is possible but awkward.
- Network: per-call profile can change ports; hostnames still need a proxy.

## Versus the broker (Spike A)

Trampoline = broker without daemon, socket, fd passing or 104-byte path limits. The only
long-lived outside process is `nd7 run` itself, already there. Spike trampoline: 30 lines.

## Risks

- `no-sandbox` is an undocumented SBPL modifier (Apple uses it in its own profiles). Could change.
- CLAUDE_CODE_SHELL_PREFIX is a CC feature; fallback would be a PATH shim if CC spawns the shell by name.
- Same-uid signal allowance is broad; it is also what unsandboxed CC has today.

## Recommendation

Adopt as Tier 1: `nd7 run` (outer profile + session record + CC sandbox off + prefix),
`nd7 exec` (trampoline, ancestry-resolved session, in-process apply+exec),
`nd7 allow|deny` (edit session policy). Then test kill/timeout with real CC, ps needs, --resume.

Spend: 5 claude -p calls, about $0.62.

## Addendum: coexistence with Claude Code's own sandbox (4 more claude -p runs, ~$0.91)

Outer profile = spike B's p5b.sb + (allow signal) + (allow process-exec (with no-sandbox) (literal "/usr/bin/sandbox-exec")).
Claude Code sandbox ENABLED via project settings.

- CC's sandbox came up under our profile (no "failed to initialize", no exit 71). Bash: $HOME write DENIED by CC's
  policy, project write OK, and `sandbox-exec -p '(allow default)'` from Bash -> "sandbox_apply: Operation not
  permitted" (Bash runs under CC's profile, where sandbox-exec is not an exit). That refusal is also the proof CC's
  sandbox was really active: had it dropped, the probe would have escaped through our rule.
- The shell prefix runs INSIDE CC's per-command sandbox (CC wraps sandbox-exec -> shell -> prefix). A trampoline
  used as prefix must detect this and just exec the shell. sandbox_check(getpid(),NULL,0) returns 1 under any
  profile and 0 after our no-sandbox exec, so the two cases are distinguishable.
- Editing .claude/settings.json from Bash to widen CC's allowlist: refused by CC's own sandbox ("deny-within-allow").
- excludedCommands did not take effect in -p mode for a composite command (inconclusive, not pursued).
- Escape hatch (dangerouslyDisableSandbox: true, auto-allowed with --allowedTools Bash): the prefix STILL ran, and
  ran under OUR outer profile (its sandbox-exec probe succeeded). The $HOME write was denied by our profile: the
  outer boundary is the floor under CC's escape hatch. With nd7 as the prefix, that path would exit via no-sandbox
  and get nd7's per-call policy instead of the bare outer profile, closing the sandbox-exec exit for escaped commands.

### Resulting layered design (Tier 1)
outer profile (nd7, whole tree) > CC per-command sandbox (their policy, their prompt UX) > nd7 per-call policy
for anything CC runs outside its own sandbox (prefix trampoline, self-detecting). Dynamic grants: CC's /sandbox
for its layer; `nd7 allow` for ours. CC enforcing its sandbox in a future release no longer breaks nd7.
Open: the trampoline must not be reachable from CC's sandboxed Bash as an exit (it is not: no-sandbox is only in
our profile); MCP servers and hooks in the outer tree can exec sandbox-exec and escape the outer profile — same
trust level as CC gives them today, but worth stating.
