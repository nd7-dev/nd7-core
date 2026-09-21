# Spike D: nd7 on top of Claude Code's own sandbox (the env interposer)

2026-09-21, Darwin 25.6, Claude Code 2.1.278, nd7 56a9fc8. 12 claude -p runs, about $1.85. Nothing committed.
Artifacts: scratchpad/ext/envtramp (interposer source), shim2/env, policy/floor-denies.sb, policy/last-combined.sb.

## Problem
Giving /usr/bin/sandbox-exec a no-sandbox exit made Claude Code's (CC) sandbox work under our floor, but a Bash
command then ran under CC's profile ALONE. nd7 was not on top of it. Rejected.

## Mechanism found
CC builds each sandboxed Bash command as
    env K=V ... /usr/bin/sandbox-exec -p <full SBPL profile> <shell> -c <cmd>
and resolves `env` THROUGH PATH (verified: a PATH shim received all 31 args including the 49 KB profile).
So an nd7 binary installed as `env` on a PATH dir that nd7 run prepends, named as the floor's only no-sandbox exit,
receives CC's requested profile and the command while still unsandboxed. It appends the nd7 floor as DENY rules,
applies the combined profile to itself with sandbox_init, and execs <shell> -c <cmd>. The kernel enforces
CC-policy AND nd7-floor on every command. CC believes its sandbox-exec ran; its proxy, domain filter, prompts and
/sandbox UX all keep working. The real /usr/bin/sandbox-exec is never exec'd (no nesting problem).
Other invocations of `env` (CC probes it with no args; commands inside the sandbox) pass through to /usr/bin/env.
Inside the combined profile the interposer is not an exit (sandbox_check=1), so nesting is closed.

## Verified live (CC sandbox enabled, project settings)
- project write OK (both allow); $HOME write denied; project/secret write DENIED by nd7 while CC allows it
  (the on-top property); sandbox-exec allow-all from Bash -> sandbox_apply EPERM; unrelated local port refused.
- curl https://example.com through CC's proxy -> 200 with example.com in CC's allowedDomains; 403/502 otherwise.
- Baseline without nd7 also 200 (so the floor was the only variable).

## Seatbelt facts learned (each cost a wrong result first)
1. Per-operation rules beat class rules regardless of order: CC's `(allow file-write-create ... (subpath PROJ))`
   wins over a LATER `(deny file-write* (subpath PROJ/secret))`. Appended denies must enumerate the concrete
   operations (file-write-create/-data/-unlink/-mode/-owner/-times/-flags/-xattr/-setugid/-acl, file-link;
   file-read-data/-metadata/-xattr). Then last-match-wins applies. Op list: grep Apple's /System/Library/Sandbox/Profiles.
2. Inside `require-not`, a network filter with a WILDCARD PORT never matches (`localhost:*`, `*:*`), so the whole
   require-not denies everything. `*:443` (wildcard host) and exact `localhost:PORT` work. The interposer takes CC's
   proxy port from the HTTPS_PROXY it was handed and templates it in. The two-step "deny all, re-allow localhost:*"
   works but widens beyond CC's own rule; rejected.
3. CC's proxy (inside the claude process, under the floor) forwards over a unix socket
   $TMPDIR/srt-mux-<pid>-N.sock. The floor needs `(allow network-outbound (regex #"^/private/var/folders/.*/T/srt-mux-"))`
   plus network-bind/inbound for it; without it every proxied request is a 502. `(remote ip)` does not cover unix sockets.
4. `log show` denial capture was unreliable in this session (empty even for known denials); bisect instead.

## Trust model now
Exits from the floor: exactly two literal paths, both nd7 binaries with no write path: the env interposer and the
prefix trampoline (for the escape-hatch / CC-sandbox-off path). /usr/bin/sandbox-exec is NOT an exit any more, so
MCP servers and hooks in the outer tree can no longer leave the floor through it. The policy dir and the binaries
are unwritable from every layer (floor denies; combined profile inherits the floor denies).
Dependencies: CC resolving `env` via PATH and passing `-p <profile>`; the shell prefix. If either changes,
CC's sandbox-exec hits the floor with no exit -> EPERM -> CC disables its sandbox for the session and commands
run under the floor directly: fail-closed, floor intact, dynamic/coexistence layers lost. nd7 detects the exit-71
/ "sandboxing disabled" signatures and says so.

## Not yet done
- Interposer hardening: session/floor from ancestry record, not a fixed path; refuse unexpected argv shapes; log.
- PATH-dir placement and permissions; nd7 run must prepend it and set CLAUDE_CODE_SHELL_PREFIX.
- Write/Edit still floor-only. ps/pgrep need. Interactive terminal run.
