# Spike F: gpg signing under `nd7 run`, and what an agent could do with your gpg-agent

2026-09-23. GnuPG 2.4.7 (Homebrew), pinentry-mac, macOS Darwin 25.6, nd7 at af94024. No model calls.
Every claim below was run under `sandbox-exec` with a copy of the nd7 profile. Tests that needed
decryption, key export or a passphrase used a throwaway `GNUPGHOME` with its own agent and throwaway
keys; the real keyring was only used to show that signing works.

## Headline
Codex could not sign commits under nd7: `gpg: can't connect to the gpg-agent: Operation not permitted`.
gpg never needed to write `~/.gnupg` to sign; it needs to reach the agent's Unix socket, and the floor
only allows `network-outbound` to mDNSResponder. The lock-file error that comes first
(`failed to create temporary file '~/.gnupg/.#lk0x…'`) is gpg trying to start a new agent after the
connect failed.

The obvious fix, allowing `~/.gnupg/S.gpg-agent`, hands the agent everything: a process in the sandbox
can guess your passphrase with no dialog, then export your secret key, decrypt anything encrypted to
you, and sign as you. Measured below.

The fix to ship is gpg-agent's restricted socket, `~/.gnupg/S.gpg-agent.extra`, which gpg built for
forwarding the agent to machines you don't trust. Through it, signing and decryption still work, but
key export, loopback pinentry, and agent control are refused. Verified end to end: a sandboxed gpg
signed with the real key through it.

## Why the naive fixes are wrong
- **Allow the main socket.** Full agent access; see the damage assessment.
- **Make `~/.gnupg` writable.** Worse. `gpg-agent.conf` names `pinentry-program` and `scdaemon-program`,
  which the agent runs outside the sandbox the next time it starts: a sandbox escape. Writable
  `trustdb.gpg` and `pubring.kbx` also let a session add a key and mark it ultimately trusted, so a
  forged signature would verify as good (reasoned, not tested). The socket rule alone is enough; no
  write to `~/.gnupg` is needed.
- **Allow every socket in `~/.gnupg`.** Also reaches `S.gpg-agent.ssh` when `enable-ssh-support` is on,
  which is SSH as you to every host your keys open (not enabled here, not tested).

## Damage assessment: a sandboxed process with the main socket
Measured on a throwaway agent (`allow-loopback-pinentry`, which is gpg-agent's default), from inside
the sandbox:

| What | Result |
|---|---|
| Sign as you | works; silent while the passphrase is cached |
| Guess the passphrase with `--pinentry-mode loopback` | no dialog; wrong guesses return `Bad passphrase`, the right one signs |
| Export the secret key (`--export-secret-keys`) | `-----BEGIN PGP PRIVATE KEY BLOCK-----` |
| Decrypt a file encrypted to you | plaintext |
| `OPTION ttyname=…`, `UPDATESTARTUPTTY` | accepted (steers where pinentry appears) |
| `KILLAGENT`, `RELOADAGENT`, `PUTVAL` | accepted |

What that means, worst first:
1. **The key leaves, for good.** Loopback pinentry lets code feed passphrase guesses straight to the agent
   with no dialog and no sign to the user. Once a guess works, `--export-secret-keys` gives the key and
   the attacker knows its passphrase. A signing key lives for years; the session lasted minutes.
   Tested with an empty passphrase and with one supplied through loopback; whether a cached
   passphrase alone is enough to export, with no prompt, was not tested.
2. **Everything encrypted to you is readable.** `pass` password stores, sops and git-crypt secrets,
   encrypted backups and mail, while the passphrase is cached or once it has been guessed.
3. **Forged work in your name.** Signed commits and tags that GitHub marks Verified, pushed anywhere the
   agent can push; signed release artifacts if the key signs releases. Silent within the cache window
   (`default-cache-ttl 600`, `max-cache-ttl 7200` on this machine).
4. **Pinentry steering.** A caller may set the tty and display pinentry uses. With a terminal pinentry
   that could put the prompt somewhere the agent reads; with pinentry-mac it is moot (not tested
   further).
5. **Agent control.** Kill or reload the agent, store values in it. A nuisance; after a kill, nothing
   in the sandbox can sign until the user starts a new agent.

For this machine's key specifically: it has no encryption subkey (`scSC`), so item 2 does not apply,
and items 1 and 3 do.

## The restricted socket
Same throwaway setup, same commands, through `S.gpg-agent.extra`:

| What | Result |
|---|---|
| Sign | works |
| Decrypt | works |
| Export the secret key | `gpg: error getting the KEK: Forbidden` |
| `--pinentry-mode loopback` (or any pinentry mode) | `Forbidden` |
| `OPTION ttyname`, `UPDATESTARTUPTTY`, `RELOADAGENT`, `KILLAGENT`, `PUTVAL`, `HAVEKEY --list`, `GETINFO std_env_names` | `Forbidden` |
| `SCD …` (smartcard passthrough) | allowed |

What is left: a session can sign and decrypt while the passphrase is cached, or after a pinentry
dialog the user approves. It cannot take the key, cannot learn the passphrase, and cannot guess it.
The gpg documentation says restricted connections keep their own passphrase cache and pinentry marks
their requests as remote; neither was checked here.

## How gpg is pointed at it
gpg always connects to `$GNUPGHOME/S.gpg-agent` (on macOS the socket dir is `GNUPGHOME`), so a session
gets a stand-in `GNUPGHOME`:

```
<short tmp dir>/            mode 700
  pubring.kbx  -> ~/.gnupg/pubring.kbx
  trustdb.gpg  -> ~/.gnupg/trustdb.gpg
  gpg.conf     -> ~/.gnupg/gpg.conf
  S.gpg-agent  -> ~/.gnupg/S.gpg-agent.extra
```

and the profile gains one rule:

```
(allow network-outbound (literal "<home>/.gnupg/S.gpg-agent.extra"))
```

Findings from wiring it by hand:
- **Seatbelt checks the socket's resolved path.** Connecting through the symlink is allowed by the rule
  on the target alone.
- **Socket paths are capped at 104 bytes on macOS.** The first attempt, under the session scratchpad
  (140 bytes), failed as if no agent were running, and gpg then tried to start one.
- **The stand-in directory must be writable.** gpg takes dotlocks there (key export needed one). Under
  the temp dir it already is.
- **The agent must be running before the sandbox starts.** A sandboxed gpg cannot start one; if it has
  exited, signing fails until something outside starts it (`gpgconf --launch gpg-agent`).
- **Fail-closed.** If a command unsets `GNUPGHOME`, gpg goes back to the main socket and is denied.
- **Side effects.** `gpg: problem with fast path key listing: Forbidden - ignored` on every sign,
  harmless. Keyring writes (importing a key, `auto-key-retrieve`) go through the symlinks into
  `~/.gnupg` and are denied. Anything that passes `--pinentry-mode` fails.
- **Listing keys fails, signing does not.** `gpg --list-keys` and `gpg --list-secret-keys` open
  `trustdb.gpg` for writing, to show validity, and die with
  `gpg: Fatal: can't open '~/.gnupg/trustdb.gpg': Operation not permitted`. Signing only reads it:
  `gpg --status-fd=2 -bsau <key>`, as git calls it, printed `SIG_CREATED` under the same profile.
  Seen in a real Codex session, which runs `gpg --list-secret-keys` as a pre-check before committing.
  The trust database stays read-only: writable, a session could mark any key ultimately trusted. If a
  trustdb check falls due (`gpg: next trustdb check due at …`), gpg may want to write during signing
  too; `gpg --check-trustdb` once from outside clears it (not observed; none was due).

## Open items
- `use-keyboxd` (in `common.conf`, the default for new GnuPG 2.4 installs) replaces `pubring.kbx` with
  another socket, `S.keyboxd`, which has no restricted mode. Not the case on this machine; untested.
- `SCD` passes through the restricted socket. With a hardware key, a session could send raw card
  commands, at least enough to lock the PIN with wrong tries. No card here; untested.
- Separate passphrase cache for restricted connections: documented, unverified.

## Free probes worth keeping
```sh
# which commands a socket refuses (safe: nothing here signs or prompts; KILLAGENT on the main socket
# really kills the agent, restart it with `gpgconf --launch gpg-agent`)
gpg-connect-agent -S ~/.gnupg/S.gpg-agent.extra 'OPTION pinentry-mode=loopback' /bye
gpg-connect-agent -S ~/.gnupg/S.gpg-agent.extra 'EXPORT_KEY 0000' /bye

# sign through a stand-in GNUPGHOME under a profile that allows only the restricted socket
echo x | sandbox-exec -f profile.sb /usr/bin/env GNUPGHOME=/private/tmp/nd7gpg.XXXX \
  gpg --batch -u <key> --detach-sign -a
```
