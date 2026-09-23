//! What a session is allowed to do, and the two Seatbelt profiles that say so.
//!
//! [`Policy`] is the whole of it: four fixed paths and the write roots
//! `nd7 allow` has added. Two profiles are rendered from it, sharing one body:
//!
//! - [`Policy::render_floor`] is what `nd7 run` applies to claude and its
//!   whole process tree. It lets exactly one program out of the sandbox,
//!   `nd7-exec`, so every command Claude Code runs goes through it.
//! - [`Policy::render_policy`] is what `nd7-exec` applies to itself before it
//!   becomes the shell for one command. Same body, plus the grants, and no
//!   way out.
//!
//! Both end with the same two per-operation denies: nd7's own records, so no
//! grant and no later rule can make the flight recorder writable, and the
//! agents' own configuration files, so a session cannot change the hooks or
//! the sandbox settings the sessions after it start with.
//!
//! This module only renders text; the paths come from the caller, already
//! canonical, because Seatbelt's `subpath` matches resolved paths.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The rules of one `nd7 run`, as the profiles need them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// The project: the canonical working directory of `nd7 run`, and the
    /// one place the agent may write from the start.
    pub project: PathBuf,
    /// The user's home, from passwd. Only used to locate `~/.ssh`, `~/.aws`,
    /// `~/.nd7`, `~/.claude` and `~/.codex`; it is never writable as a whole.
    /// It also allows one special restricted socket for gnupg for signing.
    pub home: PathBuf,
    /// The canonical `std::env::temp_dir()`.
    pub tmp: PathBuf,
    /// The `nd7-exec` binary the floor lets out of the sandbox.
    pub exit: PathBuf,
    /// Extra write roots added by `nd7 allow`. Empty when the run starts, and
    /// only ever in the per-command profile.
    pub grants: Vec<PathBuf>,
}

/// Every concrete write operation, plus `file-link`, taken from Apple's own
/// profiles in `/System/Library/Sandbox/Profiles`.
///
/// The class name `file-write*` on its own would not do: Seatbelt consults
/// per-operation rules before class rules whatever their order, so an earlier
/// `(allow file-write-create ...)` beats a later `(deny file-write* ...)`.
/// Naming the operations puts the deny on the same footing, and then the last
/// match wins as one would expect.
const WRITE_OPS: &str = "file-write* file-write-acl file-write-create file-write-data file-write-flags file-write-mode file-write-owner file-write-setugid file-write-unlink file-write-xattr file-link";

impl Policy {
    /// The profile `nd7 run` applies to claude and everything it spawns.
    pub fn render_floor(&self) -> String {
        let mut out = self.body();
        out.push_str(&format!(
            "
;; The floor's one exit: nd7-exec, which applies the session policy to itself
;; before it runs anything. Nothing else leaves this sandbox.
(allow process-exec (with no-sandbox) (literal {}))
",
            sbpl_string(&self.exit)
        ));
        out.push_str(&self.deny_records());
        out.push_str(&self.deny_agent_config());
        out
    }

    /// The profile `nd7-exec` applies to itself, per command.
    pub fn render_policy(&self) -> String {
        let mut out = self.body();
        if !self.grants.is_empty() {
            out.push_str("\n;; Write roots added by `nd7 allow` during this run.\n");
            for grant in &self.grants {
                out.push_str(&format!(
                    "(allow file-write* (subpath {}))\n",
                    sbpl_string(grant)
                ));
            }
        }
        out.push_str(&self.deny_records());
        out.push_str(&self.deny_agent_config());
        out
    }

    /// Everything both profiles say, up to the rules that differ.
    fn body(&self) -> String {
        format!(
            r#"(version 1)
(deny default)
(import "system.sb")

;; The agent runs commands, and those commands run commands.
(allow process-fork process-exec)
(allow signal)                          ; Claude Code kills timed-out commands
(allow sysctl-read)
(allow file-ioctl)                      ; terminals: window size, raw mode

;; Reading is open; credentials and nd7's own records are not.
(allow file-read*)
(deny file-read* file-read-data file-read-metadata file-read-xattr (subpath {ssh}) (subpath {aws}) (subpath {records}))

;; Writable: the project, the temp dir, Claude Code's scratch directories, and
;; each agent's own state, `~/.claude` and `~/.codex`. HOME is matched as a
;; subpath rather than spliced into the regex, because escaping a path into a
;; regex is error-prone.
(allow file-write* (subpath {project}) (subpath {tmp}) (regex #"^/private/tmp/claude-") (require-all (subpath {home}) (regex #"/\.claude(/|$)")) (require-all (subpath {home}) (regex #"/\.codex(/|$)")))

;; DNS, network configuration and the keychain: what an HTTPS client needs.
(allow mach-lookup (global-name "com.apple.dnssd.service") (global-name "com.apple.SystemConfiguration.configd") (global-name "com.apple.SecurityServer"))
(allow network-outbound (literal "/private/var/run/mDNSResponder"))
;; A wildcard host with an exact port matches; a wildcard port would not.
(allow network-outbound (remote tcp "*:443"))

;; Allow binding to ports on localhost:* and using them.
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (local ip "localhost:*"))

;; Allow socket outbound traffic to the gpg_agent
;; Here we allow only reaching a restricted socket. Never the main one.
(allow network-outbound (literal {gpg_agent}))
"#,
            ssh = sbpl_string(&self.home.join(".ssh")),
            aws = sbpl_string(&self.home.join(".aws")),
            records = sbpl_string(&self.home.join(".nd7")),
            project = sbpl_string(&self.project),
            tmp = sbpl_string(&self.tmp),
            home = sbpl_string(&self.home),
            gpg_agent = sbpl_string(&self.home.join(".gnupg/S.gpg-agent.extra"))
        )
    }

    /// The last rule of either profile; see [`WRITE_OPS`] for why it names
    /// every operation instead of the class.
    fn deny_records(&self) -> String {
        format!(
            "
;; Last, so the last match wins: nd7's own records stay unwritable, whatever
;; the rules above allow.
(deny {WRITE_OPS} (subpath {records}))
",
            records = sbpl_string(&self.home.join(".nd7"))
        )
    }

    /// The rule after that one, and the last of either profile: the agents'
    /// own configuration. The rest of `~/.claude` and `~/.codex` is writable,
    /// so the agents work, but not the files that decide what hooks and what
    /// sandbox the sessions after this one start with. `~/.codex/auth.json`
    /// is deliberately absent: refreshing a ChatGPT token rewrites it.
    fn deny_agent_config(&self) -> String {
        format!(
            "
;; And last of all, for the same reason: a session may not rewrite the hooks
;; or the sandbox settings that the next session starts with.
(deny {WRITE_OPS} (literal {codex_config}) (literal {codex_hooks}) (literal {claude_settings}))
",
            codex_config = sbpl_string(&self.home.join(".codex/config.toml")),
            codex_hooks = sbpl_string(&self.home.join(".codex/hooks.json")),
            claude_settings = sbpl_string(&self.home.join(".claude/settings.json")),
        )
    }
}

/// A path as an SBPL string literal: wrapped in double quotes, with `\` and
/// `"` escaped. The one place a path enters profile text, so the one place
/// that could get the quoting wrong.
///
/// A path that is not UTF-8 goes through [`Path::to_string_lossy`], so its
/// invalid bytes become replacement characters and the rule will not match
/// the path that was meant. Seatbelt takes profiles as C strings and has no
/// way to say such a path at all.
fn sbpl_string(path: &Path) -> String {
    let path = path.to_string_lossy();
    let mut out = String::with_capacity(path.len() + 2);
    out.push('"');
    for c in path.chars() {
        if c == '\\' || c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The body both renderings share, for the policy `sample` returns.
    const BODY: &str = r#"(version 1)
(deny default)
(import "system.sb")

;; The agent runs commands, and those commands run commands.
(allow process-fork process-exec)
(allow signal)                          ; Claude Code kills timed-out commands
(allow sysctl-read)
(allow file-ioctl)                      ; terminals: window size, raw mode

;; Reading is open; credentials and nd7's own records are not.
(allow file-read*)
(deny file-read* file-read-data file-read-metadata file-read-xattr (subpath "/Users/ada/.ssh") (subpath "/Users/ada/.aws") (subpath "/Users/ada/.nd7"))

;; Writable: the project, the temp dir, Claude Code's scratch directories, and
;; each agent's own state, `~/.claude` and `~/.codex`. HOME is matched as a
;; subpath rather than spliced into the regex, because escaping a path into a
;; regex is error-prone.
(allow file-write* (subpath "/Users/ada/proj") (subpath "/private/tmp") (regex #"^/private/tmp/claude-") (require-all (subpath "/Users/ada") (regex #"/\.claude(/|$)")) (require-all (subpath "/Users/ada") (regex #"/\.codex(/|$)")))

;; DNS, network configuration and the keychain: what an HTTPS client needs.
(allow mach-lookup (global-name "com.apple.dnssd.service") (global-name "com.apple.SystemConfiguration.configd") (global-name "com.apple.SecurityServer"))
(allow network-outbound (literal "/private/var/run/mDNSResponder"))
;; A wildcard host with an exact port matches; a wildcard port would not.
(allow network-outbound (remote tcp "*:443"))

;; Allow binding to ports on localhost:* and using them.
(allow network-bind (local ip "localhost:*"))
(allow network-inbound (local ip "localhost:*"))
(allow network-outbound (local ip "localhost:*"))

;; Allow socket outbound traffic to the gpg_agent
;; Here we allow only reaching a restricted socket. Never the main one.
(allow network-outbound (literal "/Users/ada/.gnupg/S.gpg-agent.extra"))
"#;

    /// The last rule of both renderings, for the policy `sample` returns.
    const DENY_RECORDS: &str = r#"
;; Last, so the last match wins: nd7's own records stay unwritable, whatever
;; the rules above allow.
(deny file-write* file-write-acl file-write-create file-write-data file-write-flags file-write-mode file-write-owner file-write-setugid file-write-unlink file-write-xattr file-link (subpath "/Users/ada/.nd7"))
"#;

    /// The rule after that one, for the policy `sample` returns.
    const DENY_AGENT_CONFIG: &str = r#"
;; And last of all, for the same reason: a session may not rewrite the hooks
;; or the sandbox settings that the next session starts with.
(deny file-write* file-write-acl file-write-create file-write-data file-write-flags file-write-mode file-write-owner file-write-setugid file-write-unlink file-write-xattr file-link (literal "/Users/ada/.codex/config.toml") (literal "/Users/ada/.codex/hooks.json") (literal "/Users/ada/.claude/settings.json"))
"#;

    fn sample() -> Policy {
        Policy {
            project: PathBuf::from("/Users/ada/proj"),
            home: PathBuf::from("/Users/ada"),
            tmp: PathBuf::from("/private/tmp"),
            exit: PathBuf::from("/usr/local/bin/nd7-exec"),
            grants: Vec::new(),
        }
    }

    #[test]
    fn floor_is_exactly_this() {
        let expected = format!(
            r#"{BODY}
;; The floor's one exit: nd7-exec, which applies the session policy to itself
;; before it runs anything. Nothing else leaves this sandbox.
(allow process-exec (with no-sandbox) (literal "/usr/local/bin/nd7-exec"))
{DENY_RECORDS}{DENY_AGENT_CONFIG}"#
        );

        assert_eq!(sample().render_floor(), expected);
    }

    #[test]
    fn policy_is_exactly_this() {
        let policy = Policy {
            grants: vec![
                PathBuf::from("/Users/ada/data"),
                PathBuf::from("/Volumes/scratch"),
            ],
            ..sample()
        };
        let expected = format!(
            r#"{BODY}
;; Write roots added by `nd7 allow` during this run.
(allow file-write* (subpath "/Users/ada/data"))
(allow file-write* (subpath "/Volumes/scratch"))
{DENY_RECORDS}{DENY_AGENT_CONFIG}"#
        );

        assert_eq!(policy.render_policy(), expected);
    }

    #[test]
    fn policy_without_grants_is_the_body_and_the_deny() {
        assert_eq!(
            sample().render_policy(),
            format!("{BODY}{DENY_RECORDS}{DENY_AGENT_CONFIG}")
        );
    }

    #[test]
    fn grants_and_the_exit_belong_to_one_rendering_each() {
        let policy = Policy {
            grants: vec![PathBuf::from("/Users/ada/data")],
            ..sample()
        };

        assert!(policy.render_policy().contains("/Users/ada/data"));
        assert!(!policy.render_floor().contains("/Users/ada/data"));

        assert!(policy.render_floor().contains("/usr/local/bin/nd7-exec"));
        assert!(!policy.render_policy().contains("/usr/local/bin/nd7-exec"));
        assert!(!policy.render_policy().contains("no-sandbox"));
    }

    #[test]
    fn sbpl_string_escapes_quotes_and_backslashes() {
        assert_eq!(sbpl_string(Path::new("/a/b")), r#""/a/b""#);
        assert_eq!(
            sbpl_string(Path::new(r#"/a b/"c"/d\e"#)),
            r#""/a b/\"c\"/d\\e""#
        );
    }

    #[test]
    fn serde_round_trip() {
        let policy = Policy {
            grants: vec![PathBuf::from("/Users/ada/data")],
            ..sample()
        };
        let json = serde_json::to_string(&policy).unwrap();

        assert_eq!(serde_json::from_str::<Policy>(&json).unwrap(), policy);
    }

    #[cfg(target_os = "macos")]
    mod kernel {
        //! These hand the rendered profiles to the kernel, which is the only
        //! judge of whether they compile and of what they permit.

        use super::*;
        use std::{fs, process::Output};

        /// A fresh empty directory for one test, named after the test and
        /// this pid. Canonical, because `subpath` matches resolved paths.
        fn scratch(name: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("nd7-policy-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            dir.canonicalize().unwrap()
        }

        /// Runs `/usr/bin/true` under `profile`: the profile compiles, and a
        /// program can still start, or this fails.
        fn compiles(profile: &str) {
            let status = crate::sandbox::spawn_with_profile(profile, "/usr/bin/true", &[])
                .status()
                .unwrap_or_else(|e| panic!("{e}\n{profile}"));
            assert!(status.success(), "{profile}");
        }

        /// `echo x > target` under `profile`. The path is an argument rather
        /// than part of the script, so awkward paths stay data.
        fn write_probe(profile: &str, target: &Path) -> Output {
            crate::sandbox::spawn_with_profile(profile, "/bin/sh", &[])
                .args(["-c", r#"echo x > "$1""#, "_", &target.to_string_lossy()])
                .output()
                .unwrap()
        }

        fn assert_denied(profile: &str, target: &Path) {
            let out = write_probe(profile, target);
            let stderr = String::from_utf8_lossy(&out.stderr);
            assert_eq!(out.status.code(), Some(1), "stderr: {stderr}");
            assert!(
                stderr.contains("Operation not permitted"),
                "stderr: {stderr}"
            );
            assert!(!target.exists(), "{}", target.display());
        }

        fn assert_allowed(profile: &str, target: &Path) {
            let out = write_probe(profile, target);
            assert!(
                out.status.success(),
                "stderr: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(fs::read_to_string(target).unwrap(), "x\n");
        }

        /// A policy over `home`, with `/usr/bin/true` as a stand-in exit.
        fn over(home: &Path, grants: Vec<PathBuf>) -> Policy {
            Policy {
                project: home.join("proj"),
                home: home.to_path_buf(),
                tmp: PathBuf::from("/private/tmp"),
                exit: PathBuf::from("/usr/bin/true"),
                grants,
            }
        }

        #[test]
        fn both_renderings_compile() {
            let root = scratch("compiles");
            let policy = over(&root, Vec::new());
            compiles(&policy.render_floor());
            compiles(&policy.render_policy());

            // A quote and a space in the project path: if `sbpl_string` got
            // the escaping wrong, the profile would not parse.
            let policy = Policy {
                project: root.join(r#"nd7 "proj""#),
                grants: vec![root.join(r#"grant "one""#)],
                ..policy
            };
            compiles(&policy.render_floor());
            compiles(&policy.render_policy());

            fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn a_grant_over_home_still_cannot_write_the_records() {
            let root = scratch("grant-home");
            fs::create_dir_all(root.join(".nd7")).unwrap();
            let profile = over(&root, vec![root.clone()]).render_policy();

            assert_denied(&profile, &root.join(".nd7/probe"));
            assert_allowed(&profile, &root.join("elsewhere"));

            fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn a_session_writes_its_agent_state_but_not_its_configuration() {
            let root = scratch("agent-state");
            fs::create_dir_all(root.join(".codex/sessions")).unwrap();
            let policy = over(&root, Vec::new());

            for profile in [policy.render_policy(), policy.render_floor()] {
                assert_allowed(&profile, &root.join(".codex/sessions/x"));
                assert_denied(&profile, &root.join(".codex/config.toml"));
            }

            fs::remove_dir_all(&root).unwrap();
        }

        #[test]
        fn the_floor_cannot_write_the_records_either() {
            let root = scratch("floor-home");
            fs::create_dir_all(root.join(".nd7")).unwrap();
            // The project is the home here, so the write rule above covers
            // `.nd7` and only the final deny can stop it.
            let profile = Policy {
                project: root.clone(),
                ..over(&root, Vec::new())
            }
            .render_floor();

            assert_denied(&profile, &root.join(".nd7/probe"));
            assert_allowed(&profile, &root.join("elsewhere"));

            fs::remove_dir_all(&root).unwrap();
        }
    }
}
