//! The session directory: how `nd7 run` tells `nd7-exec` what this run may do.
//!
//! One `nd7 run` owns `<root>/<its pid>/`, holding `record.json` (the
//! [`Policy`] itself, for `nd7 allow` to amend) and `policy.sb` (the profile
//! `nd7-exec` applies to each command). `nd7-exec` walks its ancestry until
//! one of those pids names a directory, so the session is found by process
//! tree rather than by anything the caller could set.
//!
//! The directory goes when the [`Session`] handle drops. A run that is killed
//! outright leaves one behind, so every [`Session::create`] first sweeps the
//! directories whose process is gone.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::policy::Policy;

/// One `nd7 run`: a directory named after its pid, holding the policy that
/// `nd7-exec` applies to each command. Removed when dropped.
pub struct Session {
    dir: PathBuf,
}

impl Session {
    /// Sweeps the stale sessions under `root`, then creates this process's
    /// own and writes `policy` into it.
    pub fn create(root: &Path, policy: &Policy) -> io::Result<Session> {
        fs::create_dir_all(root)?;
        Self::sweep(root)?;

        let dir = root.join(std::process::id().to_string());
        fs::create_dir_all(&dir)?;
        write_policy_at(&dir, policy)?;
        Ok(Session { dir })
    }

    /// Rewrites this session's policy, for `nd7 allow`.
    pub fn write_policy(&self, policy: &Policy) -> io::Result<()> {
        write_policy_at(&self.dir, policy)
    }

    /// Where this session lives.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Removes the `<root>/<pid>` directories whose process is gone, and
    /// returns how many. Entries that are not named after a pid are left
    /// alone: this sweeps nd7's own leftovers, not the directory.
    pub fn sweep(root: &Path) -> io::Result<usize> {
        let mut removed = 0;
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Ok(pid) = name.parse::<libc::pid_t>() else {
                continue;
            };
            // Signal 0 checks for the process without sending anything.
            // ESRCH is the only answer that means it is gone; EPERM means it
            // is alive and someone else's.
            if unsafe { libc::kill(pid, 0) } == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
            {
                fs::remove_dir_all(entry.path())?;
                removed += 1;
            }
        }
        Ok(removed)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // Best effort: whatever survives is swept by the next `nd7 run`.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Writes `record.json` and `policy.sb` into `dir`. Both go through a
/// temporary file in the same directory and a rename, so `nd7-exec` never
/// reads half a profile. `nd7 allow` amends a session it does not own, so
/// this is a free function rather than a method on [`Session`].
pub fn write_policy_at(dir: &Path, policy: &Policy) -> io::Result<()> {
    let record = serde_json::to_string_pretty(policy).map_err(io::Error::other)?;
    write_atomic(&dir.join("record.json"), &record)?;
    write_atomic(&dir.join("policy.sb"), &policy.render_policy())
}

/// The policy recorded for the session of `pid`.
pub fn load(root: &Path, pid: u32) -> io::Result<Policy> {
    let record = fs::read_to_string(root.join(pid.to_string()).join("record.json"))?;
    serde_json::from_str(&record).map_err(io::Error::other)
}

fn write_atomic(path: &Path, contents: &str) -> io::Result<()> {
    let mut name = path.as_os_str().to_owned();
    name.push(".tmp");
    let tmp = PathBuf::from(name);

    fs::write(&tmp, contents)?;
    fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    /// A fresh empty sessions root for one test, named after the test and
    /// this pid. Never the real `~/.nd7`.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nd7-session-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> Policy {
        Policy {
            project: PathBuf::from("/Users/ada/proj"),
            home: PathBuf::from("/Users/ada"),
            tmp: PathBuf::from("/private/tmp"),
            exit: PathBuf::from("/usr/local/bin/nd7-exec"),
            grants: Vec::new(),
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn create_writes_the_policy_and_drop_takes_it_away() {
        let root = scratch("create");
        let policy = sample();

        let dir = {
            let session = Session::create(&root, &policy).unwrap();
            assert_eq!(
                session.dir(),
                root.join(std::process::id().to_string()).as_path()
            );

            let record = fs::read_to_string(session.dir().join("record.json")).unwrap();
            assert_eq!(serde_json::from_str::<Policy>(&record).unwrap(), policy);
            assert_eq!(
                fs::read_to_string(session.dir().join("policy.sb")).unwrap(),
                policy.render_policy()
            );
            session.dir().to_path_buf()
        };

        assert!(!dir.exists());

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn writing_again_replaces_the_policy_and_leaves_nothing_behind() {
        let root = scratch("rewrite");
        let mut policy = sample();
        let session = Session::create(&root, &policy).unwrap();
        let before = fs::read_to_string(session.dir().join("policy.sb")).unwrap();

        policy.grants.push(PathBuf::from("/Volumes/scratch"));
        session.write_policy(&policy).unwrap();

        let after = fs::read_to_string(session.dir().join("policy.sb")).unwrap();
        assert_ne!(before, after);
        assert!(after.contains("/Volumes/scratch"));
        assert_eq!(names(session.dir()), ["policy.sb", "record.json"]);

        drop(session);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn load_returns_the_recorded_policy() {
        let root = scratch("load");
        let policy = Policy {
            grants: vec![PathBuf::from("/Volumes/scratch")],
            ..sample()
        };
        let session = Session::create(&root, &policy).unwrap();

        assert_eq!(load(&root, std::process::id()).unwrap(), policy);

        drop(session);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn sweep_removes_only_the_sessions_whose_process_is_gone() {
        let root = scratch("sweep");
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let dead = child.id().to_string();
        child.wait().unwrap();
        let alive = std::process::id().to_string();

        for name in [dead.as_str(), alive.as_str(), "not-a-pid"] {
            fs::create_dir_all(root.join(name)).unwrap();
        }

        assert_eq!(Session::sweep(&root).unwrap(), 1);
        assert_eq!(names(&root), [alive.as_str(), "not-a-pid"]);

        fs::remove_dir_all(&root).unwrap();
    }
}
