//! `nd7-exec`: the one program the outer Seatbelt profile lets out of the
//! sandbox. It applies the current session policy to itself and becomes the
//! shell that runs the command. It never writes anything.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
use std::{
    env::args,
    ffi::{c_char, c_int, c_void},
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
};

#[cfg(target_os = "macos")]
use nd7_core::sandbox;

#[cfg(target_os = "macos")]
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("nd7-exec: only supported on macOS");
    ExitCode::from(2)
}

#[cfg(target_os = "macos")]
#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, r#type: c_int, ...) -> c_int;
}

#[cfg(target_os = "macos")]
const USAGE: &str = "usage: nd7-exec -c <command>

Runs <command> with /bin/zsh -c under the nd7 policy of the session this
process was started in. Pass the whole command as one argument, quoted, the
way you would to `zsh -c`. Claude Code's Bash tool adds this prefix through
the hook that `nd7 run` installs; the command is otherwise denied by the
outer sandbox.

exit status: the command's; 2 for a usage error; 126 if the command was not
run: no nd7 session, no policy, the policy could not be applied, or the shell
could not be executed.";

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    match parse_args(args().skip(1)) {
        Some(cmd) => run(&cmd),
        None => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

#[cfg(target_os = "macos")]
/// Exactly `-c <command>`, and nothing else.
fn parse_args(mut args: impl Iterator<Item = String>) -> Option<String> {
    match args.next().as_deref() {
        Some("-c") => match args.next() {
            Some(cmd) if args.next().is_none() => Some(cmd),
            _ => None, // missing command, or something after it
        },
        _ => None, // unknown flag, or no arguments
    }
}

#[cfg(target_os = "macos")]
fn run(cmd: &str) -> ExitCode {
    if confined() {
        return exec_shell(cmd);
    }
    // Out of the outer sandbox now: the only way to a shell is through a
    // successfully applied session policy.
    let sessions_dir = match sessions_dir() {
        Ok(p) => p,
        Err(e) => return refuse(&e.to_string()),
    };
    let Some(session) = find_session(&sessions_dir) else {
        return refuse("no nd7 session in this process's ancestry");
    };
    match policy(session) {
        Some(policy) => exec_with_policy(&policy, cmd),
        None => refuse("session has no policy.sb"),
    }
}

#[cfg(target_os = "macos")]
/// The command is not run. Says why on stderr, with our name first so the
/// reader can tell nd7 apart from the shell and from Claude Code.
fn refuse(why: &str) -> ExitCode {
    eprintln!("nd7-exec: {why}");
    ExitCode::from(126)
}

#[cfg(target_os = "macos")]
fn exec_with_policy(policy: &Path, cmd: &str) -> ExitCode {
    let profile = match std::fs::read_to_string(policy) {
        Ok(p) => p,
        Err(e) => return refuse(&format!("read {}: {e}", policy.display())),
    };
    match sandbox::apply_to_self(&profile) {
        Ok(()) => exec_shell(cmd),
        Err(e) => refuse(&format!("apply session policy: {e}")),
    }
}

#[cfg(target_os = "macos")]
/// Where the session records live. The environment is the caller's, and the
/// caller is what we are defending against, so this is `~/.nd7/sessions`
/// with `~` from passwd, via the library. `ND7_SESSIONS_DIR` is a test seam and is only
/// compiled in under the `test-seams` feature, never in a release build.
fn sessions_dir() -> Result<PathBuf> {
    #[cfg(feature = "test-seams")]
    if let Some(dir) = std::env::var_os("ND7_SESSIONS_DIR") {
        return Ok(PathBuf::from(dir));
    }
    Ok(nd7_core::session::sessions_root()?)
}

#[cfg(target_os = "macos")]
fn find_session(sessions_dir: &Path) -> Option<PathBuf> {
    let mut pid = unsafe { libc::getppid() };
    while pid > 1 {
        let dir = sessions_dir.join(pid.to_string());
        if dir.is_dir() {
            return Some(dir);
        }
        pid = parent_of(pid)?;
    }
    None
}

#[cfg(target_os = "macos")]
fn parent_of(pid: libc::pid_t) -> Option<libc::pid_t> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as c_int;

    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            &mut info as *mut _ as *mut c_void,
            size,
        )
    };
    (n == size).then_some(info.pbi_ppid as libc::pid_t)
}

#[cfg(target_os = "macos")]
fn policy(session: PathBuf) -> Option<PathBuf> {
    let policy_path = session.join("policy.sb");
    policy_path.exists().then_some(policy_path)
}

#[cfg(target_os = "macos")]
fn exec_shell(cmd: &str) -> ExitCode {
    // Exec, not spawn: this process becomes the shell. There is no
    // intermediary to orphan the command when Claude Code kills it, and the
    // shell's exit status is ours.
    let err = Command::new("/bin/zsh").arg("-c").arg(cmd).exec();
    // Only reached if exec failed; on success the process image is replaced.
    eprintln!("nd7-exec: exec /bin/zsh: {err}");
    ExitCode::from(126)
}

#[cfg(target_os = "macos")]
fn confined() -> bool {
    unsafe { sandbox_check(libc::getpid(), std::ptr::null(), 0) != 0 }
}

#[cfg(target_os = "macos")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A fresh empty directory for one test, named after the test and this pid.
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nd7-exec-unit-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn parse(args: &[&str]) -> Option<String> {
        parse_args(args.iter().map(|a| (*a).to_owned()))
    }

    #[test]
    fn parse_args_takes_exactly_dash_c_and_a_command() {
        assert_eq!(parse(&["-c", "x"]).as_deref(), Some("x"));
        assert_eq!(parse(&["-c"]), None);
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["-c", "a", "b"]), None);
        assert_eq!(parse(&["-x", "y"]), None);
    }

    #[test]
    fn parent_of_this_process_is_our_parent() {
        let me = unsafe { libc::getpid() };
        let parent = unsafe { libc::getppid() };
        assert_eq!(parent_of(me), Some(parent));
    }

    #[test]
    fn parent_of_a_pid_that_does_not_exist_is_none() {
        assert_eq!(parent_of(2_000_000_000), None);
    }

    #[test]
    fn find_session_returns_the_ancestors_directory() {
        let dir = scratch("find-session");
        let parent = unsafe { libc::getppid() };
        let session = dir.join(parent.to_string());
        fs::create_dir_all(&session).unwrap();

        assert_eq!(find_session(&dir), Some(session));

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn find_session_ignores_an_unrelated_pid() {
        let dir = scratch("unrelated-pid");
        fs::create_dir_all(dir.join("999999999")).unwrap();

        assert_eq!(find_session(&dir), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn find_session_starts_at_the_parent_not_at_us() {
        // Our own pid is not in the walk: a caller cannot make itself a session.
        let dir = scratch("own-pid");
        fs::create_dir_all(dir.join(std::process::id().to_string())).unwrap();

        assert_eq!(find_session(&dir), None);

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn policy_is_found_only_when_the_file_is_there() {
        let dir = scratch("policy");
        assert_eq!(policy(dir.clone()), None);

        let path = dir.join("policy.sb");
        fs::write(&path, "(version 1)\n").unwrap();
        assert_eq!(policy(dir.clone()), Some(path));

        fs::remove_dir_all(&dir).unwrap();
    }
}
