//! `nd7-exec`: the one program the outer Seatbelt profile lets out of the
//! sandbox. It applies the current session policy to itself and becomes the
//! shell that runs the command. It never writes anything.

use std::{
    env::args,
    ffi::{CStr, OsStr, c_char, c_int, c_void},
    os::unix::{ffi::OsStrExt, process::CommandExt},
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

use nd7_core::sandbox;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_check(pid: libc::pid_t, operation: *const c_char, r#type: c_int, ...) -> c_int;
}

const USAGE: &str = "usage: nd7-exec -c <command>

Runs <command> with /bin/zsh -c under the nd7 policy of the session this
process was started in. Pass the whole command as one argument, quoted, the
way you would to `zsh -c`. Claude Code's Bash tool adds this prefix through
the hook that `nd7 run` installs; the command is otherwise denied by the
outer sandbox.

exit status: the command's; 2 for a usage error; 126 if the command was not
run: no nd7 session, no policy, the policy could not be applied, or the shell
could not be executed.";

fn main() -> ExitCode {
    let mut args = args().skip(1);
    let usage = || {
        eprintln!("{USAGE}");
        ExitCode::from(2)
    };
    match args.next().as_deref() {
        Some("-c") => match args.next() {
            Some(cmd) if args.next().is_none() => run(&cmd),
            _ => usage(), // missing command, or something after it
        },
        _ => usage(), // unknown flag, or no arguments
    }
}

fn run(cmd: &str) -> ExitCode {
    if confined() {
        return exec_shell(cmd);
    }
    // Out of the outer sandbox now: the only way to a shell is through a
    // successfully applied session policy.
    let home = match home() {
        Ok(p) => p,
        Err(e) => return refuse(&e.to_string()),
    };
    let sessions_dir = home.join(".nd7/sessions");
    let Some(session) = find_session(&sessions_dir) else {
        return refuse("no nd7 session in this process's ancestry");
    };
    match policy(session) {
        Some(policy) => exec_with_policy(&policy, cmd),
        None => refuse("session has no policy.sb"),
    }
}

/// The command is not run. Says why on stderr, with our name first so the
/// reader can tell nd7 apart from the shell and from Claude Code.
fn refuse(why: &str) -> ExitCode {
    eprintln!("nd7-exec: {why}");
    ExitCode::from(126)
}

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

fn home() -> Result<PathBuf> {
    let pw = unsafe { libc::getpwuid(libc::getuid()) };
    if pw.is_null() {
        return Err("no passwd entry for current user".into());
    }
    let dir = unsafe { CStr::from_ptr((*pw).pw_dir) };
    let path = PathBuf::from(OsStr::from_bytes(dir.to_bytes()));
    Ok(path)
}

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

fn policy(session: PathBuf) -> Option<PathBuf> {
    let policy_path = session.join("policy.sb");
    policy_path.exists().then_some(policy_path)
}

fn exec_shell(cmd: &str) -> ExitCode {
    // Exec, not spawn: this process becomes the shell. There is no
    // intermediary to orphan the command when Claude Code kills it, and the
    // shell's exit status is ours.
    let err = Command::new("/bin/zsh").arg("-c").arg(cmd).exec();
    // Only reached if exec failed; on success the process image is replaced.
    eprintln!("nd7-exec: exec /bin/zsh: {err}");
    ExitCode::from(126)
}

fn confined() -> bool {
    unsafe { sandbox_check(libc::getpid(), std::ptr::null(), 0) != 0 }
}
