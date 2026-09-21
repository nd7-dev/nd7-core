//! `nd7-exec`: the one program the outer Seatbelt profile lets out of the
//! sandbox. It applies the current session policy to itself and becomes the
//! shell that runs the command. It never writes anything.

use std::{
    env::args,
    os::unix::process::CommandExt,
    process::{Command, ExitCode},
};

const USAGE: &str = "usage: nd7-exec -c <command>

Runs <command> with /bin/zsh -c under the nd7 policy of the session this
process was started in. Pass the whole command as one argument, quoted, the
way you would to `zsh -c`. Claude Code's Bash tool adds this prefix through
the hook that `nd7 run` installs; the command is otherwise denied by the
outer sandbox.

exit status: the command's; 2 for a usage error; 126 if the shell could not
be executed.";

fn main() -> ExitCode {
    let mut args = args().skip(1);
    let usage = || {
        // A lambda function
        eprintln!("{USAGE}");
        ExitCode::from(2)
    };
    match args.next().as_deref() {
        Some("-c") => match args.next() {
            Some(cmd) if args.next().is_none() => exec_shell(&cmd),
            _ => usage(), // missing command, or something after it
        },
        _ => usage(), // unknown flag, or no arguments
    }
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
