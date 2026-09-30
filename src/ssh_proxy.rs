//! The ssh-agent socket `nd7 run` hands the program in place of the user's
//! own. It forwards every message and names it in `<state root>/ssh-agent.log`;
//! what each message means lives in [`crate::ssh_agent`].

use std::{
    io::{self, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::ssh_agent::{Message, read_frame, write_frame};

/// Serves `sock` as the program's ssh-agent: each connection is one thread
/// that forwards every request to the agent at `upstream` and every reply
/// back, and names each message on one line of `log`. For now everything
/// is forwarded. Returns once the socket is bound and the log is open.
pub fn serve(sock: &Path, upstream: PathBuf, log: &Path) -> io::Result<()> {
    let log = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(log)?,
    ));
    let listener = UnixListener::bind(sock)?;
    thread::spawn(move || {
        for (conn, mut client) in listener.incoming().flatten().enumerate() {
            let (upstream, log) = (upstream.clone(), Arc::clone(&log));
            thread::spawn(move || {
                let Ok(mut agent) = UnixStream::connect(upstream) else {
                    return;
                };
                let note = |dir: &str, frame: &[u8]| {
                    let at = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    // ssh must never wait on the log, so a write that
                    // fails is one line lost, not an error.
                    if let Ok(mut log) = log.lock() {
                        let _ = writeln!(
                            log,
                            "{at} {} {} {dir} {}",
                            std::process::id(),
                            conn + 1,
                            Message::parse(frame)
                        );
                    }
                };
                loop {
                    let Ok(request) = read_frame(&mut client) else {
                        return;
                    };
                    note(">", &request);
                    let Ok(reply) =
                        write_frame(&mut agent, &request).and_then(|()| read_frame(&mut agent))
                    else {
                        return;
                    };
                    note("<", &reply);
                    if write_frame(&mut client, &reply).is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;

    use super::*;

    /// Not the canonical temp dir: a socket path there is close to macOS's
    /// limit of 103 bytes.
    fn scratch(name: &str) -> PathBuf {
        let root = PathBuf::from(format!(
            "/private/tmp/nd7-ssh-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn a_request_and_its_reply_cross_the_proxy_and_the_log() {
        let root = scratch("proxy");
        let (agent, sock, log) = (
            root.join("agent.sock"),
            root.join("ssh.sock"),
            root.join("ssh-agent.log"),
        );

        let listener = UnixListener::bind(&agent).unwrap();
        thread::spawn(move || {
            for mut conn in listener.incoming().flatten() {
                thread::spawn(move || {
                    while read_frame(&mut conn).is_ok() {
                        if write_frame(&mut conn, &[12, 0, 0, 0, 0]).is_err() {
                            return;
                        }
                    }
                });
            }
        });

        serve(&sock, agent, &log).unwrap();

        let mut client = UnixStream::connect(&sock).unwrap();
        write_frame(&mut client, &[11]).unwrap();
        assert_eq!(read_frame(&mut client).unwrap(), [12, 0, 0, 0, 0]);
        drop(client);

        let lines: Vec<String> = fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].ends_with("1 > REQUEST_IDENTITIES"), "{lines:?}");
        assert!(
            lines[1].ends_with("1 < IDENTITIES_ANSWER 0 keys"),
            "{lines:?}"
        );

        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn serve_fails_when_the_socket_path_is_taken() {
        let root = scratch("taken");
        let sock = root.join("ssh.sock");
        fs::write(&sock, "").unwrap();

        assert!(serve(&sock, root.join("agent.sock"), &root.join("ssh-agent.log")).is_err());

        fs::remove_dir_all(&root).unwrap();
    }
}
