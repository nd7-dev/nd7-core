//! The `open` socket `nd7 run` serves in the session directory. A shim named
//! `open`, first on the program's PATH, sends its arguments here one per line;
//! the broker opens a single URL with the real `/usr/bin/open`, from outside
//! the sandbox, and refuses everything else. Every request lands on one line
//! of `<state root>/open.log`: time, pid, connection, verdict, arguments.
//!
//! Why a broker and not a profile rule: the app that receives an Apple Event
//! refuses it from any sandboxed sender, whatever Seatbelt allows, so the
//! event has to come from the one process without a profile.

use std::{
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

/// Serves `sock`: each connection is one request, answered with `ok`,
/// `refused: <why>` or `error: <what>`, and noted on one line of `log`.
/// `opener` is the program a URL is handed to, `/usr/bin/open` outside
/// tests. Returns once the socket is bound and the log is open.
pub fn serve(sock: &Path, log: &Path, opener: &Path) -> io::Result<()> {
    let log = Arc::new(Mutex::new(
        OpenOptions::new().append(true).create(true).open(log)?,
    ));
    let listener = UnixListener::bind(sock)?;
    let opener: PathBuf = opener.to_path_buf();
    thread::spawn(move || {
        for (index, client) in listener.incoming().flatten().enumerate() {
            let (log, opener) = (Arc::clone(&log), opener.clone());
            thread::spawn(move || handle(index, client, &opener, &log));
        }
    });
    Ok(())
}

fn handle(index: usize, mut stream: UnixStream, opener: &Path, log: &Mutex<File>) {
    let args: Vec<String> = BufReader::new(&stream)
        .lines()
        .map_while(Result::ok)
        .collect();

    let (verdict, reply) = match check(&args) {
        Err(why) => ("refuse", format!("refused: {why}")),
        Ok(url) => match Command::new(opener).arg(url).status() {
            Ok(status) if status.success() => ("allow", "ok".to_string()),
            Ok(status) => (
                "error",
                format!("error: {} exited with {status}", opener.display()),
            ),
            Err(e) => ("error", format!("error: {}: {e}", opener.display())),
        },
    };

    let at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // The caller must never wait on the log, so a write that fails is one
    // line lost, not an error.
    if let Ok(mut log) = log.lock() {
        let _ = writeln!(
            log,
            "{at} {} {index} {verdict} {}",
            std::process::id(),
            args.join(" ")
        );
    }
    let _ = writeln!(stream, "{reply}");
}

/// The one shape of request the broker opens: a single URL with a plain
/// host, `https` anywhere or `http` to this machine only, so a session can
/// show the user a dev server it started. Everything else is refused by
/// name, so the reply says what the caller got wrong.
fn check(args: &[String]) -> Result<&str, &'static str> {
    /// Hosts that name this machine, where a plain http dev server lives.
    const LOOPBACK: [&str; 2] = ["localhost", "127.0.0.1"];
    let url = match args {
        [] => return Err("nothing to open"),
        [url] => url.as_str(),
        _ => return Err("one URL at a time"),
    };
    if url.len() > 8 * 1024 {
        return Err("URL too long");
    }
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("URL contains whitespace or control characters");
    }
    let (secure, rest) = match (url.strip_prefix("https://"), url.strip_prefix("http://")) {
        (Some(rest), _) => (true, rest),
        (None, Some(rest)) => (false, rest),
        (None, None) => return Err("only http(s) URLs"),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err("URL has no host");
    }
    if !secure && !LOOPBACK.contains(&host) {
        return Err("http only to localhost");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return Err("host may only contain letters, digits, dots and hyphens");
    }
    if let Some(port) = port
        && (port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()))
    {
        return Err("port must be a number");
    }
    Ok(url)
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{Read, Write},
        net::Shutdown,
        os::unix::net::UnixStream,
        path::{Path, PathBuf},
    };

    use super::{check, serve};

    fn scratch(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!("nd7-open-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    /// One request as the shim makes it: arguments as lines, then EOF.
    fn ask(sock: &Path, args: &[&str]) -> String {
        let mut client = UnixStream::connect(sock).unwrap();
        for a in args {
            writeln!(client, "{a}").unwrap();
        }
        client.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        reply
    }

    #[test]
    fn check_accepts_one_url_https_anywhere_or_http_to_this_machine() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let ok = [
            "https://claude.ai/oauth/authorize?code=true&state=x",
            "https://console.anthropic.com:443/login#top",
            "https://localhost:8080/",
            "https://example.com",
            "http://localhost:3000/",
            "http://127.0.0.1:8000/docs",
        ];
        for url in ok {
            assert_eq!(check(&args(&[url])), Ok(url), "{url}");
        }
        let refused = [
            (vec![], "nothing to open"),
            (
                vec!["https://a.example", "https://b.example"],
                "one URL at a time",
            ),
            (vec!["-a", "Calculator"], "one URL at a time"),
            (vec!["-a"], "only http(s) URLs"),
            (vec!["http://example.com"], "http only to localhost"),
            (vec!["http://localhost.evil.com/"], "http only to localhost"),
            (vec!["http://127.0.0.1.evil.com/"], "http only to localhost"),
            (vec!["http://0.0.0.0:5173/"], "http only to localhost"),
            (vec!["file:///etc/passwd"], "only http(s) URLs"),
            (
                vec!["x-apple.systempreferences:com.apple.preference"],
                "only http(s) URLs",
            ),
            (vec!["/Applications/Calculator.app"], "only http(s) URLs"),
            (vec!["https://"], "URL has no host"),
            (vec!["https:///path"], "URL has no host"),
            (
                vec!["https://user@example.com/"],
                "host may only contain letters, digits, dots and hyphens",
            ),
            (
                vec!["https://exa mple.com"],
                "URL contains whitespace or control characters",
            ),
            (
                vec!["https://example.com/\n-a"],
                "URL contains whitespace or control characters",
            ),
            (vec!["https://example.com:abc/"], "port must be a number"),
            (vec!["https://example.com:/"], "port must be a number"),
        ];
        for (v, why) in refused {
            assert_eq!(check(&args(&v)), Err(why), "{v:?}");
        }
        let long = format!("https://example.com/{}", "a".repeat(8 * 1024));
        assert_eq!(check(&args(&[&long])), Err("URL too long"));
    }

    #[test]
    fn a_url_is_opened_and_anything_else_is_refused_both_logged() {
        let root = scratch("verdicts");
        let (sock, log) = (root.join("open.sock"), root.join("open.log"));
        serve(&sock, &log, Path::new("/usr/bin/true")).unwrap();

        assert_eq!(ask(&sock, &["https://example.com/"]), "ok\n");
        assert_eq!(
            ask(&sock, &["-a", "Calculator"]),
            "refused: one URL at a time\n"
        );

        // Time and pid vary; connection, verdict and arguments do not.
        let lines: Vec<String> = fs::read_to_string(&log)
            .unwrap()
            .lines()
            .map(|l| l.splitn(3, ' ').nth(2).unwrap().to_string())
            .collect();
        assert_eq!(
            lines,
            ["0 allow https://example.com/", "1 refuse -a Calculator"]
        );
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_opener_that_fails_is_reported_as_an_error_not_a_refusal() {
        let root = scratch("opener-fails");
        let (sock, log) = (root.join("open.sock"), root.join("open.log"));
        serve(&sock, &log, Path::new("/usr/bin/false")).unwrap();

        let reply = ask(&sock, &["https://example.com/"]);
        assert!(
            reply.starts_with("error: /usr/bin/false exited with"),
            "{reply}"
        );
        assert!(
            fs::read_to_string(&log)
                .unwrap()
                .contains(" 0 error https://example.com/")
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
