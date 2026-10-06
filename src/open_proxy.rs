use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    sync::{Arc, Mutex},
    thread::spawn,
    time::{SystemTime, UNIX_EPOCH},
};

fn handle_open_command(
    index: usize,
    mut stream: UnixStream,
    log: Arc<Mutex<File>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut cmd = String::new();
    reader.read_line(&mut cmd)?;
    if let Ok(mut log) = log.lock() {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let _ = write!(log, "{at} client {index} {cmd}");
    }
    let _ = stream.write_all(b"OK");
    Ok(())
}

/// The one shape of request the broker opens: a single `https` URL with a
/// plain host. Everything else is refused by name, so the reply says what
/// the caller got wrong without saying what would get through.
fn check(args: &[String]) -> Result<&str, &'static str> {
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
    let Some(rest) = url.strip_prefix("https://") else {
        return Err("only https URLs");
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };
    if host.is_empty() {
        return Err("URL has no host");
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

pub fn serve(sock: &Path, log: &Path) -> std::io::Result<()> {
    let log = Arc::new(Mutex::new(
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(log)?,
    ));

    let listener = UnixListener::bind(sock)?;

    spawn(move || {
        for (i, client) in listener.incoming().flatten().enumerate() {
            let log = log.clone();
            spawn(move || {
                let _ = handle_open_command(i, client, log);
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::{fs, os::unix::net::UnixStream, path::PathBuf};

    use crate::open_proxy::{check, serve};

    fn scratch() -> PathBuf {
        let root = std::env::temp_dir().join(format!("nd7-open-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn check_accepts_one_plain_https_url_and_nothing_else() {
        let args = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let ok = [
            "https://claude.ai/oauth/authorize?code=true&state=x",
            "https://console.anthropic.com:443/login#top",
            "https://localhost:8080/",
            "https://example.com",
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
            (vec!["-a"], "only https URLs"),
            (vec!["http://example.com"], "only https URLs"),
            (vec!["file:///etc/passwd"], "only https URLs"),
            (
                vec!["x-apple.systempreferences:com.apple.preference"],
                "only https URLs",
            ),
            (vec!["/Applications/Calculator.app"], "only https URLs"),
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
    fn test_write_cmd_to_log() {
        let root = scratch();
        let (sock, log) = (root.join("open.sock"), root.join("process.log"));
        serve(&sock, &log).unwrap();

        let cmd = String::from("open browser https://google.com\n");
        let mut client = UnixStream::connect(&sock).unwrap();
        // Write a command to the socket
        client.write_all(cmd.as_bytes()).unwrap();

        let mut ack = String::new();
        client.read_to_string(&mut ack).unwrap();
        assert_eq!(ack, "OK");

        let mut f = fs::OpenOptions::new().read(true).open(&log).unwrap();
        let mut buf = String::new();
        let _ = f.read_to_string(&mut buf).unwrap();
        // Log expected to have:
        // <ts> open browser https://google.com\n
        // Here we trim the ts and compare only the commands because ts changes.
        let b: String = buf.split_once(" ").unwrap().1.to_string();
        assert_eq!(b.trim(), format!("client 0 {}", cmd.trim()));
    }
}
