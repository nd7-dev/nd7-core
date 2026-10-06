use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    os::unix::net::{UnixListener, UnixStream},
    path::Path,
    sync::{Arc, Mutex},
    thread::spawn,
    time::{SystemTime, UNIX_EPOCH},
};

fn handle_open_command(mut stream: UnixStream, log: Arc<Mutex<File>>) -> std::io::Result<()> {
    let mut reader = BufReader::new(&stream);
    let mut cmd = String::new();
    reader.read_line(&mut cmd)?;
    if let Ok(mut log) = log.lock() {
        let at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let _ = write!(log, "{at} {cmd}");
    }
    let _ = stream.write_all(b"OK");
    Ok(())
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
        for (_, client) in listener.incoming().flatten().enumerate() {
            let log = log.clone();
            spawn(move || {
                let _ = handle_open_command(client, log);
            });
        }
    });
    Ok(())
}

#[cfg(test)]
mod test {
    use std::io::{Read, Write};
    use std::{fs, os::unix::net::UnixStream, path::PathBuf};

    use crate::open_proxy::serve;

    fn scratch() -> PathBuf {
        let tmp_dir = std::env::temp_dir();
        let root = tmp_dir.join(format!("/nd7-open-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
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
        // intersperse is not stable yet in rust. Using this library instead. Only in tests.
        let b: String = buf.split_once(" ").unwrap().1.to_string();
        assert_eq!(b.trim(), cmd.trim())
    }
}
