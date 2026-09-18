mod hook;

use std::{
    env::temp_dir,
    fs,
    io::{self, Read, Write},
    thread::spawn,
};

use hook::HookInput;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> Result<()> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;

    // One summary line per invocation, then the raw payload. Parse failures
    // are logged, never fatal: a hook must not interfere with the session.
    let summary = match HookInput::parse(&raw) {
        Ok(input) => format!(
            "# {} session={} cwd={}\n",
            input.event.name(),
            input.common.session_id,
            input.common.cwd
        ),
        Err(e) => format!("# unparsed: {e}\n"),
    };

    let mut path = temp_dir();
    path.push("claude_code_hook.log");
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)?;

    let h = spawn(move || -> io::Result<()> {
        f.write_all(summary.as_bytes())?;
        f.write_all(raw.as_bytes())?;
        f.write_all(b"\n")
    });
    let _ = h.join();
    Ok(())
}
