//! Facts about one hook invocation that the payload does not carry: when it
//! ran, on which host, and under which parent process.

use std::time::{SystemTime, UNIX_EPOCH};

/// Plain data. Build one per invocation with [`Invocation::now`] before
/// reading stdin, so `ts` marks when the hook fired rather than when parsing
/// finished. Producers that get these facts elsewhere fill the fields directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// Unix epoch nanoseconds, UTC.
    pub ts: i64,
    /// Hostname of the machine producing the event.
    pub host: String,
    /// Parent pid. With exec-form registration this is the `claude` process.
    pub hook_ppid: u32,
}

impl Invocation {
    /// Capture the current environment.
    pub fn now() -> Invocation {
        Invocation {
            ts: now_ns(),
            host: hostname(),
            hook_ppid: hook_ppid(),
        }
    }
}

/// Unix epoch nanoseconds now.
pub fn now_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: buf is valid for writes of its full length; gethostname
    // NUL-terminates within it on success.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    if rc == 0 {
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        if let Ok(s) = std::str::from_utf8(&buf[..end]) {
            return s.to_owned();
        }
    }
    "unknown".to_owned()
}

fn hook_ppid() -> u32 {
    // SAFETY: getppid has no preconditions and cannot fail.
    unsafe { libc::getppid() as u32 }
}
