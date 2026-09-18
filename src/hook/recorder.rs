//! Recorder-side facts for one hook invocation and the transform that joins
//! them with a parsed payload into an [`Event`].

use std::time::{SystemTime, UNIX_EPOCH};

use crate::hook::{
    Event, HookInput,
    event::{Body, Detail, SCHEMA_VERSION, SOURCE_CLAUDE_CODE},
};

/// What `nd7audit` knows that the payload does not: when it ran, where, and
/// under which parent process. Build one per invocation with
/// [`Recorder::now`], before reading stdin, so `ts` marks when the hook fired
/// rather than when parsing finished.
#[derive(Debug, Clone, PartialEq)]
pub struct Recorder {
    /// Unix epoch nanoseconds.
    ts: i64,
    host: String,
    /// Parent pid. With exec-form registration this is the `claude` process.
    hook_ppid: u32,
}

impl Recorder {
    /// Capture the current environment.
    pub fn now() -> Recorder {
        Recorder::new(now_ns(), hostname(), hook_ppid())
    }

    /// A recorder with given facts, for tests and for producers that get
    /// their timestamps elsewhere.
    pub fn new(ts: i64, host: String, hook_ppid: u32) -> Recorder {
        Recorder { ts, host, hook_ppid }
    }

    /// Transform a parsed payload into one event. `seq`, `prev` and `hash`
    /// are left for the writer.
    pub fn event(self, input: HookInput) -> Event {
        let HookInput { common, event, raw } = input;
        let (kind, detail) = Detail::from_hook_event(event, raw);
        let session_id = common.session_id.clone();
        let body = Body::new(common, Some(self.hook_ppid), detail);
        Event {
            v: SCHEMA_VERSION,
            session_id,
            seq: 0,
            ts: self.ts,
            host: self.host,
            source: SOURCE_CLAUDE_CODE.to_owned(),
            kind,
            prev: None,
            body,
            hash: None,
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
