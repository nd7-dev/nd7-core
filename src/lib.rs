//! nd7 core: a flight recorder for AI coding agents.
//!
//! This library holds everything the binaries share:
//!
//! - [`hook`]: Claude Code hook payload types, the nd7 event model, and the
//!   transform between them. Pure; no I/O.
//! - [`session_log`]: the append-only per-session log. The only module that knows
//!   where events live on disk.
//! - [`ship`]: `nd7 enroll` and `nd7 ship`, the machine's half of the vault
//!   protocol: the session directory, the vault's own state, and the
//!   network.
//! - [`vault`]: the wire format and cryptography the machine and the vault
//!   server share. Pure; no I/O.

pub mod hook;
#[cfg(target_os = "macos")]
pub mod sandbox;
pub mod session_log;
pub mod ship;
pub mod vault;
