//! nd7 core: a flight recorder for AI coding agents.
//!
//! This library holds everything the binaries share:
//!
//! - [`hook`]: Claude Code hook payload types, the nd7 event model, and the
//!   transform between them. Pure; no I/O.
//! - [`session_log`]: the append-only per-session log. The only module that knows
//!   where events live on disk.

pub mod hook;
pub mod session_log;
