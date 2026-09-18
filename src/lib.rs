//! nd7 core: a flight recorder for AI coding agents.
//!
//! This library holds everything the binaries share. Phase 1 is one module:
//!
//! - [`hook`]: Claude Code hook payload types, the transform into nd7 events,
//!   and building the frame appended to a session log.

pub mod hook;
