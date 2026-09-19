//! Claude Code hook handling: payload types, the nd7 event model, and the
//! transform from one to the other.
//!
//! - [`input`]: typed model of every Claude Code hook payload.
//! - [`event`]: the nd7 envelope and body.
//! - [`invocation`]: facts about this hook invocation (time, host, parent
//!   pid). [`Event::new`] joins them with a payload.
//!
//! Nothing here touches the filesystem; see [`crate::session_log`] for that.

pub mod event;
pub mod input;
pub mod invocation;

pub use event::Event;
pub use input::HookInput;
pub use invocation::Invocation;
