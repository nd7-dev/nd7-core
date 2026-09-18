//! Claude Code hook handling: payload types, the nd7 event model, and the
//! transform from one to the other.
//!
//! - [`input`]: typed model of every Claude Code hook payload.
//! - [`event`]: the nd7 envelope and body.
//! - [`recorder`]: invocation-side facts (time, host, parent pid) and the
//!   transform that produces an [`Event`].
//!
//! Nothing here touches the filesystem; see [`crate::writer`] for that.

pub mod event;
pub mod input;
pub mod recorder;

pub use event::Event;
pub use input::HookInput;
pub use recorder::Recorder;
