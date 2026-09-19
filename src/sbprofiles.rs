//! Seatbelt profiles shipped in the binary. Each file's header comment lists
//! the `(param "NAME")` values it expects.

/// Profile for the claude process and everything it spawns.
pub const CLAUDE: &str = include_str!("sbprofiles/claude.sb");
