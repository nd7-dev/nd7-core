//! The vault wire format and its cryptography, shared by the machine and the
//! server (VAULT.md §4, §5, §6).
//!
//! `nd7-vault` is a separate binary in a separate repository, but the format
//! it speaks is owned here, next to the frames it carries. Both sides depend
//! on this module so that neither can drift: the same signing bytes, the same
//! associated data, the same index fields, the same linkage rule.
//!
//! The rule that keeps that possible: **nothing in this module does I/O.**
//! No sockets, no files, no environment, no clock, no logging. Types and pure
//! functions only. The machine's `nd7 ship` supplies the network and the
//! session directory; the vault supplies the network and its database; this
//! module supplies what they have to agree on. A dependency here on anything
//! that touches the world would make the server depend on the recorder's
//! idea of where state lives, which is the one thing it must not do.
//!
//! - [`crypto`]: machine, admin and chain keys, request signatures,
//!   recipient sets, and the compress-then-encrypt batch format.
//! - [`wire`]: one serde type per request and response body, and the header
//!   names.
//! - [`index`]: building a batch's clear index from frame bytes, and the
//!   linkage check the vault runs over it.

pub mod crypto;
pub mod index;
pub mod wire;

pub use crypto::{
    AdminKey, AdminPublic, BatchAad, ChainKey, CryptoError, MachineKey, RecipientSet, SealedBatch,
    SignedRecipientSet, open_batch, seal_batch, verify_request,
};
pub use index::{LinkageError, build_index, verify_linkage};
pub use wire::IndexEntry;
