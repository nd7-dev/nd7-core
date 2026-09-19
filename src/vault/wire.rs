//! The request and response bodies of the vault protocol (VAULT.md §6), and
//! the names of the headers that sign them (§5).
//!
//! One serde type per body, field for field with the document, so the machine
//! and the vault cannot disagree about the JSON. Nothing here validates
//! anything: these types say what is on the wire, and [`super::index`] and
//! [`super::crypto`] say what it has to satisfy.
//!
//! Binary fields are `String`, holding base64 with the standard alphabet
//! (`A-Z`, `a-z`, `0-9`, `+`, `/`) and `=` padding -- what
//! `base64::engine::general_purpose::STANDARD` reads and writes. Hashes are
//! lower-case hex, as everywhere else in nd7.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::crypto::SignedRecipientSet;
use crate::session_log::Head;

/// `X-Nd7-Machine`: the vault-assigned machine id.
pub const HEADER_MACHINE: &str = "X-Nd7-Machine";
/// `X-Nd7-Timestamp`: Unix seconds from the machine's clock, decimal.
pub const HEADER_TIMESTAMP: &str = "X-Nd7-Timestamp";
/// `X-Nd7-Body`: BLAKE3 of the request body bytes as sent, hex.
pub const HEADER_BODY: &str = "X-Nd7-Body";
/// `X-Nd7-Signature`: base64 Ed25519, see [`super::crypto::verify_request`].
pub const HEADER_SIGNATURE: &str = "X-Nd7-Signature";

/// `POST /v1/enroll` request. The one unsigned request in the protocol: the
/// machine has no id yet and the vault has no key for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollRequest {
    /// The one-hour, single-use enrolment token.
    pub token: String,
    /// The machine's Ed25519 public key, base64 of 32 bytes.
    pub public_key: String,
    pub host: String,
    /// `nd7 enroll --rotate`: register this key under the machine id the
    /// host already has and retire the old one (§4.4). Absent from an
    /// ordinary enrolment, which is why it defaults rather than being
    /// required; without it a host that is already enrolled is refused.
    #[serde(default)]
    pub rotate: bool,
}

/// `POST /v1/enroll` response, `201`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollResponse {
    pub machine_id: String,
    /// The current admin key set, which the machine pins after checking it
    /// against the fingerprint in the token (§4.2).
    pub recipients: SignedRecipientSet,
}

/// `GET /v1/recipients` response, `200`.
pub type RecipientsResponse = SignedRecipientSet;

/// `GET /v1/chains/{session_id}/{host}/head` response, `200`: `{"seq": n,
/// "hash": "..."}`. A chain the vault has never seen is `404` instead.
///
/// The recorder's [`Head`] itself, not a copy of its two fields: the head the
/// vault reports and the head in the session directory are the same thing,
/// and a second type could drift from it.
pub type HeadResponse = Head;

/// One frame as the vault sees it: the only part of a batch that is not
/// encrypted. Envelope hashes and a timestamp, never `kind` and never a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexEntry {
    pub seq: u64,
    /// The previous frame's `hash`, hex.
    pub prev: String,
    /// BLAKE3 of this frame's bytes, hex, as the frame itself carries it.
    pub hash: String,
    /// Unix epoch nanoseconds, copied from the frame.
    pub ts: i64,
}

/// `POST /v1/chains/{session_id}/{host}/frames` request: one encrypted batch
/// and its clear index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FramesRequest {
    pub first_seq: u64,
    pub last_seq: u64,
    /// One entry per frame in the batch, in `seq` order.
    pub index: Vec<IndexEntry>,
    /// The chain key sealed to each current admin, keyed by
    /// [`super::crypto::AdminPublic::fingerprint`]. Present on the first
    /// batch of a chain and absent afterwards.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wraps: Option<BTreeMap<String, String>>,
    /// The XChaCha20-Poly1305 nonce, base64 of 24 bytes.
    pub nonce: String,
    /// XChaCha20-Poly1305 over zstd of the frame bytes, base64. The
    /// associated data is [`super::crypto::BatchAad`].
    pub ciphertext: String,
}

/// `POST .../frames` response, `200`: the batch is stored and the head moved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FramesAck {
    pub acked_seq: u64,
}

/// `POST .../frames` response, `409`: the batch does not continue the head
/// the vault holds. Nothing was stored, and the head it reports is what the
/// machine has to resume from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictResponse {
    pub expected_seq: u64,
    pub head_hash: String,
}

/// `POST .../frames` response, `422`: the index does not link up within
/// itself, at this `seq`. Nothing was stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectResponse {
    pub seq: u64,
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frames_request_is_the_json_of_the_spec() {
        let batch = FramesRequest {
            first_seq: 0,
            last_seq: 1,
            index: vec![IndexEntry {
                seq: 0,
                prev: "aa".repeat(32),
                hash: "bb".repeat(32),
                ts: 17,
            }],
            wraps: Some(BTreeMap::from([("fp".to_owned(), "c2VhbGVk".to_owned())])),
            nonce: "bm9uY2U=".into(),
            ciphertext: "Y2lwaGVy".into(),
        };
        let json = serde_json::to_string(&batch).unwrap();
        assert!(json.starts_with(r#"{"first_seq":0,"last_seq":1,"index":[{"seq":0,"prev":"#));
        assert!(json.contains(r#""wraps":{"fp":"c2VhbGVk"}"#));
        assert_eq!(serde_json::from_str::<FramesRequest>(&json).unwrap(), batch);
    }

    #[test]
    fn wraps_is_absent_rather_than_null_after_the_first_batch() {
        let batch = FramesRequest {
            first_seq: 2,
            last_seq: 2,
            index: Vec::new(),
            wraps: None,
            nonce: "bm9uY2U=".into(),
            ciphertext: "Y2lwaGVy".into(),
        };
        let json = serde_json::to_string(&batch).unwrap();
        assert!(!json.contains("wraps"), "{json}");
        assert_eq!(serde_json::from_str::<FramesRequest>(&json).unwrap(), batch);
    }
}
