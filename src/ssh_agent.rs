//! The ssh-agent protocol, enough of it to say what each message is.
//!
//! A client and the agent trade length-prefixed messages over a Unix socket,
//! one request and then one reply, in the encoding draft-miller-ssh-agent
//! describes: a `u32` is four bytes big-endian, a `string` is a `u32` length
//! and that many bytes, a `bool` is one byte.
//!
//! This module reads those frames and describes them. It decides nothing: it
//! never rejects, rewrites or answers a message, and a frame it cannot decode
//! is named as malformed rather than refused. [`describe`] returns the line
//! the ssh-agent log shows, one per message, so what the program asked its
//! agent for is there to read.

use std::{
    fmt,
    io::{self, Read, Write},
};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD as B64};
use sha2::{Digest, Sha256};

/// Longer than any message an agent trades in practice; a claim above it is a
/// client out of step with the socket, not a message.
const MAX_FRAME: u32 = 256 * 1024;

/// Reads one agent message: a big-endian u32 length, then that many bytes,
/// the first of which is the type. Returns the bytes without the length.
pub fn read_frame(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 4];
    r.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len);
    if len == 0 || len > MAX_FRAME {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("ssh-agent frame claims {len} bytes"),
        ));
    }
    let mut frame = vec![0u8; len as usize];
    r.read_exact(&mut frame)?;
    Ok(frame)
}

/// Writes `frame` with its length prefix.
pub fn write_frame(w: &mut impl Write, frame: &[u8]) -> io::Result<()> {
    w.write_all(&(frame.len() as u32).to_be_bytes())?;
    w.write_all(frame)
}

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const ADD_IDENTITY: u8 = 17;
const REMOVE_IDENTITY: u8 = 18;
const REMOVE_ALL_IDENTITIES: u8 = 19;
const ADD_SMARTCARD_KEY: u8 = 20;
const REMOVE_SMARTCARD_KEY: u8 = 21;
const LOCK: u8 = 22;
const UNLOCK: u8 = 23;
const ADD_ID_CONSTRAINED: u8 = 25;
const ADD_SMARTCARD_KEY_CONSTRAINED: u8 = 26;
const EXTENSION: u8 = 27;
const EXTENSION_FAILURE: u8 = 28;

/// The userauth request a SIGN_REQUEST's data holds, `SSH_MSG_USERAUTH_REQUEST`.
const USERAUTH_REQUEST: u8 = 50;

/// The extension OpenSSH sends to tie a forwarded agent to one session.
const SESSION_BIND: &str = "session-bind@openssh.com";

/// The name for a message type, or `None` for one the protocol does not name.
fn type_name(kind: u8) -> Option<&'static str> {
    Some(match kind {
        FAILURE => "FAILURE",
        SUCCESS => "SUCCESS",
        REQUEST_IDENTITIES => "REQUEST_IDENTITIES",
        IDENTITIES_ANSWER => "IDENTITIES_ANSWER",
        SIGN_REQUEST => "SIGN_REQUEST",
        SIGN_RESPONSE => "SIGN_RESPONSE",
        ADD_IDENTITY => "ADD_IDENTITY",
        REMOVE_IDENTITY => "REMOVE_IDENTITY",
        REMOVE_ALL_IDENTITIES => "REMOVE_ALL_IDENTITIES",
        ADD_SMARTCARD_KEY => "ADD_SMARTCARD_KEY",
        REMOVE_SMARTCARD_KEY => "REMOVE_SMARTCARD_KEY",
        LOCK => "LOCK",
        UNLOCK => "UNLOCK",
        ADD_ID_CONSTRAINED => "ADD_ID_CONSTRAINED",
        ADD_SMARTCARD_KEY_CONSTRAINED => "ADD_SMARTCARD_KEY_CONSTRAINED",
        EXTENSION => "EXTENSION",
        EXTENSION_FAILURE => "EXTENSION_FAILURE",
        _ => return None,
    })
}

/// A reader over a message body. Every field it takes is `Option`, so a short
/// frame ends a parse with `?` instead of a panic.
struct Cursor<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Cursor<'a> {
        Cursor { buf, at: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.at)?;
        self.at += 1;
        Some(b)
    }

    fn u32(&mut self) -> Option<u32> {
        let end = self.at.checked_add(4)?;
        let n = u32::from_be_bytes(self.buf.get(self.at..end)?.try_into().ok()?);
        self.at = end;
        Some(n)
    }

    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u32()? as usize;
        let end = self.at.checked_add(n)?;
        let s = self.buf.get(self.at..end)?;
        self.at = end;
        Some(s)
    }
}

/// One key the agent holds or is asked to sign with.
struct Key {
    /// The key's algorithm, the first `string` of its blob, such as
    /// `ssh-ed25519`.
    kind: String,
    /// `SHA256:` and the base64 SHA-256 of the whole blob, the fingerprint
    /// `ssh-add -l` prints.
    fingerprint: String,
    /// The comment the agent stores beside the key, where a message carries
    /// one.
    comment: Option<String>,
}

/// Reads a key blob: `string kind` first, and the digest over all of it.
fn key(blob: &[u8], comment: Option<String>) -> Option<Key> {
    Some(Key {
        kind: text(Cursor::new(blob).bytes()?),
        fingerprint: format!("SHA256:{}", B64.encode(Sha256::digest(blob))),
        comment,
    })
}

/// A wire `string` as something printable. Nothing on this wire promises
/// UTF-8, and a log line must not fail over it.
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// One message on the wire, as much of it as the log names.
enum Message {
    RequestIdentities,
    IdentitiesAnswer(Vec<Key>),
    SignRequest {
        key: Key,
        user: Option<String>,
        service: Option<String>,
        flags: u32,
    },
    SignResponse {
        len: usize,
    },
    Success,
    Failure,
    ExtensionFailure,
    SessionBind {
        host_key: Key,
        forwarding: bool,
    },
    Extension {
        name: String,
    },
    /// A type this module does not decode. Display names it where the
    /// protocol does, and prints its number otherwise.
    Other {
        kind: u8,
        len: usize,
    },
    /// A frame whose body does not match its type.
    Malformed {
        kind: u8,
        len: usize,
    },
}

/// The log line for one frame: what the message is and what it names. Never
/// fails; a frame this module cannot decode is named as malformed.
pub fn describe(frame: &[u8]) -> String {
    decode(frame)
        .unwrap_or(Message::Malformed {
            kind: frame.first().copied().unwrap_or(0),
            len: frame.len(),
        })
        .to_string()
}

fn decode(frame: &[u8]) -> Option<Message> {
    let (&kind, body) = frame.split_first()?;
    let mut c = Cursor::new(body);
    Some(match kind {
        FAILURE => Message::Failure,
        SUCCESS => Message::Success,
        EXTENSION_FAILURE => Message::ExtensionFailure,
        REQUEST_IDENTITIES => Message::RequestIdentities,
        IDENTITIES_ANSWER => {
            let mut keys = Vec::new();
            for _ in 0..c.u32()? {
                let blob = c.bytes()?;
                let comment = text(c.bytes()?);
                keys.push(key(blob, Some(comment))?);
            }
            Message::IdentitiesAnswer(keys)
        }
        SIGN_REQUEST => {
            let blob = c.bytes()?;
            let data = c.bytes()?;
            let (user, service) = userauth(data).unzip();
            Message::SignRequest {
                key: key(blob, None)?,
                user,
                service,
                flags: c.u32()?,
            }
        }
        SIGN_RESPONSE => Message::SignResponse {
            len: c.bytes()?.len(),
        },
        EXTENSION => {
            let name = text(c.bytes()?);
            if name != SESSION_BIND {
                return Some(Message::Extension { name });
            }
            let host_key = key(c.bytes()?, None)?;
            c.bytes()?; // session id
            c.bytes()?; // signature
            Message::SessionBind {
                host_key,
                forwarding: c.byte()? != 0,
            }
        }
        _ => Message::Other {
            kind,
            len: frame.len(),
        },
    })
}

/// The user and service from the userauth request a signature covers:
/// `string session_id`, `byte 50`, `string user`, `string service`, and more
/// the log does not name. A signature over anything else says nothing about
/// either.
fn userauth(data: &[u8]) -> Option<(String, String)> {
    let mut c = Cursor::new(data);
    c.bytes()?; // session id
    if c.byte()? != USERAUTH_REQUEST {
        return None;
    }
    let user = text(c.bytes()?);
    Some((user, text(c.bytes()?)))
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// `<kind> <fingerprint>`, and the comment where there is one.
        fn key(f: &mut fmt::Formatter<'_>, k: &Key) -> fmt::Result {
            write!(f, "{} {}", k.kind, k.fingerprint)?;
            match &k.comment {
                Some(c) => write!(f, " {c:?}"),
                None => Ok(()),
            }
        }

        /// The protocol's name for a type, or `TYPE_<n>`.
        fn name(f: &mut fmt::Formatter<'_>, kind: u8) -> fmt::Result {
            match type_name(kind) {
                Some(n) => write!(f, "{n}"),
                None => write!(f, "TYPE_{kind}"),
            }
        }

        match self {
            Message::RequestIdentities => write!(f, "REQUEST_IDENTITIES"),
            Message::IdentitiesAnswer(keys) => {
                write!(f, "IDENTITIES_ANSWER {} keys", keys.len())?;
                for (i, k) in keys.iter().enumerate() {
                    write!(f, "{}", if i == 0 { ": " } else { ", " })?;
                    key(f, k)?;
                }
                Ok(())
            }
            Message::SignRequest {
                key: k,
                user,
                service,
                flags,
            } => {
                write!(f, "SIGN_REQUEST key ")?;
                key(f, k)?;
                if let Some(user) = user {
                    write!(f, " user={user}")?;
                }
                if let Some(service) = service {
                    write!(f, " service={service}")?;
                }
                write!(f, " flags={flags}")
            }
            Message::SignResponse { len } => write!(f, "SIGN_RESPONSE {len} bytes"),
            Message::Success => write!(f, "SUCCESS"),
            Message::Failure => write!(f, "FAILURE"),
            Message::ExtensionFailure => write!(f, "EXTENSION_FAILURE"),
            Message::SessionBind {
                host_key,
                forwarding,
            } => {
                write!(f, "EXTENSION {SESSION_BIND} host ")?;
                key(f, host_key)?;
                write!(f, " forwarding={forwarding}")
            }
            Message::Extension { name } => write!(f, "EXTENSION {name}"),
            Message::Other { kind, len } => {
                name(f, *kind)?;
                write!(f, " {len} bytes")
            }
            Message::Malformed { kind, len } => {
                write!(f, "MALFORMED ")?;
                name(f, *kind)?;
                write!(f, " {len} bytes")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    fn put_u32(out: &mut Vec<u8>, n: u32) {
        out.extend_from_slice(&n.to_be_bytes());
    }

    fn put_string(out: &mut Vec<u8>, s: &[u8]) {
        put_u32(out, s.len() as u32);
        out.extend_from_slice(s);
    }

    /// A key blob: `string kind` and one more string standing in for the key
    /// material.
    fn blob(kind: &str, material: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        put_string(&mut out, kind.as_bytes());
        put_string(&mut out, material);
        out
    }

    #[test]
    fn request_identities() {
        assert_eq!(describe(&[REQUEST_IDENTITIES]), "REQUEST_IDENTITIES");
    }

    #[test]
    fn identities_answer_names_every_key() {
        let mut frame = vec![IDENTITIES_ANSWER];
        put_u32(&mut frame, 2);
        put_string(&mut frame, &blob("ssh-ed25519", b"one"));
        put_string(&mut frame, b"ahmed@mac");
        put_string(&mut frame, &blob("ssh-rsa", b"two"));
        put_string(&mut frame, b"work");

        let text = describe(&frame);
        assert!(
            text.starts_with("IDENTITIES_ANSWER 2 keys: ssh-ed25519 SHA256:"),
            "{text}"
        );
        assert!(text.contains("\"ahmed@mac\", ssh-rsa SHA256:"), "{text}");
        assert!(text.ends_with("\"work\""), "{text}");
    }

    #[test]
    fn identities_answer_with_no_keys() {
        let mut frame = vec![IDENTITIES_ANSWER];
        put_u32(&mut frame, 0);
        assert_eq!(describe(&frame), "IDENTITIES_ANSWER 0 keys");
    }

    #[test]
    fn truncated_identities_answer_is_malformed() {
        let mut frame = vec![IDENTITIES_ANSWER];
        put_u32(&mut frame, 2);
        put_string(&mut frame, &blob("ssh-ed25519", b"one"));
        put_string(&mut frame, b"ahmed@mac");
        assert_eq!(describe(&frame), "MALFORMED IDENTITIES_ANSWER 44 bytes");
    }

    /// `string session_id`, `byte 50`, `string user`, `string service`.
    fn userauth_data(kind: u8) -> Vec<u8> {
        let mut data = Vec::new();
        put_string(&mut data, b"session");
        data.push(kind);
        put_string(&mut data, b"git");
        put_string(&mut data, b"ssh-connection");
        data
    }

    fn sign_request(data: &[u8]) -> Vec<u8> {
        let mut frame = vec![SIGN_REQUEST];
        put_string(&mut frame, &blob("ssh-ed25519", b"one"));
        put_string(&mut frame, data);
        put_u32(&mut frame, 0);
        frame
    }

    #[test]
    fn sign_request_names_the_user_and_service() {
        let text = describe(&sign_request(&userauth_data(USERAUTH_REQUEST)));
        assert!(
            text.starts_with("SIGN_REQUEST key ssh-ed25519 SHA256:"),
            "{text}"
        );
        assert!(
            text.ends_with(" user=git service=ssh-connection flags=0"),
            "{text}"
        );
    }

    #[test]
    fn sign_request_over_other_data_names_neither() {
        let text = describe(&sign_request(&userauth_data(51)));
        assert!(
            text.starts_with("SIGN_REQUEST key ssh-ed25519 SHA256:"),
            "{text}"
        );
        assert!(text.ends_with(" flags=0"), "{text}");
        assert!(!text.contains("user="), "{text}");
        assert!(!text.contains("service="), "{text}");
    }

    #[test]
    fn short_sign_request_is_malformed() {
        assert_eq!(
            describe(&[SIGN_REQUEST, 0, 0, 0, 9, 9]),
            "MALFORMED SIGN_REQUEST 6 bytes"
        );
    }

    #[test]
    fn sign_response_counts_the_signature() {
        let mut frame = vec![SIGN_RESPONSE];
        put_string(&mut frame, &[7u8; 83]);
        assert_eq!(describe(&frame), "SIGN_RESPONSE 83 bytes");
    }

    #[test]
    fn the_plain_answers() {
        assert_eq!(describe(&[SUCCESS]), "SUCCESS");
        assert_eq!(describe(&[FAILURE]), "FAILURE");
        assert_eq!(describe(&[EXTENSION_FAILURE]), "EXTENSION_FAILURE");
    }

    #[test]
    fn session_bind_names_the_host_key() {
        let mut frame = vec![EXTENSION];
        put_string(&mut frame, SESSION_BIND.as_bytes());
        put_string(&mut frame, &blob("ssh-ed25519", b"host"));
        put_string(&mut frame, b"session");
        put_string(&mut frame, b"signature");
        frame.push(0);

        let text = describe(&frame);
        assert!(
            text.starts_with("EXTENSION session-bind@openssh.com host ssh-ed25519 SHA256:"),
            "{text}"
        );
        assert!(text.ends_with(" forwarding=false"), "{text}");
    }

    #[test]
    fn another_extension_is_named_only() {
        let mut frame = vec![EXTENSION];
        put_string(&mut frame, b"query");
        put_string(&mut frame, b"ignored");
        assert_eq!(describe(&frame), "EXTENSION query");
    }

    #[test]
    fn undecoded_types_carry_their_size() {
        let mut frame = vec![ADD_IDENTITY];
        frame.extend_from_slice(&[0u8; 411]);
        assert_eq!(describe(&frame), "ADD_IDENTITY 412 bytes");
        assert_eq!(describe(&[99, 1, 2, 3, 4]), "TYPE_99 5 bytes");
    }

    #[test]
    fn the_fingerprint_is_the_one_ssh_add_prints() {
        let blob = blob("ssh-ed25519", b"one");
        let key = key(&blob, None).unwrap();
        let want = B64.encode(Sha256::digest(&blob));

        assert_eq!(key.fingerprint, format!("SHA256:{want}"));
        assert_eq!(key.kind, "ssh-ed25519");
        let digest = key.fingerprint.strip_prefix("SHA256:").unwrap();
        assert_eq!(digest.len(), 43);
    }

    #[test]
    fn frames_are_read_one_after_another() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &[REQUEST_IDENTITIES]).unwrap();
        write_frame(&mut wire, &[IDENTITIES_ANSWER, 0, 0, 0, 0]).unwrap();

        let mut wire = Cursor::new(wire);
        assert_eq!(read_frame(&mut wire).unwrap(), [REQUEST_IDENTITIES]);
        assert_eq!(
            read_frame(&mut wire).unwrap(),
            [IDENTITIES_ANSWER, 0, 0, 0, 0]
        );
        assert_eq!(
            read_frame(&mut wire).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn a_closed_connection_is_unexpected_eof() {
        let mut empty = Cursor::new(Vec::new());
        assert_eq!(
            read_frame(&mut empty).unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    fn frames_beyond_the_cap_are_refused() {
        let mut wire = Cursor::new((MAX_FRAME + 1).to_be_bytes().to_vec());
        assert_eq!(
            read_frame(&mut wire).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        let mut empty = Cursor::new(0u32.to_be_bytes().to_vec());
        assert_eq!(
            read_frame(&mut empty).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
