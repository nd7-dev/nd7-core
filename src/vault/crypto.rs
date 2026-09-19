//! Keys, signatures and batch encryption for the vault protocol
//! (VAULT.md §4, §5 and the batch body of §6).
//!
//! Three key kinds, none of which this module ever reads from or writes to
//! disk: a [`MachineKey`] that signs requests, an [`AdminKey`] that unwraps
//! chain keys and signs recipient sets, and a [`ChainKey`] that encrypts one
//! chain's frames. The primitives are Ed25519, X25519 sealed boxes,
//! XChaCha20-Poly1305 and BLAKE3; nothing here is invented.
//!
//! Every byte layout that a signature or an AEAD covers is fixed here and
//! documented at the function that builds it, because the vault and the
//! browser viewer reconstruct the same bytes from their own code. Binary
//! fields cross the wire as base64 with the standard alphabet (`A-Z`, `a-z`,
//! `0-9`, `+`, `/`) and `=` padding.

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// zstd level used for every batch. Level 3 is zstd's own default: the knee
/// of the curve for log text, and fast enough that the machine does not feel
/// it.
const ZSTD_LEVEL: i32 = 3;

/// BLAKE3 derivation context for the X25519 half of an admin key. Changing
/// this string changes every admin's public key, so it never changes.
const ADMIN_X25519_CONTEXT: &str = "nd7-vault admin x25519";

/// The first thing that went wrong while decoding or opening something.
///
/// Deliberately coarse: none of these distinctions can be shown to whoever
/// supplied the bytes without telling them which guess was closer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Not base64 with the standard alphabet, or the right base64 for the
    /// wrong number of bytes.
    Encoding,
    /// The sealed box did not open: it was sealed to another admin, or the
    /// bytes were changed.
    Unseal,
    /// The AEAD tag did not verify: wrong chain key, wrong associated data,
    /// or the ciphertext was changed.
    Decrypt,
    /// The batch decrypted but the plaintext is not zstd.
    Decompress,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::Encoding => write!(f, "not valid base64 of the expected length"),
            CryptoError::Unseal => write!(f, "sealed box did not open"),
            CryptoError::Decrypt => write!(f, "batch did not decrypt"),
            CryptoError::Decompress => write!(f, "batch plaintext did not decompress"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Decode base64 into exactly `N` bytes.
fn decode_array<const N: usize>(s: &str) -> Result<[u8; N], CryptoError> {
    let raw = B64.decode(s).map_err(|_| CryptoError::Encoding)?;
    raw.try_into().map_err(|_| CryptoError::Encoding)
}

/// A machine's Ed25519 signing key (§4.1).
///
/// It signs every request the machine makes and encrypts nothing: leaking it
/// lets an attacker push signed garbage as that machine, never read a frame.
pub struct MachineKey(SigningKey);

impl MachineKey {
    /// A new key from the operating system's CSPRNG.
    pub fn generate() -> MachineKey {
        MachineKey(SigningKey::generate(&mut OsRng))
    }

    /// The key whose Ed25519 secret scalar is derived from this 32-byte seed.
    /// This is what `machine.key` holds.
    pub fn from_seed(seed: &[u8; 32]) -> MachineKey {
        MachineKey(SigningKey::from_bytes(seed))
    }

    /// The 32-byte seed, for writing `machine.key`.
    pub fn to_seed(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// The public half, as registered with the vault at enrolment.
    pub fn public_key(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Sign one request, returning the `X-Nd7-Signature` value: base64 of a
    /// 64-byte Ed25519 signature over exactly these bytes (§5):
    ///
    /// ```text
    /// method 0x0a path 0x0a machine 0x0a timestamp 0x0a body-hash
    /// ```
    ///
    /// Five fields, each pair separated by one literal newline (`0x0a`) and
    /// nothing else: no spaces around the separators, no trailing newline, no
    /// length prefixes. Every field is ASCII, so the string is its own bytes.
    ///
    /// - `method`: the HTTP method, upper case, as sent (`GET`, `POST`).
    /// - `path`: the request path with no scheme, host or query
    ///   (`/v1/recipients`).
    /// - `machine`: the `X-Nd7-Machine` value.
    /// - `timestamp`: the `X-Nd7-Timestamp` value, Unix seconds in decimal
    ///   with no padding and no sign for positive values.
    /// - `body-hash`: the `X-Nd7-Body` value, BLAKE3 of the body bytes as
    ///   sent, lower-case hex. A request with no body still signs the hash of
    ///   the empty body rather than an empty field.
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        machine_id: &str,
        timestamp_secs: i64,
        body_hash_hex: &str,
    ) -> String {
        let msg = request_bytes(method, path, machine_id, timestamp_secs, body_hash_hex);
        B64.encode(self.0.sign(msg.as_bytes()).to_bytes())
    }
}

/// The exact bytes a request signature covers; the layout is documented on
/// [`MachineKey::sign_request`], which is where an implementer will look.
fn request_bytes(
    method: &str,
    path: &str,
    machine_id: &str,
    timestamp_secs: i64,
    body_hash_hex: &str,
) -> String {
    format!("{method}\n{path}\n{machine_id}\n{timestamp_secs}\n{body_hash_hex}")
}

/// Check a request signature against a machine's registered public key. The
/// vault's side of [`MachineKey::sign_request`], with the same field meanings.
///
/// `false` for anything wrong at all: a public key that is not a point, a
/// signature that is not base64 or not 64 bytes, or a signature over
/// different fields. The caller still has to check the timestamp against its
/// own clock (§5); that is not a cryptographic question.
pub fn verify_request(
    public_key: &[u8; 32],
    method: &str,
    path: &str,
    machine_id: &str,
    timestamp_secs: i64,
    body_hash_hex: &str,
    signature_b64: &str,
) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(raw) = decode_array::<64>(signature_b64) else {
        return false;
    };
    let msg = request_bytes(method, path, machine_id, timestamp_secs, body_hash_hex);
    key.verify(msg.as_bytes(), &Signature::from_bytes(&raw))
        .is_ok()
}

/// An admin's key pair: the X25519 half that chain keys are wrapped to, and
/// the Ed25519 half that signs recipient sets (§4.3).
///
/// Both halves come from one 32-byte seed, which is the only thing an admin
/// has to keep:
///
/// - Ed25519 secret: the seed itself, unchanged. `ed25519-dalek` expands it
///   internally as RFC 8032 says.
/// - X25519 secret: `BLAKE3::derive_key("nd7-vault admin x25519", seed)`,
///   32 bytes, used directly as the X25519 scalar (clamped by the X25519
///   implementation, as the function requires).
///
/// Separate scalars, rather than the usual birational map from the Ed25519
/// key, so that neither half's use can say anything about the other's.
pub struct AdminKey {
    ed25519: SigningKey,
    x25519: crypto_box::SecretKey,
}

impl AdminKey {
    /// A new key pair from a fresh seed out of the operating system's CSPRNG.
    pub fn generate() -> AdminKey {
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        AdminKey::from_seed(&seed)
    }

    /// Both halves, derived from this seed as the type docs describe. Pure:
    /// the same seed always gives the same pair, on any machine.
    pub fn from_seed(seed: &[u8; 32]) -> AdminKey {
        AdminKey {
            ed25519: SigningKey::from_bytes(seed),
            x25519: crypto_box::SecretKey::from_bytes(blake3::derive_key(
                ADMIN_X25519_CONTEXT,
                seed,
            )),
        }
    }

    /// The two public halves, which are what the vault stores.
    pub fn public(&self) -> AdminPublic {
        AdminPublic {
            x25519: self.x25519.public_key().to_bytes(),
            ed25519: self.ed25519.verifying_key().to_bytes(),
        }
    }

    /// Sign one request as this admin, returning the `X-Nd7-Signature`
    /// value (§4.5).
    ///
    /// Exactly [`MachineKey::sign_request`]: the same five fields in the
    /// same layout, over the same private function, with the admin's
    /// Ed25519 half in place of the machine's key and the admin's key
    /// fingerprint -- the `X-Nd7-Admin` value -- in place of the machine
    /// id. The vault verifies it with [`verify_request`] against the
    /// Ed25519 half of the [`AdminPublic`] it has stored, and so cannot
    /// tell the two signers apart except by which header named them.
    pub fn sign_request(
        &self,
        method: &str,
        path: &str,
        admin_fingerprint: &str,
        timestamp_secs: i64,
        body_hash_hex: &str,
    ) -> String {
        let msg = request_bytes(
            method,
            path,
            admin_fingerprint,
            timestamp_secs,
            body_hash_hex,
        );
        B64.encode(self.ed25519.sign(msg.as_bytes()).to_bytes())
    }

    /// Open a chain key wrapped by [`ChainKey::wrap_for`] to this admin.
    pub fn unwrap(&self, wrapped: &str) -> Result<ChainKey, CryptoError> {
        let sealed = B64.decode(wrapped).map_err(|_| CryptoError::Encoding)?;
        let opened = self
            .x25519
            .unseal(&sealed)
            .map_err(|_| CryptoError::Unseal)?;
        let key: [u8; 32] = opened.try_into().map_err(|_| CryptoError::Unseal)?;
        Ok(ChainKey(key))
    }
}

/// The public halves of an [`AdminKey`]: what the vault publishes and what a
/// machine encrypts to.
///
/// The canonical form is the 64 bytes `x25519 || ed25519`, in that order.
/// Everything that names an admin -- the fingerprint, the wire form, the
/// recipient set hash -- is built from those bytes, so two implementations
/// cannot disagree about which admin they mean.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminPublic {
    pub x25519: [u8; 32],
    pub ed25519: [u8; 32],
}

impl AdminPublic {
    /// The canonical 64 bytes: the X25519 public key then the Ed25519 one.
    pub fn canonical_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.x25519);
        out[32..].copy_from_slice(&self.ed25519);
        out
    }

    /// The canonical bytes as base64, which is how an admin public key is
    /// written on the wire, in `recipients`, and when printed for comparison.
    pub fn to_base64(&self) -> String {
        B64.encode(self.canonical_bytes())
    }

    /// Parse [`AdminPublic::to_base64`]. Only the length is checked here; a
    /// key that is not a valid point fails later, at the operation that uses
    /// it.
    pub fn from_base64(s: &str) -> Result<AdminPublic, CryptoError> {
        let raw = decode_array::<64>(s)?;
        Ok(AdminPublic {
            x25519: raw[..32].try_into().expect("32 of 64 bytes"),
            ed25519: raw[32..].try_into().expect("32 of 64 bytes"),
        })
    }

    /// BLAKE3 hex of the canonical bytes. This is the string that keys the
    /// `wraps` map of a batch and that a [`SignedRecipientSet`] names as its
    /// signer.
    pub fn fingerprint(&self) -> String {
        blake3::hash(&self.canonical_bytes()).to_hex().to_string()
    }
}

impl Serialize for AdminPublic {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for AdminPublic {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<AdminPublic, D::Error> {
        let s = String::deserialize(d)?;
        AdminPublic::from_base64(&s).map_err(serde::de::Error::custom)
    }
}

/// The admins of one organisation: who a machine wraps chain keys to (§4.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientSet {
    pub admins: Vec<AdminPublic>,
    /// Bumped by the vault every time the set changes, so a machine can tell
    /// a newer set from an older one.
    pub version: u64,
}

impl RecipientSet {
    /// BLAKE3 hex over every admin's canonical 64 bytes, sorted
    /// lexicographically and concatenated with nothing between them.
    ///
    /// Sorted, so the order the vault happens to return the admins in cannot
    /// change the result. `version` is deliberately not covered: the
    /// fingerprint names a set of keys, which is what an enrolment token pins
    /// and what an admin reads out over the phone.
    pub fn fingerprint(&self) -> String {
        let mut canonical: Vec<[u8; 64]> = self
            .admins
            .iter()
            .map(AdminPublic::canonical_bytes)
            .collect();
        canonical.sort_unstable();
        let mut hasher = blake3::Hasher::new();
        for admin in &canonical {
            hasher.update(admin);
        }
        hasher.finalize().to_hex().to_string()
    }
}

/// A [`RecipientSet`] as the vault hands it out: signed by the admin who last
/// changed it, so a machine can accept a new set without trusting the vault
/// (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecipientSet {
    pub set: RecipientSet,
    /// [`AdminPublic::fingerprint`] of the signer.
    pub signed_by: String,
    /// Base64 of a 64-byte Ed25519 signature; see [`SignedRecipientSet::sign`].
    pub signature: String,
}

impl SignedRecipientSet {
    /// Sign a set with an admin's Ed25519 half, over exactly these bytes:
    ///
    /// ```text
    /// nd7-vault recipients 0x0a version 0x0a fingerprint
    /// ```
    ///
    /// A fixed ASCII context line, the decimal `version`, and
    /// [`RecipientSet::fingerprint`], separated by one literal newline each
    /// and with no trailing newline. The context line keeps the signature
    /// from meaning anything in another protocol; the version keeps a
    /// signature over an old set from being replayed as a new one.
    pub fn sign(set: RecipientSet, admin: &AdminKey) -> SignedRecipientSet {
        let signature = B64.encode(
            admin
                .ed25519
                .sign(recipients_bytes(&set).as_bytes())
                .to_bytes(),
        );
        SignedRecipientSet {
            signed_by: admin.public().fingerprint(),
            signature,
            set,
        }
    }

    /// Whether this set may replace `pinned`: the signature is valid *and*
    /// the signer is an admin `pinned` already contains. Both halves matter.
    /// A valid signature by a key the machine has never seen is exactly what
    /// a malicious vault would produce.
    pub fn verify_against(&self, pinned: &RecipientSet) -> bool {
        let Some(signer) = pinned
            .admins
            .iter()
            .find(|admin| admin.fingerprint() == self.signed_by)
        else {
            return false;
        };
        let Ok(key) = VerifyingKey::from_bytes(&signer.ed25519) else {
            return false;
        };
        let Ok(raw) = decode_array::<64>(&self.signature) else {
            return false;
        };
        key.verify(
            recipients_bytes(&self.set).as_bytes(),
            &Signature::from_bytes(&raw),
        )
        .is_ok()
    }
}

/// The bytes an admin signs when handing out a recipient set; the layout is
/// documented on [`SignedRecipientSet::sign`].
fn recipients_bytes(set: &RecipientSet) -> String {
    format!(
        "nd7-vault recipients\n{}\n{}",
        set.version,
        set.fingerprint()
    )
}

/// The 256-bit key of one `(session_id, host)` chain (§4.1). Generated on the
/// machine the first time it ships that chain, wrapped once per admin, and
/// never sent to the vault in the clear.
pub struct ChainKey([u8; 32]);

impl ChainKey {
    /// A new chain key from the operating system's CSPRNG.
    pub fn generate() -> ChainKey {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        ChainKey(key)
    }

    /// The key a session directory's `chain.key` holds, read back.
    pub fn from_bytes(key: [u8; 32]) -> ChainKey {
        ChainKey(key)
    }

    /// The raw key, for writing `chain.key` in the session directory.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Seal this key to one admin: a libsodium-compatible sealed box (an
    /// ephemeral X25519 public key followed by a Salsa20-Poly1305 box to the
    /// admin's key), base64. This is one entry of a batch's `wraps` map.
    pub fn wrap_for(&self, admin: &AdminPublic) -> String {
        let sealed = crypto_box::PublicKey::from_bytes(admin.x25519)
            .seal(&mut OsRng, &self.0)
            // The only failure a sealed box reports is the AEAD refusing to
            // grow its buffer, which a 32-byte plaintext into a fresh Vec
            // cannot provoke.
            .expect("sealing 32 bytes into a fresh buffer cannot fail");
        B64.encode(sealed)
    }
}

/// Associated data for one batch (§6). It binds a ciphertext to one chain and
/// one position in it, so a batch cannot be moved to another chain, another
/// host, or another place in the same chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchAad {
    pub session_id: String,
    pub host: String,
    pub first_seq: u64,
    pub last_seq: u64,
}

impl BatchAad {
    /// The exact associated-data bytes:
    ///
    /// ```text
    /// session_id 0x0a host 0x0a first_seq 0x0a last_seq
    /// ```
    ///
    /// Four fields separated by one literal newline each, no trailing
    /// newline, the two sequence numbers in decimal with no padding. Neither
    /// a session id nor a hostname may contain a newline, so the split is
    /// unambiguous.
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}\n{}\n{}\n{}",
            self.session_id, self.host, self.first_seq, self.last_seq
        )
        .into_bytes()
    }
}

/// One encrypted batch: what travels in a `frames` request body, minus the
/// clear index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBatch {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Compress then encrypt one run of raw frame bytes.
///
/// zstd first and XChaCha20-Poly1305 second, in that order and never the
/// other way round: the vault must not be able to compress, and compressing
/// ciphertext would achieve nothing anyway. The nonce is 24 fresh random
/// bytes, which is why a chain key can encrypt an unbounded number of
/// batches without a counter.
pub fn seal_batch(key: &ChainKey, aad: &BatchAad, plaintext_frames: &[u8]) -> SealedBatch {
    // Both of these operate on slices already in memory, so the `io::Error`
    // and `aead::Error` they are typed to return have no way to occur.
    let compressed =
        zstd::encode_all(plaintext_frames, ZSTD_LEVEL).expect("zstd of an in-memory slice");
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = XChaCha20Poly1305::new(key.as_bytes().into())
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: &compressed,
                aad: &aad.to_bytes(),
            },
        )
        .expect("XChaCha20-Poly1305 of an in-memory batch");
    SealedBatch { nonce, ciphertext }
}

/// Decrypt then decompress a batch sealed by [`seal_batch`]: the raw frame
/// bytes back, byte for byte.
///
/// [`CryptoError::Decrypt`] covers the wrong chain key, an `aad` that does
/// not match the one the batch was sealed under, and any change to the
/// nonce or the ciphertext. The AEAD cannot tell those apart, and neither
/// can this.
pub fn open_batch(
    key: &ChainKey,
    aad: &BatchAad,
    sealed: &SealedBatch,
) -> Result<Vec<u8>, CryptoError> {
    let compressed = XChaCha20Poly1305::new(key.as_bytes().into())
        .decrypt(
            &XNonce::from(sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: &aad.to_bytes(),
            },
        )
        .map_err(|_| CryptoError::Decrypt)?;
    zstd::decode_all(compressed.as_slice()).map_err(|_| CryptoError::Decompress)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BODY_HASH: &str = "ab";

    fn body_hash() -> String {
        BODY_HASH.repeat(32)
    }

    fn aad() -> BatchAad {
        BatchAad {
            session_id: "s1".into(),
            host: "laptop".into(),
            first_seq: 0,
            last_seq: 9,
        }
    }

    #[test]
    fn request_signature_round_trips_and_covers_every_field() {
        let key = MachineKey::generate();
        let pk = key.public_key();
        let hash = body_hash();
        let sig = key.sign_request("POST", "/v1/enroll", "m1", 1_700_000_000, &hash);
        assert!(verify_request(
            &pk,
            "POST",
            "/v1/enroll",
            "m1",
            1_700_000_000,
            &hash,
            &sig
        ));

        // One field different at a time; each must break the signature.
        assert!(!verify_request(
            &pk,
            "GET",
            "/v1/enroll",
            "m1",
            1_700_000_000,
            &hash,
            &sig
        ));
        assert!(!verify_request(
            &pk,
            "POST",
            "/v1/enrol",
            "m1",
            1_700_000_000,
            &hash,
            &sig
        ));
        assert!(!verify_request(
            &pk,
            "POST",
            "/v1/enroll",
            "m2",
            1_700_000_000,
            &hash,
            &sig
        ));
        assert!(!verify_request(
            &pk,
            "POST",
            "/v1/enroll",
            "m1",
            1_700_000_001,
            &hash,
            &sig
        ));
        assert!(!verify_request(
            &pk,
            "POST",
            "/v1/enroll",
            "m1",
            1_700_000_000,
            &"cd".repeat(32),
            &sig
        ));

        // Another machine's key, a signature that is not base64, and one that
        // is base64 of the wrong length.
        let other = MachineKey::generate().public_key();
        assert!(!verify_request(
            &other,
            "POST",
            "/v1/enroll",
            "m1",
            1_700_000_000,
            &hash,
            &sig
        ));
        assert!(!verify_request(
            &pk,
            "POST",
            "/v1/enroll",
            "m1",
            1_700_000_000,
            &hash,
            "not!b64"
        ));
        assert!(!verify_request(
            &pk,
            "POST",
            "/v1/enroll",
            "m1",
            1_700_000_000,
            &hash,
            "AAAA"
        ));
    }

    #[test]
    fn signed_bytes_are_the_documented_layout() {
        assert_eq!(
            request_bytes("GET", "/v1/recipients", "m1", 17, "beef"),
            "GET\n/v1/recipients\nm1\n17\nbeef"
        );
        assert_eq!(aad().to_bytes(), b"s1\nlaptop\n0\n9".to_vec());
    }

    #[test]
    fn machine_key_round_trips_through_its_seed() {
        let key = MachineKey::generate();
        let same = MachineKey::from_seed(&key.to_seed());
        assert_eq!(key.public_key(), same.public_key());
    }

    #[test]
    fn admin_key_derivation_is_deterministic_and_separates_its_halves() {
        let seed = [7u8; 32];
        let a = AdminKey::from_seed(&seed).public();
        let b = AdminKey::from_seed(&seed).public();
        assert_eq!(a, b, "same seed, same pair");
        assert_ne!(a.x25519, a.ed25519, "the two halves are different scalars");
        assert_ne!(a, AdminKey::from_seed(&[8u8; 32]).public());

        // The Ed25519 half is the seed itself; the X25519 half is the keyed
        // derivation of it. Both are pinned here so a change is deliberate.
        assert_eq!(
            a.ed25519,
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        );
        assert_eq!(
            a.x25519,
            crypto_box::SecretKey::from_bytes(blake3::derive_key(ADMIN_X25519_CONTEXT, &seed))
                .public_key()
                .to_bytes()
        );
    }

    #[test]
    fn an_admin_signs_a_request_exactly_as_a_machine_does() {
        let seed = [23u8; 32];
        let admin = AdminKey::from_seed(&seed);
        let hash = body_hash();
        let fingerprint = admin.public().fingerprint();

        let signature = admin.sign_request("GET", "/api/me", &fingerprint, 1_700_000_000, &hash);
        assert_eq!(
            signature,
            MachineKey::from_seed(&seed).sign_request(
                "GET",
                "/api/me",
                &fingerprint,
                1_700_000_000,
                &hash
            )
        );
        assert!(verify_request(
            &admin.public().ed25519,
            "GET",
            "/api/me",
            &fingerprint,
            1_700_000_000,
            &hash,
            &signature
        ));
    }

    #[test]
    fn admin_public_fingerprint_is_stable_across_the_canonical_form() {
        let admin = AdminKey::from_seed(&[1u8; 32]).public();
        let round_tripped = AdminPublic::from_base64(&admin.to_base64()).unwrap();
        assert_eq!(admin, round_tripped);
        assert_eq!(admin.fingerprint(), round_tripped.fingerprint());
        assert_eq!(admin.fingerprint().len(), 64);

        let json = serde_json::to_string(&admin).unwrap();
        assert_eq!(json, format!("\"{}\"", admin.to_base64()));
        assert_eq!(serde_json::from_str::<AdminPublic>(&json).unwrap(), admin);

        assert_eq!(AdminPublic::from_base64("!!"), Err(CryptoError::Encoding));
        assert_eq!(AdminPublic::from_base64("AAAA"), Err(CryptoError::Encoding));
    }

    #[test]
    fn recipient_set_fingerprint_ignores_order_but_not_membership() {
        let a = AdminKey::from_seed(&[1u8; 32]).public();
        let b = AdminKey::from_seed(&[2u8; 32]).public();
        let one = RecipientSet {
            admins: vec![a.clone(), b.clone()],
            version: 1,
        };
        let reversed = RecipientSet {
            admins: vec![b, a.clone()],
            version: 1,
        };
        assert_eq!(one.fingerprint(), reversed.fingerprint());

        // The version is not part of it, membership is.
        let bumped = RecipientSet {
            version: 9,
            ..one.clone()
        };
        assert_eq!(one.fingerprint(), bumped.fingerprint());
        let alone = RecipientSet {
            admins: vec![a],
            version: 1,
        };
        assert_ne!(one.fingerprint(), alone.fingerprint());
    }

    #[test]
    fn a_new_recipient_set_is_accepted_only_from_a_pinned_signer() {
        let pinned_admin = AdminKey::from_seed(&[1u8; 32]);
        let added = AdminKey::from_seed(&[2u8; 32]);
        let stranger = AdminKey::from_seed(&[3u8; 32]);

        let pinned = RecipientSet {
            admins: vec![pinned_admin.public()],
            version: 1,
        };
        let grown = RecipientSet {
            admins: vec![pinned_admin.public(), added.public()],
            version: 2,
        };

        // Signed by the admin already in the pinned set: accepted.
        assert!(SignedRecipientSet::sign(grown.clone(), &pinned_admin).verify_against(&pinned));
        // Signed by the admin being added, who is not pinned yet: refused.
        assert!(!SignedRecipientSet::sign(grown.clone(), &added).verify_against(&pinned));
        // Signed by a key nobody has ever seen: refused.
        assert!(!SignedRecipientSet::sign(grown.clone(), &stranger).verify_against(&pinned));

        // A signature lifted from one set onto another, and a mangled one.
        let mut swapped = SignedRecipientSet::sign(grown, &pinned_admin);
        swapped.set.version = 3;
        assert!(!swapped.verify_against(&pinned));
        swapped.set.version = 2;
        swapped.signature = "AAAA".into();
        assert!(!swapped.verify_against(&pinned));
    }

    #[test]
    fn chain_key_wraps_to_one_admin_only() {
        let admin = AdminKey::generate();
        let other = AdminKey::generate();
        let key = ChainKey::generate();

        // `ChainKey` is neither `Debug` nor `PartialEq`, so that a secret
        // cannot reach a log line or a timing-variable comparison by
        // accident; the tests unwrap it by hand.
        let wrapped = key.wrap_for(&admin.public());
        assert_eq!(admin.unwrap(&wrapped).unwrap().as_bytes(), key.as_bytes());
        assert_eq!(other.unwrap(&wrapped).err(), Some(CryptoError::Unseal));
        assert_eq!(admin.unwrap("not!b64").err(), Some(CryptoError::Encoding));

        // A flipped byte in the sealed box.
        let mut raw = B64.decode(&wrapped).unwrap();
        raw[40] ^= 1;
        assert_eq!(
            admin.unwrap(&B64.encode(raw)).err(),
            Some(CryptoError::Unseal)
        );
    }

    #[test]
    fn batch_seals_and_opens() {
        let key = ChainKey::generate();
        let frames = b"{\"v\":0,\"seq\":0}\n{\"v\":0,\"seq\":1}\n".repeat(64);
        let sealed = seal_batch(&key, &aad(), &frames);
        assert_eq!(open_batch(&key, &aad(), &sealed).unwrap(), frames);
        // Compression is real on frame-shaped input, and the plaintext is not
        // recoverable from the ciphertext by eye.
        assert!(sealed.ciphertext.len() < frames.len());
    }

    #[test]
    fn batch_refuses_the_wrong_key_the_wrong_aad_and_changed_bytes() {
        let key = ChainKey::generate();
        let frames = b"frame bytes\n".repeat(16);
        let sealed = seal_batch(&key, &aad(), &frames);

        assert_eq!(
            open_batch(&ChainKey::generate(), &aad(), &sealed),
            Err(CryptoError::Decrypt)
        );

        // Each associated-data field on its own.
        for changed in [
            BatchAad {
                session_id: "s2".into(),
                ..aad()
            },
            BatchAad {
                host: "desktop".into(),
                ..aad()
            },
            BatchAad {
                first_seq: 1,
                ..aad()
            },
            BatchAad {
                last_seq: 10,
                ..aad()
            },
        ] {
            assert_eq!(
                open_batch(&key, &changed, &sealed),
                Err(CryptoError::Decrypt),
                "{changed:?}"
            );
        }

        let mut flipped = sealed.clone();
        flipped.ciphertext[3] ^= 1;
        assert_eq!(
            open_batch(&key, &aad(), &flipped),
            Err(CryptoError::Decrypt)
        );

        let mut renonced = sealed;
        renonced.nonce[0] ^= 1;
        assert_eq!(
            open_batch(&key, &aad(), &renonced),
            Err(CryptoError::Decrypt)
        );
    }
}
