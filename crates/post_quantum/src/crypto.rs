//! Published MLKEM768-P256 construction with an opaque receiver agreement.
//!
//! AWS-LC supplies ML-KEM, ephemeral P-256 and the specified SHA3-256 combiner.
//! The pinned HPKE hybrid type supplies parsing, suite metadata and the existing
//! HPKE key schedule/AEAD. Its private-key and KEM operations are never called.
use aws_lc_rs::{
    agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey},
    digest::{Context, SHA3_256, SHA256, digest},
    hmac,
    kem::{EncapsulationKey, ML_KEM_768},
};
use hpke::{
    Deserializable, OpModeS, Serializable,
    aead::{AeadCtxS, ChaCha20Poly1305},
    kdf::{HkdfSha256, Kdf},
    kem::{DhP256HkdfSha256, MlKem768P256, SharedSecret},
};
use std::io;
use zeroize::Zeroizing;

pub const INFO: &[u8] = b"age-encryption.org/mlkem768p256tag";
pub const PUBLIC_LEN: usize = 1249;
pub const ENC_LEN: usize = 1153;
type Hybrid = MlKem768P256;
type Public = <Hybrid as hpke::Kem>::PublicKey;
type Point = <DhP256HkdfSha256 as hpke::Kem>::PublicKey;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn validate_public(public: &[u8]) -> io::Result<()> {
    if public.len() != PUBLIC_LEN {
        return Err(invalid("invalid hybrid public length"));
    }
    Public::from_bytes(public).map_err(|_| invalid("invalid hybrid public key"))?;
    Ok(())
}

fn peer(enc: &[u8]) -> io::Result<&[u8; 65]> {
    if enc.len() != ENC_LEN {
        return Err(invalid("invalid hybrid encapsulation length"));
    }
    let point: &[u8; 65] = enc[1088..]
        .try_into()
        .map_err(|_| invalid("invalid P-256 encapsulation"))?;
    if point[0] != 4 || Point::from_bytes(point).is_err() {
        return Err(invalid("invalid P-256 encapsulation"));
    }
    Ok(point)
}

// Exact C2PRICombiner from generic hybrid KEMs §5.1.3 / concrete §4.1.
// Incremental hashing avoids a concatenated buffer of both secret components.
fn combine(
    post_quantum: &[u8],
    raw: &[u8; 32],
    enc_point: &[u8; 65],
    public_point: &[u8],
) -> SharedSecret<Hybrid> {
    let mut hash = Context::new(&SHA3_256);
    hash.update(post_quantum);
    hash.update(raw);
    hash.update(enc_point);
    hash.update(public_point);
    hash.update(b"MLKEM768-P256");
    let mut shared = SharedSecret::<Hybrid>::default();
    shared.0.copy_from_slice(hash.finish().as_ref());
    shared
}

pub struct Wrapped {
    pub enc: Vec<u8>,
    pub body: Vec<u8>,
}

pub fn wrap(public: &[u8], file_key: &[u8]) -> io::Result<Wrapped> {
    if file_key.len() != 16 {
        return Err(invalid("invalid age file key length"));
    }
    validate_public(public)?;
    let post_quantum = EncapsulationKey::new(&ML_KEM_768, &public[..1184])
        .map_err(|_| invalid("ML-KEM public import failed"))?;
    let ephemeral = PrivateKey::generate(&ECDH_P256)
        .map_err(|_| invalid("ephemeral P-256 generation failed"))?;
    let ephemeral_public = ephemeral
        .compute_public_key()
        .map_err(|_| invalid("ephemeral P-256 public failed"))?;
    let enc_point: &[u8; 65] = ephemeral_public
        .as_ref()
        .try_into()
        .map_err(|_| invalid("invalid generated P-256 point"))?;
    let raw = agreement::agree(
        &ephemeral,
        UnparsedPublicKey::new(&ECDH_P256, &public[1184..]),
        invalid("P-256 agreement failed"),
        |bytes| {
            Ok(Zeroizing::new(
                <[u8; 32]>::try_from(bytes)
                    .map_err(|_| invalid("invalid P-256 agreement length"))?,
            ))
        },
    )?;
    let (ciphertext, post_quantum_shared) = post_quantum
        .encapsulate()
        .map_err(|_| invalid("ML-KEM encapsulation failed"))?;
    let shared = combine(
        post_quantum_shared.as_ref(),
        &raw,
        enc_point,
        &public[1184..],
    );
    let mut sender: AeadCtxS<ChaCha20Poly1305, HkdfSha256, Hybrid> =
        HkdfSha256::combine_secrets::<ChaCha20Poly1305, Hybrid, _>(&OpModeS::Base, shared, INFO)
            .into();
    let mut body = Zeroizing::new(file_key.to_vec());
    let tag = sender
        .seal_inout_detached(body.as_mut_slice().into(), b"")
        .map_err(|_| invalid("HPKE seal failed"))?;
    body.extend(tag.to_bytes());
    let mut enc = ciphertext.as_ref().to_vec();
    enc.extend(enc_point);
    Ok(Wrapped {
        enc,
        body: body.to_vec(),
    })
}

/// Receiver errors retain the distinction between operational/input failure
/// and a completed authentication check. Diagnostics never classify a failure.
#[cfg(feature = "seed-restoration")]
#[derive(Debug)]
pub enum OpenFailure {
    Operational(io::Error),
    Authentication,
}
#[cfg(feature = "seed-restoration")]
impl From<io::Error> for OpenFailure {
    fn from(error: io::Error) -> Self {
        Self::Operational(error)
    }
}

/// Compatibility receiver: preserve the original io::Result interface.
#[cfg(feature = "seed-restoration")]
pub fn open(
    public: &[u8],
    enc: &[u8],
    body: &[u8],
    private: &aws_lc_rs::kem::DecapsulationKey,
    agree: impl FnOnce(&[u8; 65]) -> io::Result<Zeroizing<[u8; 32]>>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    open_classified(public, enc, body, private, agree).map_err(|failure| match failure {
        OpenFailure::Operational(error) => error,
        OpenFailure::Authentication => invalid("HPKE authentication failed"),
    })
}

/// This adapter receives an already unsealed key and a Windows-owned agreement
/// callback. It never requests a scalar, generates a receiver key or retries
/// with another component. The caller must validate the PCP public identity.
#[cfg(feature = "seed-restoration")]
pub fn open_classified(
    public: &[u8],
    enc: &[u8],
    body: &[u8],
    private: &aws_lc_rs::kem::DecapsulationKey,
    agree: impl FnOnce(&[u8; 65]) -> io::Result<Zeroizing<[u8; 32]>>,
) -> Result<Zeroizing<Vec<u8>>, OpenFailure> {
    use hpke::{
        OpModeR,
        aead::{AeadCtxR, AeadTag},
    };
    if body.len() != 32 {
        return Err(invalid("invalid age stanza body length").into());
    }
    validate_public(public)?;
    let enc_point = peer(enc)?;
    let actual = private
        .encapsulation_key()
        .map_err(|_| invalid("ML-KEM public derivation failed"))?;
    if actual
        .key_bytes()
        .map_err(|_| invalid("ML-KEM public export failed"))?
        .as_ref()
        != &public[..1184]
    {
        return Err(invalid("ML-KEM recipient mismatch").into());
    }
    let post_quantum_shared = private
        .decapsulate(aws_lc_rs::kem::Ciphertext::from(&enc[..1088]))
        .map_err(|_| invalid("ML-KEM decapsulation failed"))?;
    let raw = agree(enc_point)?;
    let shared = combine(
        post_quantum_shared.as_ref(),
        &raw,
        enc_point,
        &public[1184..],
    );
    let mut receiver: AeadCtxR<ChaCha20Poly1305, HkdfSha256, Hybrid> =
        HkdfSha256::combine_secrets::<ChaCha20Poly1305, Hybrid, _>(&OpModeR::Base, shared, INFO)
            .into();
    let mut plain = Zeroizing::new(body[..16].to_vec());
    let tag = AeadTag::<ChaCha20Poly1305>::from_bytes(&body[16..])
        .map_err(|_| invalid("invalid HPKE tag"))?;
    receiver
        .open_inout_detached(plain.as_mut_slice().into(), b"", &tag)
        .map_err(|_| OpenFailure::Authentication)?;
    Ok(plain)
}

pub fn routing_tag(public: &[u8], enc: &[u8]) -> io::Result<[u8; 4]> {
    validate_public(public)?;
    peer(enc)?;
    let fingerprint = digest(&SHA256, &public[1184..]);
    let mut input = enc.to_vec();
    input.extend(&fingerprint.as_ref()[..4]);
    // HKDF-Extract-SHA256(salt, ikm) is HMAC-SHA256(salt, ikm), RFC 5869 §2.2.
    let extracted = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, INFO), &input);
    extracted.as_ref()[..4]
        .try_into()
        .map_err(|_| invalid("invalid routing tag"))
}

#[cfg(all(test, feature = "seed-restoration"))]
mod tests;
