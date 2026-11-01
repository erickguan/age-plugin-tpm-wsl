//! Fixed suites shared by the Linux sender and Windows receiver.
use crate::{LABEL, PublicKey, Recipient, Scheme, formats::HPKE_INFO_PREFIX, invalid};
use hpke::{
    Deserializable, OpModeR, OpModeS, Serializable,
    aead::{AeadCtxR, ChaCha20Poly1305},
    kdf::{HkdfSha256, Kdf},
    kem::{DhP256HkdfSha256, SharedSecret},
};
use std::io;
use zeroize::Zeroizing;

type Kem = DhP256HkdfSha256;
type Point = <Kem as hpke::Kem>::PublicKey;

pub fn validate_point(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(invalid("expected canonical uncompressed P-256 point"));
    }
    Point::from_bytes(bytes).map_err(|_| invalid("invalid P-256 point"))?;
    Ok(())
}

fn info(recipient: &Recipient) -> Vec<u8> {
    let mut bytes = HPKE_INFO_PREFIX.to_vec();
    bytes.extend(recipient.bytes());
    bytes
}
fn aad(recipient: &Recipient) -> Vec<u8> {
    let scheme = Scheme::P256Hpke;
    format!(
        "{} {} {}",
        scheme.tag(),
        scheme.stanza_version(),
        recipient.fingerprint()
    )
    .into_bytes()
}

pub fn wrap(recipient: &Recipient, file_key: &[u8]) -> io::Result<Vec<u8>> {
    if file_key.len() != 16 {
        return Err(invalid("invalid file key length"));
    }
    match &recipient.key {
        PublicKey::Rsa(key) => key.encrypt_oaep(file_key, LABEL.as_bytes()),
        PublicKey::P256(point) => {
            let public =
                Point::from_bytes(point).map_err(|_| invalid("invalid P-256 public key"))?;
            let (enc, mut sender) = hpke::setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(
                &OpModeS::Base,
                &public,
                &info(recipient),
            )
            .map_err(|_| invalid("HPKE sender setup failed"))?;
            let mut body = enc.to_bytes().to_vec();
            body.extend(
                sender
                    .seal(file_key, &aad(recipient))
                    .map_err(|_| invalid("HPKE wrapping failed"))?,
            );
            Ok(body)
        }
    }
}

/// Complete HPKE in the receiver process. The callback supplies only raw,
/// big-endian ECDH for this already validated peer. No private scalar is needed.
pub fn open_p256(
    recipient: &Recipient,
    body: &[u8],
    agree: impl FnOnce(&[u8; 65]) -> io::Result<Zeroizing<[u8; 32]>>,
) -> io::Result<Zeroizing<Vec<u8>>> {
    let PublicKey::P256(public) = &recipient.key else {
        return Err(invalid("HPKE requires a P-256 recipient"));
    };
    if body.len() != Scheme::P256Hpke.body_len() {
        return Err(invalid("invalid HPKE ciphertext length"));
    }
    validate_point(public)?;
    validate_point(&body[..65])?;
    let enc: &[u8; 65] = body[..65]
        .try_into()
        .map_err(|_| invalid("invalid HPKE encapsulation"))?;
    let raw = agree(enc)?;
    let mut receiver = receiver(public, enc, raw.as_slice(), &info(recipient))?;
    let mut plain = Zeroizing::new(body[65..81].to_vec());
    let tag = hpke::aead::AeadTag::<ChaCha20Poly1305>::from_bytes(&body[81..])
        .map_err(|_| invalid("invalid HPKE tag"))?;
    receiver
        .open_inout_detached(plain.as_mut_slice().into(), &aad(recipient), &tag)
        .map_err(|_| invalid("HPKE authentication failed"))?;
    Ok(plain)
}

// Use the library's DHKEM extraction and receiver key schedule directly. These
// public, doc(hidden) interfaces are pinned and checked against RFC vectors.
fn receiver(
    public: &[u8],
    enc: &[u8],
    raw: &[u8],
    info: &[u8],
) -> io::Result<AeadCtxR<ChaCha20Poly1305, HkdfSha256, Kem>> {
    let mut kem_context = enc.to_vec();
    kem_context.extend(public);
    let mut secret = SharedSecret::<Kem>::default();
    HkdfSha256::extract_and_expand(raw, b"KEM\x00\x10", &kem_context, &mut secret.0)
        .map_err(|_| invalid("HPKE decapsulation failed"))?;
    Ok(
        HkdfSha256::combine_secrets::<ChaCha20Poly1305, Kem, _>(&OpModeR::Base, secret, info)
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::Kem as _;

    #[test]
    fn hardware_schedule_matches_pinned_rfc9180_vector() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(
            "../notes/hpke-evaluation/rfc9180-p256-vector.json"
        ))
        .unwrap();
        assert_eq!(
            (
                vector["mode"].as_u64(),
                vector["kem_id"].as_u64(),
                vector["kdf_id"].as_u64(),
                vector["aead_id"].as_u64()
            ),
            (Some(0), Some(16), Some(1), Some(3))
        );
        let bytes = |name: &str| hex::decode(vector[name].as_str().unwrap()).unwrap();
        let private = p256::SecretKey::from_slice(&bytes("skRm")).unwrap();
        let peer = p256::PublicKey::from_sec1_bytes(&bytes("enc")).unwrap();
        let raw = p256::ecdh::diffie_hellman(private.to_nonzero_scalar(), peer.as_affine());
        let mut secret = SharedSecret::<Kem>::default();
        let mut context = bytes("enc");
        context.extend(bytes("pkRm"));
        HkdfSha256::extract_and_expand(
            raw.raw_secret_bytes(),
            b"KEM\x00\x10",
            &context,
            &mut secret.0,
        )
        .unwrap();
        assert_eq!(secret.0.as_slice(), bytes("shared_secret"));
        let mut receiver = receiver(
            &bytes("pkRm"),
            &bytes("enc"),
            raw.raw_secret_bytes(),
            &bytes("info"),
        )
        .unwrap();
        let records = vector["encryptions"].as_array().unwrap();
        assert_eq!(records.len(), 257);
        for record in records {
            let decode = |name: &str| hex::decode(record[name].as_str().unwrap()).unwrap();
            assert_eq!(
                *Zeroizing::new(receiver.open(&decode("ct"), &decode("aad")).unwrap()),
                decode("pt")
            );
        }
    }

    #[test]
    fn application_transcript_opens_independent_go_fixture() {
        // Generated by Go's independent crypto/hpke sender. Literal transcript
        // fields prevent a shared sender/receiver encoding bug from passing.
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../notes/fixtures/p256-hpke-go.json")).unwrap();
        let bytes = |field: &str| hex::decode(fixture[field].as_str().unwrap()).unwrap();
        let recipient = Recipient::parse(&bytes("recipient")).unwrap();
        assert_eq!(
            recipient.fingerprint(),
            fixture["fingerprint"].as_str().unwrap()
        );
        assert_eq!(info(&recipient), bytes("info"));
        assert_eq!(aad(&recipient), bytes("aad"));
        let private = p256::SecretKey::from_slice(&bytes("receiver_private")).unwrap();
        let body = bytes("body");
        let plaintext = open_p256(&recipient, &body, |enc| {
            let peer = p256::PublicKey::from_sec1_bytes(enc).unwrap();
            let raw = p256::ecdh::diffie_hellman(private.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(
                raw.raw_secret_bytes().as_slice().try_into().unwrap(),
            ))
        })
        .unwrap();
        assert_eq!(*plaintext, bytes("plaintext"));
    }

    #[test]
    fn bound_hardware_interface_rejects_tampering_and_bad_peers() {
        let (private, public) = Kem::gen_keypair();
        let mut encoded = vec![2, 0, 1];
        encoded.extend(public.to_bytes());
        let recipient = Recipient::parse(&encoded).unwrap();
        let scalar = p256::SecretKey::from_slice(&private.to_bytes()).unwrap();
        let agree = |enc: &[u8; 65]| {
            let peer = p256::PublicKey::from_sec1_bytes(enc).unwrap();
            let raw = p256::ecdh::diffie_hellman(scalar.to_nonzero_scalar(), peer.as_affine());
            Ok(Zeroizing::new(
                raw.raw_secret_bytes().as_slice().try_into().unwrap(),
            ))
        };
        let body = wrap(&recipient, &[0x5a; 16]).unwrap();
        assert_eq!(*open_p256(&recipient, &body, agree).unwrap(), [0x5a; 16]);
        for offset in [0, 1, 64, 65, 80, 81, 96] {
            let mut altered = body.clone();
            altered[offset] ^= 1;
            assert!(open_p256(&recipient, &altered, agree).is_err());
        }
        for length in [0, 64, 65, 81, 96, 98] {
            assert!(
                open_p256(&recipient, &vec![0; length], |_| panic!(
                    "invalid body reached agreement"
                ))
                .is_err()
            );
        }
        let mut off_curve = body.clone();
        off_curve[..65].fill(0);
        off_curve[0] = 4;
        assert!(
            open_p256(&recipient, &off_curve, |_| panic!(
                "invalid peer reached agreement"
            ))
            .is_err()
        );
        let (_, other) = Kem::gen_keypair();
        encoded.truncate(3);
        encoded.extend(other.to_bytes());
        let other = Recipient::parse(&encoded).unwrap();
        assert!(open_p256(&other, &body, agree).is_err());
        assert!(open_p256(&recipient, &body, |_| Err(invalid("TPM failed"))).is_err());
        let enc = &body[..65];
        let raw = agree(enc.try_into().unwrap()).unwrap();
        let mut wrong_info =
            receiver(&public.to_bytes(), enc, raw.as_slice(), b"wrong-info").unwrap();
        assert!(wrong_info.open(&body[65..], &aad(&recipient)).is_err());
        let mut wrong_aad =
            receiver(&public.to_bytes(), enc, raw.as_slice(), &info(&recipient)).unwrap();
        assert!(wrong_aad.open(&body[65..], b"wrong-aad").is_err());
    }
}
