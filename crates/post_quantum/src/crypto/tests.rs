use super::*;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey};
use hpke::OpModeR;
use hpke::aead::{AeadCtxR, AesGcm128};
use serde_json::Value;

mod classified;

fn fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../../notes/aws-lc-hybrid-evaluation/go-fixture.json"
    ))
    .expect("Go public fixture")
}
fn bytes(record: &Value, field: &str) -> Vec<u8> {
    hex::decode(record[field].as_str().expect("public fixture field")).expect("fixture hex")
}
fn components(record: &Value) -> (DecapsulationKey, PrivateKey) {
    let seed = Zeroizing::new(bytes(record, "mlkem_seed"));
    let scalar = Zeroizing::new(bytes(record, "p256_private"));
    (
        DecapsulationKey::from_seed(&ML_KEM_768, seed.as_slice()).expect("test seed import"),
        PrivateKey::from_private_key(&ECDH_P256, scalar.as_slice()).expect("test scalar import"),
    )
}
fn raw_agree(private: &PrivateKey, enc: &[u8; 65]) -> io::Result<Zeroizing<[u8; 32]>> {
    agreement::agree(
        private,
        UnparsedPublicKey::new(&ECDH_P256, enc),
        invalid("test agreement failed"),
        |raw| {
            Ok(Zeroizing::new(
                raw.try_into().map_err(|_| invalid("test raw length"))?,
            ))
        },
    )
}
fn shared_for(record: &Value, public: &[u8], enc: &[u8]) -> SharedSecret<Hybrid> {
    let (post_quantum, t) = components(record);
    let post_quantum_shared = post_quantum
        .decapsulate(Ciphertext::from(&enc[..1088]))
        .expect("test decapsulation");
    let enc_point = peer(enc).expect("test peer");
    let raw = raw_agree(&t, enc_point).expect("test agreement");
    combine(
        post_quantum_shared.as_ref(),
        &raw,
        enc_point,
        &public[1184..],
    )
}

#[test]
fn authoritative_hybrid_shared_secret_schedule_records_and_exports() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../notes/pq-construction/ietf-hpke-pq-05-mlkem768p256.json"
    ))
    .expect("pinned IETF WG hybrid vector");
    let component_fixture: Value = serde_json::from_str(include_str!(
        "../../../../notes/aws-lc-hybrid-evaluation/kat-components.json"
    ))
    .expect("independently expanded public-test components");
    for (field, expected) in [("mode", 0), ("kem_id", 80), ("kdf_id", 1), ("aead_id", 1)] {
        assert_eq!(vector[field].as_u64(), Some(expected));
    }
    assert_eq!(<Hybrid as hpke::Kem>::KEM_ID, 80);
    let public = bytes(&vector, "pkRm");
    assert_eq!(public.len(), PUBLIC_LEN);
    assert!(bytes(&component_fixture, "public_key") == public);
    validate_public(&public).unwrap();
    let (post_quantum, t) = components(&component_fixture);
    assert!(
        post_quantum
            .encapsulation_key()
            .unwrap()
            .key_bytes()
            .unwrap()
            .as_ref()
            == &public[..1184]
    );
    assert!(t.compute_public_key().unwrap().as_ref() == &public[1184..]);
    let enc = bytes(&vector, "enc");
    let shared = shared_for(&component_fixture, &public, &enc);
    assert!(shared.0.as_slice() == bytes(&vector, "shared_secret"));
    let mut receiver: AeadCtxR<AesGcm128, HkdfSha256, Hybrid> =
        HkdfSha256::combine_secrets::<AesGcm128, Hybrid, _>(
            &OpModeR::Base,
            shared,
            &bytes(&vector, "info"),
        )
        .into();
    let encryptions = vector["encryptions"].as_array().unwrap();
    assert_eq!(encryptions.len(), 10);
    for record in encryptions {
        let plain = Zeroizing::new(
            receiver
                .open(&bytes(record, "ct"), &bytes(record, "aad"))
                .unwrap(),
        );
        assert!(*plain == bytes(record, "pt"));
    }
    let exports = vector["exports"].as_array().unwrap();
    assert_eq!(exports.len(), 5);
    for record in exports {
        let mut out = Zeroizing::new(vec![0; record["L"].as_u64().unwrap().try_into().unwrap()]);
        receiver
            .export(&bytes(record, "exporter_context"), out.as_mut_slice())
            .unwrap();
        assert!(*out == bytes(record, "exported_value"));
    }
}

#[test]
fn concrete_draft03_component_keys_and_shared_secrets_match_all_vectors() {
    // These directly published components avoid depending on Go's fixture
    // expansion to validate the construction. The actual post-quantum fields are seeds
    // of 64 bytes; their public-key equality validates that interpretation.
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../notes/pq-construction/concrete-03-mlkem768p256.json"
    ))
    .expect("hash-pinned concrete draft vectors");
    let records = fixture["vectors"].as_array().expect("construction vectors");
    assert_eq!(records.len(), 10);
    for (index, record) in records.iter().enumerate() {
        let seed = Zeroizing::new(bytes(record, "decapsulation_key_pq"));
        assert_eq!(seed.len(), 64);
        let scalar = Zeroizing::new(bytes(record, "decapsulation_key_t"));
        let post_quantum = DecapsulationKey::from_seed(&ML_KEM_768, seed.as_slice())
            .expect("construction seed import");
        let t = PrivateKey::from_private_key(&ECDH_P256, scalar.as_slice())
            .expect("construction scalar import");
        let public = bytes(record, "encapsulation_key");
        validate_public(&public).expect("construction public validation");
        assert!(
            post_quantum
                .encapsulation_key()
                .unwrap()
                .key_bytes()
                .unwrap()
                .as_ref()
                == &public[..1184],
            "ML-KEM public mismatch in vector {index}"
        );
        assert!(
            t.compute_public_key().unwrap().as_ref() == &public[1184..],
            "P-256 public mismatch in vector {index}"
        );
        let enc = bytes(record, "ciphertext");
        let enc_point = peer(&enc).expect("construction peer");
        let post_quantum_shared = post_quantum
            .decapsulate(Ciphertext::from(&enc[..1088]))
            .expect("construction decapsulation");
        let raw = raw_agree(&t, enc_point).expect("construction agreement");
        let shared = combine(
            post_quantum_shared.as_ref(),
            &raw,
            enc_point,
            &public[1184..],
        );
        assert!(
            shared.0.as_slice() == bytes(record, "shared_secret"),
            "hybrid shared secret mismatch in vector {index}"
        );
    }
}

#[test]
fn independent_go_tagged_age_fixture_opens_with_opaque_callback() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    assert!(bytes(&record, "info") == b"age-encryption.org/mlkem768p256tag");
    assert!(bytes(&record, "aad").is_empty());
    assert!(bytes(&record, "plaintext") == b"0123456789abcdef");
    assert!(routing_tag(&public, &enc).unwrap().as_slice() == bytes(&record, "routing_tag"));
    let (post_quantum, t) = components(&record);
    let plain = open(&public, &enc, &body, &post_quantum, |enc| {
        raw_agree(&t, enc)
    })
    .unwrap();
    assert!(plain.as_slice() == b"0123456789abcdef");
}

#[test]
fn fresh_aws_lc_sender_opens_with_separate_receiver_components() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let wrapped = wrap(&public, b"0123456789abcdef").unwrap();
    assert_eq!(wrapped.enc.len(), ENC_LEN);
    assert_eq!(wrapped.body.len(), 32);
    let (post_quantum, t) = components(&record);
    let plain = open(&public, &wrapped.enc, &wrapped.body, &post_quantum, |enc| {
        raw_agree(&t, enc)
    })
    .unwrap();
    assert!(plain.as_slice() == b"0123456789abcdef");
}

#[test]
fn both_ciphertext_components_and_authenticated_body_fail_closed() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    let (post_quantum, t) = components(&record);
    for offset in [0, 543, 1087, 1088, 1089, 1152] {
        let mut changed = enc.clone();
        changed[offset] ^= 1;
        assert!(
            open(&public, &changed, &body, &post_quantum, |enc| raw_agree(
                &t, enc
            ))
            .is_err()
        );
    }
    for offset in 0..32 {
        let mut changed = body.clone();
        changed[offset] ^= 1;
        assert!(
            open(&public, &enc, &changed, &post_quantum, |enc| raw_agree(
                &t, enc
            ))
            .is_err()
        );
    }
    assert!(
        open(&public, &enc, &body, &post_quantum, |_| Err(invalid(
            "opaque agreement unavailable"
        )))
        .is_err()
    );
}

#[test]
fn each_wrong_private_component_is_rejected() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    let (post_quantum, _) = components(&record);
    let mut scalar = [0; 32];
    scalar[31] = 2;
    let wrong_t = PrivateKey::from_private_key(&ECDH_P256, &scalar).unwrap();
    assert!(
        open(&public, &enc, &body, &post_quantum, |enc| raw_agree(
            &wrong_t, enc
        ))
        .is_err()
    );
    let wrong_post_quantum = DecapsulationKey::from_seed(&ML_KEM_768, &[0x99; 64]).unwrap();
    assert!(
        open(&public, &enc, &body, &wrong_post_quantum, |_| panic!(
            "wrong post-quantum public reached agreement"
        ))
        .is_err()
    );
    let mut changed = public.clone();
    changed[1184..].copy_from_slice(wrong_t.compute_public_key().unwrap().as_ref());
    validate_public(&changed).unwrap();
    assert!(
        open(&changed, &enc, &body, &post_quantum, |enc| raw_agree(
            &wrong_t, enc
        ))
        .is_err()
    );
}

#[test]
fn malformed_inputs_are_rejected_before_opaque_agreement() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    let (post_quantum, _) = components(&record);
    for length in [0, 1088, 1152, 1154, 8193] {
        assert!(
            open(&public, &vec![0; length], &body, &post_quantum, |_| panic!(
                "bad encapsulation length reached agreement"
            ))
            .is_err()
        );
    }
    for length in [0, 16, 31, 33, 8193] {
        assert!(
            open(&public, &enc, &vec![0; length], &post_quantum, |_| panic!(
                "bad body length reached agreement"
            ))
            .is_err()
        );
    }
    for length in [0, 1184, 1248, 1250, 8193] {
        assert!(
            open(&vec![0; length], &enc, &body, &post_quantum, |_| panic!(
                "bad public length reached agreement"
            ))
            .is_err()
        );
    }
    let mut off_curve = enc.clone();
    off_curve[1088..].fill(0);
    off_curve[1088] = 4;
    assert!(
        open(&public, &off_curve, &body, &post_quantum, |_| panic!(
            "off-curve peer reached agreement"
        ))
        .is_err()
    );
    let mut malformed = public.clone();
    malformed[0] = 0xff;
    malformed[1] |= 0x0f;
    assert!(
        open(&malformed, &enc, &body, &post_quantum, |_| panic!(
            "noncanonical ML-KEM public reached agreement"
        ))
        .is_err()
    );
    assert!(wrap(&malformed, &[0; 16]).is_err());
    malformed = public.clone();
    malformed[1184..].fill(0);
    malformed[1184] = 4;
    assert!(validate_public(&malformed).is_err());
    assert!(wrap(&malformed, &[0; 16]).is_err());
    for length in [0, 15, 17, 32] {
        assert!(wrap(&public, &vec![0; length]).is_err());
    }
}

#[test]
fn incorrect_info_aad_and_suite_cannot_authenticate() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    for (info, aad) in [
        (b"wrong-info".as_slice(), b"".as_slice()),
        (INFO, b"wrong-aad".as_slice()),
    ] {
        let shared = shared_for(&record, &public, &enc);
        let mut receiver: AeadCtxR<ChaCha20Poly1305, HkdfSha256, Hybrid> =
            HkdfSha256::combine_secrets::<ChaCha20Poly1305, Hybrid, _>(
                &OpModeR::Base,
                shared,
                info,
            )
            .into();
        assert!(receiver.open(&body, aad).is_err());
    }
    // The same precombined bytes under a classical KEM ID produce another context.
    let hybrid = shared_for(&record, &public, &enc);
    let mut classical = SharedSecret::<DhP256HkdfSha256>::default();
    classical.0.copy_from_slice(&hybrid.0);
    let mut receiver: AeadCtxR<ChaCha20Poly1305, HkdfSha256, DhP256HkdfSha256> =
        HkdfSha256::combine_secrets::<ChaCha20Poly1305, DhP256HkdfSha256, _>(
            &OpModeR::Base,
            classical,
            INFO,
        )
        .into();
    assert!(receiver.open(&body, b"").is_err());
}
