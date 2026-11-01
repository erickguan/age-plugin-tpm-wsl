//! Compatibility checks for replacing the RSA implementation without a format change.
use age_plugin_tpm_wsl::{LABEL, Recipient, schemes};
use aws_lc_rs::{
    encoding::{AsDer, PublicKeyX509Der},
    rsa::{
        KeySize, OAEP_SHA1_MGF1SHA1, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey,
        PrivateDecryptingKey, PublicKey,
    },
};
use zeroize::Zeroizing;

#[test]
fn legacy_rsa_encoding_and_fingerprint_remain_exact() {
    let mut bytes = vec![1];
    bytes.extend([0xff; 256]);
    let recipient = Recipient::parse(&bytes).unwrap();
    assert_eq!(recipient.bytes(), bytes);
    assert_eq!(
        recipient.fingerprint(),
        "3wcs6PvRTqihODyLJHVmhKdTUMnw4yJ2TbpXENSpkS8"
    );
}

#[test]
fn rsa_wrapping_requires_exact_file_key_and_oaep_parameters() {
    let private = PrivateDecryptingKey::generate(KeySize::Rsa2048).unwrap();
    let der: PublicKeyX509Der<'static> = private.public_key().as_der().unwrap();
    let public = PublicKey::from_der(der.as_ref()).unwrap();
    assert_eq!(
        public.exponent().big_endian_without_leading_zero(),
        [1, 0, 1]
    );
    let mut bytes = vec![1];
    bytes.extend(public.modulus().big_endian_without_leading_zero());
    let recipient = Recipient::parse(&bytes).unwrap();
    let key = OaepPrivateDecryptingKey::new(private).unwrap();
    let file_key = Zeroizing::new([0x5a; 16]);
    let ciphertext = schemes::wrap(&recipient, file_key.as_slice()).unwrap();
    assert_eq!(ciphertext.len(), 256);
    assert_ne!(
        ciphertext,
        schemes::wrap(&recipient, file_key.as_slice()).unwrap()
    );
    let mut plaintext = Zeroizing::new(vec![0; key.min_output_size()]);
    assert_eq!(
        key.decrypt(
            &OAEP_SHA256_MGF1SHA256,
            &ciphertext,
            &mut plaintext,
            Some(b"age-plugin-tpm-wsl/v1\0"),
        )
        .unwrap(),
        file_key.as_slice()
    );
    // A backend default, strlen-based label, or hash change must never pass.
    assert_eq!(LABEL.as_bytes(), b"age-plugin-tpm-wsl/v1\0");
    for label in [
        None,
        Some(b"age-plugin-tpm-wsl/v1".as_slice()),
        Some(b"wrong\0".as_slice()),
    ] {
        assert!(
            key.decrypt(&OAEP_SHA256_MGF1SHA256, &ciphertext, &mut plaintext, label)
                .is_err()
        );
    }
    assert!(
        key.decrypt(
            &OAEP_SHA1_MGF1SHA1,
            &ciphertext,
            &mut plaintext,
            Some(LABEL.as_bytes())
        )
        .is_err()
    );
    for length in [0, 15, 17, 256] {
        assert!(schemes::wrap(&recipient, &vec![0; length]).is_err());
    }
}
