//! Native public-key formats, independent of Windows calls for regression tests.
use age_plugin_tpm_wsl::{Recipient, formats::P256_RECIPIENT_PREFIX, invalid};
use std::io;

pub fn is_ecdh(algorithm: &str) -> bool {
    matches!(algorithm, "ECDH" | "ECDH_P256")
}

pub fn p256_recipient(algorithm: &str, blob: &[u8]) -> io::Result<Recipient> {
    // BCRYPT_ECDH_PUBLIC_P256_MAGIC (ECK1), cbKey=32, then x and y.
    if !is_ecdh(algorithm)
        || blob.len() != 72
        || blob[..4] != *b"ECK1"
        || blob[4..8] != 32u32.to_le_bytes()
    {
        return Err(invalid("invalid native P-256 public key"));
    }
    let mut bytes = P256_RECIPIENT_PREFIX.to_vec();
    bytes.push(4);
    bytes.extend(&blob[8..]);
    Recipient::parse(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_generic_ecdh_only_with_exact_canonical_p256_blob() {
        // SEC2 P-256 generator, public test material.
        let coordinates = [
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7,
            0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
            0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut blob = b"ECK1".to_vec();
        blob.extend(32u32.to_le_bytes());
        blob.extend(coordinates);
        for algorithm in ["ECDH", "ECDH_P256"] {
            let recipient = p256_recipient(algorithm, &blob).unwrap();
            assert_eq!(
                &recipient.bytes()[3..],
                &[&[4], coordinates.as_slice()].concat()
            );
            for (offset, value) in [(3, b'3'), (4, 48), (8, 0)] {
                let mut bad = blob.clone();
                bad[offset] = value;
                assert!(p256_recipient(algorithm, &bad).is_err());
            }
            assert!(p256_recipient(algorithm, &blob[..71]).is_err());
            let mut longer = blob.clone();
            longer.push(0);
            assert!(p256_recipient(algorithm, &longer).is_err());
        }
        for algorithm in ["ECDSA", "ECDSA_P256", "ECDH_P384", "RSA"] {
            assert!(p256_recipient(algorithm, &blob).is_err());
        }
    }
}
