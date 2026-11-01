//! RSA-2048 public wrapping only. Private operations belong to Windows PCP.
use crate::invalid;
use aws_lc_rs::rsa::{
    OAEP_SHA256_MGF1SHA256, OaepPublicEncryptingKey, PublicEncryptingKey, PublicKeyComponents,
};
use std::io;

#[derive(Clone, PartialEq, Eq)]
pub struct RsaPublicKey {
    modulus: [u8; 256],
}

impl RsaPublicKey {
    pub fn from_modulus(modulus: [u8; 256]) -> io::Result<Self> {
        if modulus[0] & 0x80 == 0 || modulus[255] & 1 == 0 {
            return Err(invalid("invalid RSA-2048 modulus"));
        }
        let key = Self { modulus };
        key.backend()?;
        Ok(key)
    }

    pub fn modulus(&self) -> &[u8; 256] {
        &self.modulus
    }

    fn backend(&self) -> io::Result<PublicEncryptingKey> {
        PublicKeyComponents {
            n: self.modulus.as_slice(),
            e: &[1, 0, 1],
        }
        .try_into()
        .map_err(|_| invalid("invalid RSA public key"))
    }

    /// The checker also uses this to exercise wrong-label and wrong-size rejection.
    pub fn encrypt_oaep(&self, plaintext: &[u8], label: &[u8]) -> io::Result<Vec<u8>> {
        let key = OaepPublicEncryptingKey::new(self.backend()?)
            .map_err(|_| invalid("RSA wrapping failed"))?;
        let mut ciphertext = vec![0; 256];
        let written = key
            .encrypt(
                &OAEP_SHA256_MGF1SHA256,
                plaintext,
                &mut ciphertext,
                Some(label),
            )
            .map_err(|_| invalid("RSA wrapping failed"))?
            .len();
        if written != ciphertext.len() {
            return Err(invalid("invalid RSA ciphertext length"));
        }
        Ok(ciphertext)
    }
}
