#![forbid(unsafe_code)]

pub mod cli;
pub mod client;
pub mod formats;
pub mod keys;
pub mod plugin;
pub mod post_quantum;
pub mod rsa;
pub mod schemes;
pub mod wire;

use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use rsa::RsaPublicKey;
use sha2::{Digest, Sha256};
use std::io;

pub use formats::{HPKE_RECIPIENT_LEN, HPKE_TAG};
use formats::{HPKE_STANZA_VERSION, P256_RECIPIENT_PREFIX};

pub const NAME: &str = "tpm-wsl";
pub const TAG: &str = "tpm-wsl-rsa";
// TPM RSA OAEP labels are NUL-terminated; the terminator is part of the hash.
pub const LABEL: &str = "age-plugin-tpm-wsl/v1\0";
pub const RECIPIENT_LEN: usize = 257;

pub fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    Rsa2048,
    P256Hpke,
}
impl Scheme {
    pub fn parse(name: &str) -> io::Result<Self> {
        match name {
            "rsa2048" => Ok(Self::Rsa2048),
            "p256-hpke" => Ok(Self::P256Hpke),
            _ => Err(invalid("unsupported algorithm; use rsa2048 or p256-hpke")),
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa2048",
            Self::P256Hpke => "p256-hpke",
        }
    }
    pub fn tag(self) -> &'static str {
        match self {
            Self::Rsa2048 => TAG,
            Self::P256Hpke => HPKE_TAG,
        }
    }
    pub fn stanza_version(self) -> &'static str {
        match self {
            Self::Rsa2048 => "1",
            Self::P256Hpke => HPKE_STANZA_VERSION,
        }
    }
    pub fn body_len(self) -> usize {
        match self {
            Self::Rsa2048 => 256,
            Self::P256Hpke => 65 + 16 + 16,
        }
    }
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag {
            TAG => Some(Self::Rsa2048),
            HPKE_TAG => Some(Self::P256Hpke),
            _ => None,
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub enum PublicKey {
    Rsa(RsaPublicKey),
    P256([u8; 65]),
}

#[derive(Clone, PartialEq, Eq)]
pub struct Recipient {
    pub key: PublicKey,
}
impl Recipient {
    pub fn rsa(key: RsaPublicKey) -> Self {
        Self {
            key: PublicKey::Rsa(key),
        }
    }
    fn encoded_len(bytes: &[u8]) -> io::Result<usize> {
        match bytes.first() {
            Some(1) => Ok(RECIPIENT_LEN),
            _ if bytes.starts_with(&P256_RECIPIENT_PREFIX) => Ok(HPKE_RECIPIENT_LEN),
            _ => Err(invalid("unsupported recipient version or suite")),
        }
    }
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != Self::encoded_len(bytes)? {
            return Err(invalid("invalid recipient length"));
        }
        let key = if bytes[0] == 1 {
            PublicKey::Rsa(RsaPublicKey::from_modulus(
                bytes[1..]
                    .try_into()
                    .map_err(|_| invalid("invalid RSA modulus length"))?,
            )?)
        } else {
            let point = &bytes[P256_RECIPIENT_PREFIX.len()..];
            schemes::validate_point(point)?;
            PublicKey::P256(
                point
                    .try_into()
                    .map_err(|_| invalid("invalid P-256 public key"))?,
            )
        };
        Ok(Self { key })
    }
    pub fn scheme(&self) -> Scheme {
        match &self.key {
            PublicKey::Rsa(_) => Scheme::Rsa2048,
            PublicKey::P256(_) => Scheme::P256Hpke,
        }
    }
    pub fn bytes(&self) -> Vec<u8> {
        match &self.key {
            PublicKey::Rsa(key) => {
                let mut bytes = vec![1];
                bytes.extend(key.modulus());
                bytes
            }
            PublicKey::P256(point) => {
                let mut bytes = P256_RECIPIENT_PREFIX.to_vec();
                bytes.extend(point);
                bytes
            }
        }
    }
    pub fn fingerprint(&self) -> String {
        BASE64_STANDARD_NO_PAD.encode(Sha256::digest(self.bytes()))
    }
}

#[derive(Clone)]
pub struct Identity {
    pub recipient: Recipient,
    pub name: String,
}
impl Identity {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        let split = Recipient::encoded_len(bytes)?;
        if bytes.len() <= split {
            return Err(invalid("short identity"));
        }
        let recipient = Recipient::parse(&bytes[..split])?;
        let length = usize::from(bytes[split]);
        if bytes.len() != split + 1 + length {
            return Err(invalid("invalid identity length"));
        }
        let name =
            std::str::from_utf8(&bytes[split + 1..]).map_err(|_| invalid("invalid key name"))?;
        validate_name(name)?;
        Ok(Self {
            recipient,
            name: name.into(),
        })
    }
    pub fn bytes(&self) -> Vec<u8> {
        let mut bytes = self.recipient.bytes();
        bytes.push(self.name.len() as u8);
        bytes.extend(self.name.as_bytes());
        bytes
    }
}

pub fn validate_name(name: &str) -> io::Result<()> {
    let suffix = name
        .strip_prefix("age-tpm-wsl-")
        .ok_or_else(|| invalid("invalid key name"))?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid("invalid key name"));
    }
    Ok(())
}
