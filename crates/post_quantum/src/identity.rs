//! Canonical hybrid identity and custody descriptor.
//! No key creation, private operations, filesystem access or enrollment occurs here.

use sha2::{Digest, Sha256};
use std::io;

mod record;
pub use record::{MAX_RECORD, Record};

pub const PUBLIC_LEN: usize = 1249;
pub const RECIPIENT_LEN: usize = 1252;
pub const IDENTITY_LEN: usize = 1300;
pub const NAME_LEN: usize = 47;
const PREFIX: [u8; 3] = [3, 0, 2];
const NAME_PREFIX: &str = "age-tpm-wsl-pq-";

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn valid_name(name: &str) -> bool {
    name.len() == NAME_LEN
        && name.starts_with(NAME_PREFIX)
        && name.as_bytes()[NAME_PREFIX.len()..]
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
}

pub fn validate_name(name: &str) -> io::Result<()> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(invalid("invalid dedicated hybrid key name"))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Identity {
    public: [u8; PUBLIC_LEN],
    name: String,
}
impl Identity {
    pub fn new(public: &[u8], name: &str) -> io::Result<Self> {
        validate_name(name)?;
        crate::crypto::validate_public(public)?;
        Ok(Self {
            public: public
                .try_into()
                .map_err(|_| invalid("invalid hybrid public length"))?,
            name: name.into(),
        })
    }

    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() != IDENTITY_LEN
            || bytes[..3] != PREFIX
            || bytes[RECIPIENT_LEN] != NAME_LEN as u8
        {
            return Err(invalid("invalid canonical hybrid identity"));
        }
        let name = std::str::from_utf8(&bytes[RECIPIENT_LEN + 1..])
            .map_err(|_| invalid("invalid hybrid key name encoding"))?;
        Self::new(&bytes[3..RECIPIENT_LEN], name)
    }

    pub fn public(&self) -> &[u8; PUBLIC_LEN] {
        &self.public
    }
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn recipient(&self) -> [u8; RECIPIENT_LEN] {
        let mut bytes = [0; RECIPIENT_LEN];
        bytes[..3].copy_from_slice(&PREFIX);
        bytes[3..].copy_from_slice(&self.public);
        bytes
    }

    pub fn bytes(&self) -> [u8; IDENTITY_LEN] {
        let mut bytes = [0; IDENTITY_LEN];
        bytes[..RECIPIENT_LEN].copy_from_slice(&self.recipient());
        bytes[RECIPIENT_LEN] = NAME_LEN as u8;
        bytes[RECIPIENT_LEN + 1..].copy_from_slice(self.name.as_bytes());
        bytes
    }

    pub fn commitment(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"ATW-PQ-RECIPIENT-v1\0");
        hash.update(b"age1tagpq\0");
        hash.update(self.recipient());
        hash.finalize().into()
    }

    pub fn binding(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"ATW-CUSTODY-BINDING-v2\0");
        hash.update(self.bytes());
        hash.update(self.commitment());
        hash.finalize().into()
    }
}

#[cfg(test)]
mod tests;
