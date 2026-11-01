use crate::{Identity, Scheme, invalid};
use std::io::{self, Read, Write};
use zeroize::Zeroizing;

pub const MAX_PAYLOAD: usize = 8192;
pub const CREATE: u8 = 1;
pub const INSPECT: u8 = 2;
pub const UNWRAP: u8 = 3;
pub const DELETE: u8 = 4;
pub const RECOVER: u8 = 5;
pub const CREATE_SCHEME: u8 = 6;
pub const UNWRAP_SCHEME: u8 = 7;
pub const CREATE_POST_QUANTUM: u8 = 8;
pub const UNWRAP_POST_QUANTUM: u8 = 9;
pub const RECOVER_POST_QUANTUM: u8 = 10;

mod post_quantum;
pub use post_quantum::PostQuantumRequest;

pub struct Frame {
    pub operation: u8,
    pub status: u32,
    pub payload: Zeroizing<Vec<u8>>,
}

impl Frame {
    pub fn unwrap(identity: &Identity, body: &[u8]) -> Self {
        let bytes = identity.bytes();
        let mut payload = Zeroizing::new(Vec::new());
        let operation = if identity.recipient.scheme() == Scheme::Rsa2048 {
            UNWRAP
        } else {
            payload.extend((bytes.len() as u16).to_be_bytes());
            UNWRAP_SCHEME
        };
        payload.extend(bytes);
        payload.extend(body);
        Self {
            operation,
            status: 0,
            payload,
        }
    }

    pub fn unwrap_parts(&self) -> io::Result<(Identity, &[u8])> {
        let (identity_bytes, body) = match self.operation {
            UNWRAP if self.payload.len() > 256 => self.payload.split_at(self.payload.len() - 256),
            UNWRAP_SCHEME if self.payload.len() >= 2 => {
                let split = usize::from(u16::from_be_bytes([self.payload[0], self.payload[1]]));
                let payload = &self.payload[2..];
                if split > payload.len() {
                    return Err(invalid("invalid unwrap identity length"));
                }
                payload.split_at(split)
            }
            _ => return Err(invalid("invalid unwrap request")),
        };
        let identity = Identity::parse(identity_bytes)?;
        let scheme = identity.recipient.scheme();
        if (self.operation == UNWRAP && scheme != Scheme::Rsa2048)
            || (self.operation == UNWRAP_SCHEME && scheme != Scheme::P256Hpke)
            || body.len() != scheme.body_len()
        {
            return Err(invalid(
                "unwrap operation, scheme or ciphertext length mismatch",
            ));
        }
        Ok((identity, body))
    }

    pub fn write(&self, mut output: impl Write) -> io::Result<()> {
        if !(CREATE..=RECOVER_POST_QUANTUM).contains(&self.operation)
            || self.payload.len() > MAX_PAYLOAD
        {
            return Err(invalid("invalid frame"));
        }
        if self.status != 0 && !self.payload.is_empty() {
            return Err(invalid("error frame contains payload"));
        }
        output.write_all(b"ATW1")?;
        output.write_all(&[self.operation])?;
        output.write_all(&self.status.to_le_bytes())?;
        output.write_all(&(self.payload.len() as u32).to_le_bytes())?;
        output.write_all(&self.payload)?;
        output.flush()
    }

    pub fn read(mut input: impl Read) -> io::Result<Self> {
        let mut header = [0; 13];
        input.read_exact(&mut header)?;
        if &header[..4] != b"ATW1" || !(CREATE..=RECOVER_POST_QUANTUM).contains(&header[4]) {
            return Err(invalid("invalid helper frame header"));
        }
        let status = u32::from_le_bytes(header[5..9].try_into().unwrap());
        let length = u32::from_le_bytes(header[9..13].try_into().unwrap()) as usize;
        if length > MAX_PAYLOAD || (status != 0 && length != 0) {
            return Err(invalid("invalid helper frame length"));
        }
        let mut payload = Zeroizing::new(vec![0; length]);
        input.read_exact(&mut payload)?;
        let mut trailing = [0];
        if input.read(&mut trailing)? != 0 {
            return Err(invalid("trailing helper data"));
        }
        Ok(Self {
            operation: header[4],
            status,
            payload,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_hostile_frames() {
        let frame = Frame {
            operation: UNWRAP,
            status: 0,
            payload: Zeroizing::new(vec![42; 16]),
        };
        let mut valid = vec![];
        frame.write(&mut valid).unwrap();
        assert_eq!(&*Frame::read(valid.as_slice()).unwrap().payload, &[42; 16]);
        for length in 0..valid.len() {
            assert!(Frame::read(&valid[..length]).is_err());
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(Frame::read(trailing.as_slice()).is_err());
        for (offset, replacement) in [(0, 0), (4, 0), (5, 1)] {
            let mut broken = valid.clone();
            broken[offset] = replacement;
            assert!(Frame::read(broken.as_slice()).is_err());
        }
        valid[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Frame::read(valid.as_slice()).is_err());
    }
}
