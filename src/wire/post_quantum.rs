//! Fixed post-quantum helper payloads. Parsing performs no storage or private operation.
use super::{CREATE_POST_QUANTUM, Frame, RECOVER_POST_QUANTUM, UNWRAP_POST_QUANTUM};
use crate::{formats::POST_QUANTUM_SUITE_ID, invalid};
use age_tpm_wsl_post_quantum::{
    ENC_LEN, IDENTITY_LEN, Identity, NAME_LEN, routing_tag, validate_name,
};
use std::io;
use zeroize::Zeroizing;

/// A fully validated request, before any directory/key acquisition or unsealing.
/// Boxing the public identity keeps the enum small; no private material is here.
pub enum PostQuantumRequest<'a> {
    Create {
        name: &'a str,
    },
    Unwrap {
        identity: Box<Identity>,
        enc: &'a [u8; ENC_LEN],
        body: &'a [u8; 32],
    },
    Recover {
        name: &'a str,
    },
}

fn name(bytes: &[u8]) -> io::Result<&str> {
    let value =
        std::str::from_utf8(bytes).map_err(|_| invalid("invalid post-quantum name encoding"))?;
    validate_name(value)?;
    Ok(value)
}

fn ciphertext<'a>(
    identity: &Identity,
    enc: &'a [u8],
    body: &'a [u8],
) -> io::Result<(&'a [u8; ENC_LEN], &'a [u8; 32])> {
    let enc: &[u8; ENC_LEN] = enc
        .try_into()
        .map_err(|_| invalid("invalid post-quantum encapsulation length"))?;
    let body: &[u8; 32] = body
        .try_into()
        .map_err(|_| invalid("invalid post-quantum ciphertext length"))?;
    // This public calculation also validates the ephemeral point before any
    // private work. It conveys no identity authority or authentication result.
    routing_tag(identity.public(), enc)?;
    Ok((enc, body))
}

impl Frame {
    pub fn post_quantum_create(name: &str) -> io::Result<Self> {
        validate_name(name)?;
        let mut payload = Zeroizing::new(POST_QUANTUM_SUITE_ID.to_vec());
        payload.extend(name.as_bytes());
        Ok(Self {
            operation: CREATE_POST_QUANTUM,
            status: 0,
            payload,
        })
    }

    pub fn post_quantum_recover(name: &str) -> io::Result<Self> {
        validate_name(name)?;
        Ok(Self {
            operation: RECOVER_POST_QUANTUM,
            status: 0,
            payload: Zeroizing::new(name.as_bytes().to_vec()),
        })
    }

    pub fn post_quantum_unwrap(identity: &Identity, enc: &[u8], body: &[u8]) -> io::Result<Self> {
        ciphertext(identity, enc, body)?;
        let mut payload = Zeroizing::new(Vec::with_capacity(2 + IDENTITY_LEN + ENC_LEN + 32));
        payload.extend((IDENTITY_LEN as u16).to_be_bytes());
        payload.extend(identity.bytes());
        payload.extend(enc);
        payload.extend(body);
        Ok(Self {
            operation: UNWRAP_POST_QUANTUM,
            status: 0,
            payload,
        })
    }

    pub fn post_quantum_request(&self) -> io::Result<PostQuantumRequest<'_>> {
        if self.status != 0 {
            return Err(invalid("post-quantum request status must be zero"));
        }
        let payload = self.payload.as_slice();
        match self.operation {
            CREATE_POST_QUANTUM
                if payload.len() == POST_QUANTUM_SUITE_ID.len() + NAME_LEN
                    && payload.starts_with(&POST_QUANTUM_SUITE_ID) =>
            {
                Ok(PostQuantumRequest::Create {
                    name: name(&payload[2..])?,
                })
            }
            RECOVER_POST_QUANTUM if payload.len() == NAME_LEN => Ok(PostQuantumRequest::Recover {
                name: name(payload)?,
            }),
            UNWRAP_POST_QUANTUM
                if payload.len() == 2 + IDENTITY_LEN + ENC_LEN + 32
                    && payload[..2] == (IDENTITY_LEN as u16).to_be_bytes() =>
            {
                let identity = Identity::parse(&payload[2..2 + IDENTITY_LEN])?;
                let (enc, body) = ciphertext(
                    &identity,
                    &payload[2 + IDENTITY_LEN..2 + IDENTITY_LEN + ENC_LEN],
                    &payload[2 + IDENTITY_LEN + ENC_LEN..],
                )?;
                Ok(PostQuantumRequest::Unwrap {
                    identity: Box::new(identity),
                    enc,
                    body,
                })
            }
            _ => Err(invalid(
                "invalid post-quantum operation, suite or request length",
            )),
        }
    }
}
