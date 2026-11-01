//! Canonical age MLKEM768-P256 wrapping and TPM-custody records.
//!
//! Public wrapping is offline. A receiver supplies an already restored ML-KEM
//! key and an opaque agreement callback; Windows custody owns authorization,
//! actual PCP identity checks, storage and key lifecycle. This module performs
//! no filesystem access, key enrollment or provider fallback.
#![forbid(unsafe_code)]

mod crypto;
mod identity;

pub use crypto::{ENC_LEN, INFO, PUBLIC_LEN, Wrapped, routing_tag, validate_public, wrap};
#[cfg(feature = "seed-restoration")]
pub use crypto::{OpenFailure, open, open_classified};
pub use identity::{
    IDENTITY_LEN, Identity, MAX_RECORD, NAME_LEN, RECIPIENT_LEN, Record, validate_name,
};
