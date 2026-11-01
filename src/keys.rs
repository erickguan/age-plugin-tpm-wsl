//! Explicit key creation shared by the CLI and disposable checker.
use crate::{
    Identity, Scheme,
    client::Helper,
    formats::P256_SUITE_ID,
    invalid,
    wire::{CREATE, CREATE_SCHEME, Frame},
};
use rand::{RngCore, rngs::OsRng};
use std::io;
use zeroize::Zeroizing;

pub fn key_name() -> String {
    let mut random = [0; 16];
    OsRng.fill_bytes(&mut random);
    format!(
        "age-tpm-wsl-{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

pub fn create_request(name: &str, scheme: Scheme) -> Frame {
    let mut payload = Zeroizing::new(Vec::new());
    let operation = match scheme {
        Scheme::Rsa2048 => CREATE,
        Scheme::P256Hpke => {
            payload.extend(P256_SUITE_ID);
            CREATE_SCHEME
        }
    };
    payload.extend(name.as_bytes());
    Frame {
        operation,
        status: 0,
        payload,
    }
}

pub fn create(helper: &Helper, scheme: Scheme) -> io::Result<Identity> {
    let name = key_name();
    // Keep the reference visible if a deadline interrupts creation.
    eprintln!("creating {} key {name}", scheme.name());
    let response = helper.call(create_request(&name, scheme))?;
    let identity = Identity::parse(&response.payload)?;
    if identity.name != name || identity.recipient.scheme() != scheme {
        return Err(invalid(
            "helper returned unexpected key name or scheme; inspect the reported key",
        ));
    }
    Ok(identity)
}
