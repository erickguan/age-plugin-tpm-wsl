//! Exercise real request dispatch against the harness's isolated store.
use super::{Identity, Input, Outcome, Store, random};
use crate::post_quantum::dispatch::{StoreLocation, at};
use age_plugin_tpm_wsl::wire::Frame;

impl StoreLocation for Input {
    fn for_creation(&self) -> Outcome<Store> {
        self.store(true)
    }
    fn existing(&self) -> Outcome<Store> {
        self.store(false)
    }
}

pub(super) fn roundtrip(input: &Input, identity: &Identity) -> Outcome<()> {
    let key = random::<16>()?;
    let wrapped = age_tpm_wsl_post_quantum::wrap(identity.public(), key.as_ref())
        .map_err(|_| "native public wrapping failed")?;
    let request = Frame::post_quantum_unwrap(identity, &wrapped.enc, &wrapped.body)
        .map_err(|_| "native unwrap request encoding failed")?;
    let response = at(&request, input)?;
    if response.as_slice() != key.as_ref() {
        return Err("native dispatched file key mismatch".into());
    }
    Ok(())
}
