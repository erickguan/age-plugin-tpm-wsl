//! Validate helper requests before acquiring storage or private-key authority.
use super::{Identity, lifecycle::Outcome, store::Store};
use age_plugin_tpm_wsl::wire::{DELETE, Frame, INSPECT, PostQuantumRequest};
use zeroize::Zeroizing;

/// Storage acquisition is the only variation between production dispatch and
/// the isolated native harness. Both return the same verified Store and run the
/// same custody lifecycle. Decryption can only ask for an existing root.
pub(crate) trait StoreLocation {
    fn for_creation(&self) -> Outcome<Store>;
    fn existing(&self) -> Outcome<Store>;
}

struct ProductionLocation;
impl StoreLocation for ProductionLocation {
    fn for_creation(&self) -> Outcome<Store> {
        Store::create_root()
    }
    fn existing(&self) -> Outcome<Store> {
        Store::existing()
    }
}

/// The production entry always selects the fixed production location. No
/// environment variable or request field can override that choice.
pub(crate) fn dispatch(request: &Frame) -> crate::cng::Result<Zeroizing<Vec<u8>>> {
    at(request, &ProductionLocation).map_err(|failure| {
        // All messages originate from fixed validation text or numeric status.
        // Never format seeds, raw agreement, file keys or ciphertext here.
        eprintln!("age-tpm-wsl-helper: {}", failure.message);
        if failure.cleanup_failed {
            crate::cng::CLEANUP_FAILED
        } else {
            crate::cng::INVALID
        }
    })
}

/// The same request validation and lifecycle serve each storage adapter. The
/// caller owns location selection; the protocol supplies no storage path.
pub(crate) fn at(request: &Frame, location: &impl StoreLocation) -> Outcome<Zeroizing<Vec<u8>>> {
    if request.status != 0 {
        return Err("invalid post-quantum request status".into());
    }
    if matches!(request.operation, INSPECT | DELETE) {
        let identity =
            Identity::parse(&request.payload).map_err(|_| "invalid post-quantum identity")?;
        let store = location.existing()?;
        return if request.operation == INSPECT {
            store.inspect(&identity).map(Zeroizing::new)
        } else {
            store.delete(&identity)?;
            Ok(Zeroizing::new(Vec::new()))
        };
    }
    match request
        .post_quantum_request()
        .map_err(|_| "invalid post-quantum request")?
    {
        PostQuantumRequest::Create { name } => Ok(Zeroizing::new(
            location.for_creation()?.create(name)?.bytes().to_vec(),
        )),
        PostQuantumRequest::Recover { name } => {
            let identity = location.existing()?.recover(name)?;
            eprintln!(
                "age-tpm-wsl-helper: explicit post-quantum recovery establishes a new public identity expectation; prior recipient continuity is not verified"
            );
            Ok(Zeroizing::new(identity.bytes().to_vec()))
        }
        PostQuantumRequest::Unwrap {
            identity,
            enc,
            body,
        } => location.existing()?.unwrap(&identity, enc, body),
    }
}

#[cfg(test)]
mod tests;
