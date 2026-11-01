//! Bounded ATW1 on stdout; no file key passes through a test/logging harness.
#![forbid(unsafe_code)]
use super::arguments::Arguments;
use crate::post_quantum::{
    dispatch::{StoreLocation, at},
    lifecycle::{Failure, FailureKind, Outcome},
};
use age_plugin_tpm_wsl::wire::{
    CREATE_POST_QUANTUM, DELETE, Frame, RECOVER_POST_QUANTUM, UNWRAP_POST_QUANTUM,
};
use zeroize::Zeroizing;

fn execute(
    request: &Frame,
    arguments: &Arguments,
    location: &impl StoreLocation,
) -> Outcome<Zeroizing<Vec<u8>>> {
    arguments.authorize(request)?;
    let payload = if request.operation == RECOVER_POST_QUANTUM {
        // The ordinary name-only recovery command establishes a new reference.
        // This fixture must bind the receipt BEFORE private verification/commit.
        let expected = arguments.retained_identity()?;
        Zeroizing::new(
            location
                .existing()?
                .recover_authorized(expected.name(), Some(expected))?
                .bytes()
                .to_vec(),
        )
    } else {
        at(request, location)?
    };
    if matches!(
        request.operation,
        CREATE_POST_QUANTUM | RECOVER_POST_QUANTUM
    ) {
        arguments
            .check_identity_response(&payload)
            .map_err(|message| Failure {
                message,
                // A successful create followed by an unusable reference leaves
                // ownership uncertain. The controller must retain and stop.
                cleanup_failed: request.operation == CREATE_POST_QUANTUM,
                kind: FailureKind::Operational,
            })?;
    }
    if (request.operation == UNWRAP_POST_QUANTUM && payload.len() != 16)
        || (request.operation == DELETE && !payload.is_empty())
    {
        return Err("invalid successful fixture response length".into());
    }
    Ok(payload)
}

// Validation-only status: production dispatch retains its existing status ABI.
const AUTHENTICATION_FAILED: u32 = 0xa0010003;

fn failure_status(operation: u8, failure: &Failure) -> u32 {
    if failure.cleanup_failed {
        crate::cng::CLEANUP_FAILED
    } else if operation == UNWRAP_POST_QUANTUM && failure.kind == FailureKind::Authentication {
        AUTHENTICATION_FAILED
    } else {
        crate::cng::INVALID
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_completed_unwrap_authentication_gets_the_validation_status() {
        let authentication = Failure::authentication();
        assert_eq!(
            failure_status(UNWRAP_POST_QUANTUM, &authentication),
            AUTHENTICATION_FAILED
        );
        assert_eq!(
            failure_status(CREATE_POST_QUANTUM, &authentication),
            crate::cng::INVALID
        );
        assert_eq!(
            failure_status(UNWRAP_POST_QUANTUM, &Failure::from("CNG agreement failed")),
            crate::cng::INVALID
        );
        assert_eq!(
            failure_status(
                UNWRAP_POST_QUANTUM,
                &Failure::from("HPKE authentication failed")
            ),
            crate::cng::INVALID
        );
    }
    #[test]
    fn failed_release_dominates_an_authentication_result() {
        let failure =
            Failure::complete::<()>(Err(Failure::authentication()), Err("close failed".into()))
                .unwrap_err();
        assert_eq!(
            failure_status(UNWRAP_POST_QUANTUM, &failure),
            crate::cng::CLEANUP_FAILED
        );
    }
}

pub fn serve(arguments: &Arguments, location: &impl StoreLocation) -> Outcome<()> {
    let request =
        Frame::read(std::io::stdin().lock()).map_err(|_| "invalid or interrupted fixture frame")?;
    let (status, payload) = match execute(&request, arguments, location) {
        Ok(payload) => (0, payload),
        Err(error) => {
            eprintln!("post-quantum-fixture: {}", error.message);
            (
                failure_status(request.operation, &error),
                Zeroizing::new(Vec::new()),
            )
        }
    };
    Frame {
        operation: request.operation,
        status,
        payload,
    }
    .write(std::io::stdout().lock())
    .map_err(|_| "interrupted fixture response".into())
}
