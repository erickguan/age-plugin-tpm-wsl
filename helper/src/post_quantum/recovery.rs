//! Check retained public authority before any recovery verification or commit.
#![forbid(unsafe_code)]
use super::lifecycle::Outcome;
use age_tpm_wsl_post_quantum::Identity;

/// Name-only operator recovery intentionally establishes a new expectation.
/// Identity-bound validation recovery instead rejects substituted receipts before
/// entering the continuation that may unseal, verify or commit pending storage.
pub(super) fn with_receipt<T>(
    receipt: &[u8],
    name: &str,
    expected: Option<&Identity>,
    recover: impl FnOnce(Identity) -> Outcome<T>,
) -> Outcome<T> {
    let identity = Identity::parse(receipt).map_err(|_| "invalid recovery receipt")?;
    if identity.name() != name {
        return Err("recovery receipt name mismatch".into());
    }
    if expected.is_some_and(|expected| expected != &identity) {
        return Err("recovery receipt differs from retained identity".into());
    }
    recover(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    const NAME: &str = "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef";
    fn identity() -> Identity {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../notes/aws-lc-hybrid-evaluation/go-fixture.json"
        ))
        .unwrap();
        let public = fixture["public_key"]
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>();
        Identity::new(&public, NAME).unwrap()
    }

    #[test]
    fn substituted_same_name_receipt_never_enters_private_or_commit_work() {
        let expected = identity();
        let mut public = expected.public().to_vec();
        let coefficient = u16::from(public[0]) | (u16::from(public[1] & 15) << 8);
        public[0] = u8::from(coefficient == 0);
        public[1] &= 0xf0;
        let substituted = Identity::new(&public, NAME).unwrap();
        assert!(substituted != expected);
        let entered = Cell::new(false);
        let result = with_receipt(&substituted.bytes(), NAME, Some(&expected), |_| {
            entered.set(true);
            Ok(())
        });
        assert!(result.is_err());
        assert!(
            !entered.get(),
            "private verification/commit continuation must not run"
        );
    }

    #[test]
    fn malformed_or_wrong_name_receipts_never_enter_recovery() {
        let expected = identity();
        let receipt = expected.bytes();
        for (receipt, name) in [
            (&receipt[..1299], NAME),
            (
                &receipt[..],
                "age-tpm-wsl-pq-00000000000000000000000000000000",
            ),
        ] {
            assert!(
                with_receipt::<()>(receipt, name, Some(&expected), |_| {
                    panic!("invalid receipt reached private verification or commit")
                })
                .is_err()
            );
        }
    }

    #[test]
    fn matching_and_explicit_name_only_recovery_keep_their_contracts() {
        let identity = identity();
        for expected in [Some(&identity), None] {
            let result = with_receipt(&identity.bytes(), NAME, expected, |accepted| {
                assert!(accepted == identity);
                Ok("verified continuation")
            });
            assert_eq!(result.unwrap(), "verified continuation");
        }
    }
}
