//! Preserve cleanup failure as a safety fact across ordinary operation errors.
use super::Result;

pub(crate) type Outcome<T> = std::result::Result<T, Failure>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailureKind {
    Operational,
    Authentication,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    pub message: String,
    pub cleanup_failed: bool,
    pub kind: FailureKind,
}
impl From<String> for Failure {
    fn from(message: String) -> Self {
        Self {
            message,
            cleanup_failed: false,
            kind: FailureKind::Operational,
        }
    }
}
impl From<&str> for Failure {
    fn from(message: &str) -> Self {
        message.to_owned().into()
    }
}
impl Failure {
    pub fn authentication() -> Self {
        Self {
            message: "post-quantum HPKE authentication failed".into(),
            cleanup_failed: false,
            kind: FailureKind::Authentication,
        }
    }

    /// Resource release preserves every failure, even if the operation failed first.
    pub fn complete<T>(operation: Outcome<T>, release: Result<()>) -> Outcome<T> {
        match release {
            Ok(()) => operation,
            Err(cleanup) => Err(Self {
                message: match operation {
                    Ok(_) => format!("cleanup {cleanup}"),
                    Err(operation) => format!("operation {}; cleanup {cleanup}", operation.message),
                },
                cleanup_failed: true,
                kind: FailureKind::Operational,
            }),
        }
    }
    /// Authorized deletion and its independent absence check are both cleanup.
    /// A failed delete stops before verification; neither failure permits retry.
    pub fn delete_and_verify(
        delete: impl FnOnce() -> Result<()>,
        verify_absence: impl FnOnce() -> Result<()>,
    ) -> Outcome<()> {
        Self::complete(Ok(()), delete())?;
        Self::complete(Ok(()), verify_absence())
    }
    /// Never start another destructive cleanup after an earlier cleanup failure.
    pub fn rollback(self, cleanup: impl FnOnce() -> Outcome<()>) -> Self {
        if self.cleanup_failed {
            return self;
        }
        match Self::complete::<()>(Err(self), cleanup().map_err(|failure| failure.message)) {
            Err(failure) => failure,
            Ok(()) => unreachable!("the original operation failed"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authentication_kind_survives_successful_release_but_not_cleanup_failure() {
        let preserved =
            Failure::complete::<()>(Err(Failure::authentication()), Ok(())).unwrap_err();
        assert_eq!(preserved.kind, FailureKind::Authentication);
        assert!(!preserved.cleanup_failed);
        let fatal = Failure::complete::<()>(Err(preserved), Err("context close failed".into()))
            .unwrap_err();
        assert_eq!(fatal.kind, FailureKind::Operational);
        assert!(fatal.cleanup_failed);
        let fatal = Failure::complete::<()>(Err(fatal), Ok(())).unwrap_err();
        assert!(fatal.cleanup_failed);
    }
    #[test]
    fn diagnostic_text_does_not_classify_operational_errors() {
        let ordinary = Failure::from("HPKE authentication failed");
        assert_eq!(ordinary.kind, FailureKind::Operational);
        assert!(!ordinary.cleanup_failed);
    }
    #[test]
    fn earlier_cleanup_failure_blocks_destructive_rollback() {
        let failure =
            Failure::complete::<()>(Err("operation error".into()), Err("flush error".into()))
                .unwrap_err();
        let failure = Failure::complete::<()>(Err(failure), Ok(())).unwrap_err();
        let failure = failure.rollback(|| panic!("must not delete PCP key or filesystem"));
        assert!(failure.cleanup_failed);
        assert!(failure.message.contains("operation error"));
        assert!(failure.message.contains("flush error"));
    }
    #[test]
    fn ordinary_failure_rolls_back_once_and_retains_cleanup_error() {
        let mut actions = Vec::new();
        let failure = Failure::from("write error").rollback(|| {
            actions.push("delete owned key");
            Err("absence error".into())
        });
        let failure = failure.rollback(|| {
            actions.push("delete files");
            Ok(())
        });
        assert_eq!(actions, ["delete owned key"]);
        assert!(failure.cleanup_failed);
        assert!(failure.message.contains("write error"));
        assert!(failure.message.contains("absence error"));
        let mut attempts = 0;
        let failure = Failure::from("operation error").rollback(|| {
            attempts += 1;
            Ok(())
        });
        assert_eq!(attempts, 1);
        assert!(!failure.cleanup_failed);
        assert_eq!(failure.message, "operation error");
    }
    #[test]
    fn persistent_delete_failure_stops_before_absence_and_cannot_retry() {
        let failure = Failure::delete_and_verify(
            || Err("delete failed".into()),
            || panic!("no absence check after failed delete"),
        )
        .unwrap_err();
        assert!(failure.cleanup_failed);
        let failure = failure.rollback(|| panic!("driver must not delete again"));
        assert!(failure.message.contains("delete failed"));
    }
    #[test]
    fn successful_delete_with_failed_absence_cannot_authorize_later_cleanup() {
        let actions = std::cell::RefCell::new(Vec::new());
        let failure = Failure::delete_and_verify(
            || {
                actions.borrow_mut().push("delete");
                Ok(())
            },
            || {
                actions.borrow_mut().push("absence");
                Err("query failed".into())
            },
        )
        .unwrap_err();
        assert_eq!(*actions.borrow(), ["delete", "absence"]);
        assert!(failure.cleanup_failed);
        let failure = failure.rollback(|| panic!("must not remove storage after failed absence"));
        assert!(failure.message.contains("query failed"));
        assert!(Failure::delete_and_verify(|| Ok(()), || Ok(())).is_ok());
    }
    #[test]
    fn close_failure_cannot_be_hidden_by_operation_or_release_success() {
        for operation in [Ok(()), Err(Failure::from("operation error"))] {
            let result = Failure::complete(operation, Ok(()));
            let failure = Failure::complete(result, Err("context close error".into())).unwrap_err();
            assert!(failure.cleanup_failed);
            assert!(failure.message.contains("context close error"));
        }
    }
}
