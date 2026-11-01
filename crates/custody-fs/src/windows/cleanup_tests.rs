//! Test-only reported rollback failures. Actual owned unlink succeeds first, so
//! exercising the campaign's fatal-error boundary does not leave test objects.
use super::*;
use std::{
    any::Any,
    cell::{Cell, RefCell},
    fmt::Debug,
    process::Command,
};

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    UnlinkReport,
    AbsenceReport,
}
thread_local! {
    static FAULT: Cell<Fault> = const { Cell::new(Fault::None) };
    static NAMESPACE: RefCell<String> = const { RefCell::new(String::new()) };
}
const MARKER: &str = "ATW_TEST_CONTINUED_AFTER_CLEANUP_ERROR";

pub(super) fn namespace(value: &str) {
    NAMESPACE.with(|name| value.clone_into(&mut name.borrow_mut()));
}

pub(in crate::windows) fn after_verify(result: Result<()>, disposition: u32) -> Result<()> {
    if result.is_ok() && disposition == FILE_CREATE && FAULT.with(|f| f.get() != Fault::None) {
        Err(Error::Invalid("injected post-create verification failure"))
    } else {
        result
    }
}
pub(in crate::windows) fn after_unlink(result: Result<()>) -> Result<()> {
    // Never hide a genuine failure. Report the controlled fault only AFTER the
    // real owned-handle deletion succeeded; closing that handle completes it.
    if result.is_ok() && FAULT.with(|f| f.get() == Fault::UnlinkReport) {
        Err(Error::Invalid(
            "injected unlink-result failure after real success",
        ))
    } else {
        result
    }
}
pub(in crate::windows) fn after_absence(absent: bool) -> bool {
    absent && !FAULT.with(|f| f.get() == Fault::AbsenceReport)
}

pub(super) trait Must<T>: Sized {
    fn guard_cleanup(self) -> Self;
    fn must(self) -> T;
}
impl<T, E: Debug + Any> Must<T> for std::result::Result<T, E> {
    fn guard_cleanup(self) -> Self {
        if let Err(error) = &self
            && let Some(Error::Cleanup { operation, cleanup }) =
                (error as &dyn Any).downcast_ref::<Error>()
        {
            NAMESPACE.with(|name| eprintln!("structured cleanup failure; namespace {}; operation {operation:?}; cleanup {cleanup:?}", name.borrow()));
            std::process::exit(97);
        }
        self
    }
    fn must(self) -> T {
        self.guard_cleanup().unwrap()
    }
}

#[test]
fn native_reported_rollback_errors_stop_before_next_test() {
    for mode in ["unlink-report", "absence-report"] {
        let name = super::namespace();
        let path = local_app_data().unwrap().join(&name);
        assert!(!path.try_exists().unwrap());
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["native_cleanup_failure_", "--test-threads=1", "--nocapture"])
            .env("ATW_FS_TEST_ROLLBACK_MODE", mode)
            .env("ATW_FS_TEST_ROLLBACK_NAMESPACE", &name)
            .output()
            .unwrap();
        // A real leftover is not an expected fault: stop without further tests.
        if path.try_exists().unwrap_or(true) {
            eprintln!(
                "real fixture absence failure after rollback-control child; namespace {name}"
            );
            std::process::exit(97);
        }
        assert_eq!(
            output.status.code(),
            Some(97),
            "cleanup guard must terminate the child campaign"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains(MARKER));
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        assert!(diagnostic.contains("structured cleanup failure"));
        assert!(diagnostic.contains(&name));
        assert!(diagnostic.contains("injected post-create verification failure"));
        assert!(diagnostic.contains(if mode == "unlink-report" {
            "injected unlink-result failure"
        } else {
            "new storage object absence not verified"
        }));
    }
}

#[test]
fn native_cleanup_failure_0_constructor() {
    let Ok(mode) = std::env::var("ATW_FS_TEST_ROLLBACK_MODE") else {
        return;
    };
    let name = std::env::var("ATW_FS_TEST_ROLLBACK_NAMESPACE").unwrap();
    component(&name).unwrap();
    assert!(name.starts_with("age-tpm-wsl-fs-"));
    namespace(&name);
    FAULT.with(|fault| {
        fault.set(match mode.as_str() {
            "unlink-report" => Fault::UnlinkReport,
            "absence-report" => Fault::AbsenceReport,
            _ => panic!("unknown controlled rollback mode"),
        })
    });
    // This must traverse the PUBLIC constructor and return the structured error
    // before test-side result handling decides whether the campaign can proceed.
    let _root = Root::open(&[&name], RootMode::CreateNew).must();
    panic!("controlled constructor unexpectedly succeeded");
}

#[test]
fn native_cleanup_failure_1_subsequent_marker() {
    if std::env::var_os("ATW_FS_TEST_ROLLBACK_MODE").is_some() {
        println!("{MARKER}");
    }
}
