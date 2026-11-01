//! No filesystem, PCP or TPM access: the location records acquisition attempts
//! and returns a controlled error before constructing a Store.
use super::*;
use crate::post_quantum::lifecycle::Failure;
use age_plugin_tpm_wsl::wire::{CREATE_POST_QUANTUM, RECOVER_POST_QUANTUM, UNWRAP_POST_QUANTUM};
use std::cell::RefCell;

#[derive(Default)]
struct RecordingLocation {
    opens: RefCell<Vec<&'static str>>,
    cleanup_failed: bool,
}
impl RecordingLocation {
    fn stop(&self, method: &'static str) -> Outcome<Store> {
        self.opens.borrow_mut().push(method);
        Err(Failure {
            message: "controlled store acquisition stop".into(),
            cleanup_failed: self.cleanup_failed,
            kind: crate::post_quantum::lifecycle::FailureKind::Operational,
        })
    }
}
impl StoreLocation for RecordingLocation {
    fn for_creation(&self) -> Outcome<Store> {
        self.stop("creation")
    }
    fn existing(&self) -> Outcome<Store> {
        self.stop("existing")
    }
}

const NAME: &str = "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef";
fn frame(operation: u8, status: u32, payload: &[u8]) -> Frame {
    Frame {
        operation,
        status,
        payload: Zeroizing::new(payload.to_vec()),
    }
}
fn fixture() -> (Identity, Vec<u8>, Vec<u8>) {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../notes/aws-lc-hybrid-evaluation/go-fixture.json"
    ))
    .unwrap();
    let bytes = |field: &str| -> Vec<u8> {
        value[field]
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    };
    (
        Identity::new(&bytes("public_key"), NAME).unwrap(),
        bytes("enc"),
        bytes("body"),
    )
}

#[test]
fn malformed_requests_never_acquire_storage() {
    for request in [
        frame(CREATE_POST_QUANTUM, 1, &[]),
        frame(CREATE_POST_QUANTUM, 0, b"\0\x01invalid-name"),
        frame(RECOVER_POST_QUANTUM, 0, b"../custody"),
        frame(UNWRAP_POST_QUANTUM, 0, b"\x05\x14short-identity"),
        frame(INSPECT, 0, &[3, 0, 2]),
        frame(DELETE, 0, &[1, 0]),
        frame(255, 0, &[]),
    ] {
        let location = RecordingLocation::default();
        assert!(at(&request, &location).is_err());
        assert!(location.opens.borrow().is_empty());
    }
}

#[test]
fn only_explicit_create_can_acquire_creation_storage() {
    let (identity, enc, body) = fixture();
    let create = Frame::post_quantum_create(NAME).unwrap();
    let location = RecordingLocation::default();
    assert!(at(&create, &location).is_err());
    assert_eq!(*location.opens.borrow(), ["creation"]);

    for request in [
        Frame::post_quantum_recover(NAME).unwrap(),
        Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap(),
        frame(INSPECT, 0, &identity.bytes()),
        frame(DELETE, 0, &identity.bytes()),
    ] {
        let location = RecordingLocation::default();
        let error = at(&request, &location).unwrap_err();
        assert_eq!(error.message, "controlled store acquisition stop");
        assert!(!error.cleanup_failed);
        assert_eq!(*location.opens.borrow(), ["existing"]);
    }
}

#[test]
fn acquisition_failure_preserves_fatal_cleanup_state() {
    let request = Frame::post_quantum_recover(NAME).unwrap();
    let location = RecordingLocation {
        cleanup_failed: true,
        ..Default::default()
    };
    let error = at(&request, &location).unwrap_err();
    assert_eq!(error.message, "controlled store acquisition stop");
    assert!(error.cleanup_failed);
    assert_eq!(*location.opens.borrow(), ["existing"]);
}
