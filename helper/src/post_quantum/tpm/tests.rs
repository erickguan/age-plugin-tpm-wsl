use super::*;
use std::{cell::RefCell, collections::VecDeque, rc::Rc};

struct Script {
    responses: VecDeque<Result<Bytes>>,
    calls: Rc<RefCell<Vec<u32>>>,
    close_failure: bool,
}
impl Transport for Script {
    fn submit(&mut self, command: &[u8]) -> Result<Bytes> {
        self.calls
            .borrow_mut()
            .push(u32::from_be_bytes(command[6..10].try_into().unwrap()));
        self.responses
            .pop_front()
            .expect("unexpected extra TPM command")
    }
    fn close(&mut self) -> Result<()> {
        self.calls.borrow_mut().push(0);
        if self.close_failure {
            Err("context close failure".into())
        } else {
            Ok(())
        }
    }
}
fn context(responses: Vec<Result<Bytes>>) -> (Context<Script>, Rc<RefCell<Vec<u32>>>) {
    let calls = Rc::new(RefCell::new(Vec::new()));
    (
        Context::new(Script {
            responses: responses.into(),
            calls: calls.clone(),
            close_failure: false,
        }),
        calls,
    )
}
fn success() -> Result<Bytes> {
    frame(0x8001, 0, &[])
}
fn absent() -> Result<Bytes> {
    frame(0x8001, 0x18b, &[])
}
fn session(parameters: &[u8], handle: bool) -> Bytes {
    let mut out = Vec::new();
    if handle {
        dword(&mut out, 0x8000_0000);
    }
    dword(&mut out, parameters.len() as u32);
    out.extend(parameters);
    out.extend([0, 0, 1, 0, 0]);
    frame(0x8002, 0, &out).unwrap()
}
#[test]
fn rejects_all_short_headers_malformed_sizes_and_error_sessions() {
    let bytes = frame(0x8001, 0, &[]).unwrap();
    for n in 0..bytes.len() {
        assert!(header(&bytes[..n]).is_err());
    }
    let mut extra = bytes.to_vec();
    extra.push(0);
    assert!(header(&extra).is_err());
    assert!(header(&frame(0x8002, 0x18b, &[]).unwrap()).is_err());
    assert!(header(&frame(0x8001, 0x18b, &[0]).unwrap()).is_err());
    assert!(frame(0x8001, 0, &[0; 8183]).is_err());
    assert!(sized(&mut Vec::new(), &[0; 65536]).is_err());
    assert!(authorization(&mut Vec::new(), 0, &[0; 33]).is_err());
}
#[test]
fn every_cleanup_failure_stops_commands_but_closes_once_and_blocks_success() {
    for failed in 0..3 {
        let mut responses = vec![success(), success(), absent()];
        responses[failed] = Err("injected transport failure".into());
        let (mut context, calls) = context(responses);
        context.owned = vec![0x8000_0000, 0x8000_0001];
        let failure = context
            .complete(Ok(Zeroizing::new(vec![0x55; 16])))
            .unwrap_err();
        assert!(failure.cleanup_failed);
        assert_eq!(
            *calls.borrow(),
            [&[READ_PUBLIC, FLUSH, READ_PUBLIC][..=failed], &[0]].concat()
        );
        let failure =
            failure.rollback(|| panic!("must not delete persistent objects after cleanup failure"));
        assert!(failure.cleanup_failed);
    }
}
#[test]
fn absence_requires_exact_missing_handle_and_successful_transport() {
    for code in [0, 0x8b, 0x18b, 0x28b, 0x1cb, 0x910] {
        let (mut context, calls) = context(vec![success(), success(), frame(0x8001, code, &[])]);
        context.owned.push(0x8000_0000);
        let expected = matches!(code, 0x8b | 0x18b);
        assert_eq!(context.complete(Ok(())).is_ok(), expected);
        assert_eq!(*calls.borrow(), [READ_PUBLIC, FLUSH, READ_PUBLIC, 0]);
    }
}
#[test]
fn flush_is_not_retried_after_success_even_when_acknowledgment_is_invalid() {
    let (mut context, calls) = context(vec![success(), frame(0x8001, 0, &[0])]);
    context.owned.push(0x8000_0000);
    assert!(context.complete(Ok(())).unwrap_err().cleanup_failed);
    assert_eq!(*calls.borrow(), [READ_PUBLIC, FLUSH, 0]);
}
#[test]
fn close_failure_preserves_operation_failure_and_forbids_rollback() {
    let (mut context, calls) = context(Vec::new());
    context.transport.close_failure = true;
    let failure = context
        .complete::<()>(Err("original operation".into()))
        .unwrap_err();
    assert!(
        failure.cleanup_failed
            && failure.message.contains("original operation")
            && failure.message.contains("context close")
    );
    assert_eq!(*calls.borrow(), [0]);
    assert!(
        failure
            .rollback(|| panic!("no destructive retry"))
            .cleanup_failed
    );
}
#[test]
fn registers_parent_handle_before_any_public_or_session_parse_failure() {
    for malformed in [
        frame(0x8002, 0, &0x8000_0000u32.to_be_bytes()).unwrap(),
        session(&[], true),
    ] {
        let (mut context, calls) = context(vec![Ok(malformed), success(), success(), absent()]);
        let operation = context.parent().map_err(Failure::from);
        assert!(operation.is_err());
        assert_eq!(context.owned, [0x8000_0000]);
        let failure = context.complete(operation).unwrap_err();
        assert!(!failure.cleanup_failed);
        assert_eq!(*calls.borrow(), [0x131, READ_PUBLIC, FLUSH, READ_PUBLIC, 0]);
    }
}
#[test]
fn loaded_child_is_owned_before_malformed_name_or_session_validation() {
    let mut public = CHILD_PREFIX.to_vec();
    sized(&mut public, &[0x55; 32]).unwrap();
    let (mut context, calls) =
        context(vec![Ok(session(&[], true)), success(), success(), absent()]);
    let operation = context
        .load(0x8000_0001, &[0x55; 64], &public)
        .map_err(Failure::from);
    assert!(operation.is_err());
    assert_eq!(context.owned, [0x8000_0000]);
    assert!(!context.complete(operation).unwrap_err().cleanup_failed);
    assert_eq!(*calls.borrow(), [0x157, READ_PUBLIC, FLUSH, READ_PUBLIC, 0]);
}
#[test]
fn unseal_requires_exact_96_bytes_and_canonical_session_before_returning_payload() {
    let mut p = Vec::new();
    sized(&mut p, &[0x55; 96]).unwrap();
    let valid = session(&p, false);
    let (mut context, calls) = context(vec![Ok(valid.clone())]);
    assert_eq!(*context.unseal(0x8000_0000, &[0; 32]).unwrap(), [0x55; 96]);
    context.complete(Ok(())).unwrap();
    assert_eq!(*calls.borrow(), [0x15e, 0]);
    for size in [95, 97] {
        let mut p = Vec::new();
        sized(&mut p, &vec![0x55; size]).unwrap();
        let (mut context, _) = self::context(vec![Ok(session(&p, false))]);
        assert!(context.unseal(0x8000_0000, &[0; 32]).is_err());
        context.complete(Ok(())).unwrap();
    }
    for attributes in [0, 2, 0x21] {
        let mut malformed = valid.to_vec();
        let n = malformed.len();
        malformed[n - 3] = attributes;
        assert!(parameters(&malformed, false).is_err());
    }
    for n in 0..valid.len() {
        assert!(parameters(&valid[..n], false).is_err());
    }
}
