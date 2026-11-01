#![cfg(unix)]
use age_plugin_tpm_wsl::{
    client::Helper,
    wire::{Frame, UNWRAP, UNWRAP_POST_QUANTUM, UNWRAP_SCHEME},
};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    time::{Duration, Instant},
};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn call(script: &str, timeout: Duration) -> std::io::Result<Frame> {
    call_operation(script, timeout, UNWRAP)
}
fn call_operation(script: &str, timeout: Duration, operation: u8) -> std::io::Result<Frame> {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("helper");
    fs::write(
        &path,
        format!(
            "#!/usr/bin/env python3\nimport sys, struct, time\nsys.stdin.buffer.read()\n{script}\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    Helper::new(&path, timeout).unwrap().call(Frame {
        operation,
        status: 0,
        payload: Zeroizing::new(vec![0; 256]),
    })
}

#[test]
fn rejects_helper_failures_and_invalid_output() {
    let cases = [
        "sys.exit(1)",
        "sys.stdout.buffer.write(b'garbage')",
        "sys.stdout.buffer.write(b'ATW1' + bytes([3]) + struct.pack('<II', 0, 16) + bytes(15))",
        "sys.stdout.buffer.write(b'ATW1' + bytes([3]) + struct.pack('<II', 0, 17) + bytes(17))",
        "sys.stdout.buffer.write(b'ATW1' + bytes([3]) + struct.pack('<II', 0, 15) + bytes(15))",
        "sys.stdout.buffer.write(b'ATW1' + bytes([3]) + struct.pack('<II', 0x80090016, 0))",
        "sys.stdout.buffer.write(b'ATW1' + bytes([2]) + struct.pack('<II', 0, 16) + bytes(16))",
        "sys.stdout.buffer.write(b'ATW1' + bytes([3]) + struct.pack('<II', 0, 16) + bytes(17))",
        "sys.stdout.buffer.write(bytes(100000))",
    ];
    for script in cases {
        assert!(call(script, Duration::from_secs(2)).is_err(), "{script}");
    }
    let valid =
        "sys.stdout.buffer.write(b'ATW1' + bytes([3]) + struct.pack('<II', 0, 16) + bytes(16))";
    assert_eq!(
        call(valid, Duration::from_secs(2)).unwrap().payload.len(),
        16
    );
}

#[test]
fn kills_and_reaps_helper_at_deadline() {
    let start = Instant::now();
    let error = match call("time.sleep(30)", Duration::from_millis(150)) {
        Err(e) => e,
        Ok(_) => panic!("accepted stalled helper"),
    };
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn scheme_unwrap_checks_response_length_operation_and_old_helper_rejection() {
    for request_operation in [UNWRAP_SCHEME, UNWRAP_POST_QUANTUM] {
        for (status, length, operation) in [
            (0, 15, request_operation),
            (0, 17, request_operation),
            (0, 16, 3),
            (0xA0010001u32, 0, request_operation),
        ] {
            let script = format!(
                "sys.stdout.buffer.write(b'ATW1' + bytes([{operation}]) + struct.pack('<II', {status}, {length}) + bytes({length}))"
            );
            assert!(call_operation(&script, Duration::from_secs(2), request_operation).is_err());
        }
        let valid = format!(
            "sys.stdout.buffer.write(b'ATW1' + bytes([{request_operation}]) + struct.pack('<II', 0, 16) + bytes(16))"
        );
        assert_eq!(
            call_operation(&valid, Duration::from_secs(2), request_operation)
                .unwrap()
                .payload
                .len(),
            16
        );
        // Older helpers reject new operations or exit with no protocol output.
        assert!(call_operation("sys.exit(1)", Duration::from_secs(2), request_operation).is_err());
    }
}
