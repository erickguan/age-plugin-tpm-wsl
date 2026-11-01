use age_plugin_tpm_wsl::wire::{Frame, PostQuantumRequest};
use age_tpm_wsl_post_quantum::Identity;
use zeroize::Zeroizing;

const NAME: &str = "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef";

fn fixture() -> (Identity, Vec<u8>, Vec<u8>) {
    let value: serde_json::Value = serde_json::from_str(include_str!(
        "../notes/aws-lc-hybrid-evaluation/go-fixture.json"
    ))
    .unwrap();
    let bytes = |field: &str| hex::decode(value[field].as_str().unwrap()).unwrap();
    (
        Identity::new(&bytes("public_key"), NAME).unwrap(),
        bytes("enc"),
        bytes("body"),
    )
}

#[test]
fn literal_post_quantum_layouts_roundtrip_without_changing_legacy_request_parsing() {
    let (identity, enc, body) = fixture();
    let frames = [
        Frame::post_quantum_create(NAME).unwrap(),
        Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap(),
        Frame::post_quantum_recover(NAME).unwrap(),
    ];
    for (frame, operation, length) in [
        (&frames[0], 8, 49),
        (&frames[1], 9, 2487),
        (&frames[2], 10, 47),
    ] {
        let mut bytes = Vec::new();
        frame.write(&mut bytes).unwrap();
        assert_eq!(&bytes[..5], &[b'A', b'T', b'W', b'1', operation]);
        assert_eq!(&bytes[5..9], &[0, 0, 0, 0]);
        assert_eq!(&bytes[9..13], &(length as u32).to_le_bytes());
        assert_eq!(frame.payload.len(), length);
        let parsed = Frame::read(bytes.as_slice()).unwrap();
        assert!(parsed.unwrap_parts().is_err());
        match parsed.post_quantum_request().unwrap() {
            PostQuantumRequest::Create { name } | PostQuantumRequest::Recover { name } => {
                assert_eq!(name, NAME)
            }
            PostQuantumRequest::Unwrap {
                identity: actual,
                enc: actual_enc,
                body: actual_body,
            } => {
                assert!(actual.bytes() == identity.bytes());
                assert!(actual_enc.as_slice() == enc && actual_body.as_slice() == body);
            }
        }
    }
    assert_eq!(&frames[0].payload[..2], &[0, 2]);
    assert_eq!(&frames[1].payload[..2], &[5, 20]); // literal big-endian 1300
    assert_eq!(&frames[1].payload[2..5], &[3, 0, 2]);
    for operation in 1..=7 {
        assert!(
            Frame {
                operation,
                status: 0,
                payload: Zeroizing::new(Vec::new())
            }
            .post_quantum_request()
            .is_err()
        );
    }
    for operation in [0, 11, 255] {
        let frame = Frame {
            operation,
            status: 0,
            payload: Zeroizing::new(Vec::new()),
        };
        assert!(frame.write(Vec::new()).is_err());
    }
}

#[test]
fn post_quantum_requests_reject_every_truncation_trailing_data_and_wrong_operation() {
    let (identity, enc, body) = fixture();
    for frame in [
        Frame::post_quantum_create(NAME).unwrap(),
        Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap(),
        Frame::post_quantum_recover(NAME).unwrap(),
    ] {
        for length in 0..frame.payload.len() {
            let short = Frame {
                operation: frame.operation,
                status: 0,
                payload: Zeroizing::new(frame.payload[..length].to_vec()),
            };
            assert!(short.post_quantum_request().is_err());
        }
        let mut trailing = Frame {
            operation: frame.operation,
            status: 0,
            payload: Zeroizing::new(frame.payload.to_vec()),
        };
        trailing.payload.push(0);
        assert!(trailing.post_quantum_request().is_err());
        for operation in 1..=10 {
            if operation != frame.operation {
                assert!(
                    Frame {
                        operation,
                        status: 0,
                        payload: Zeroizing::new(frame.payload.to_vec())
                    }
                    .post_quantum_request()
                    .is_err()
                );
            }
        }
        assert!(
            Frame {
                operation: frame.operation,
                status: 1,
                payload: frame.payload
            }
            .post_quantum_request()
            .is_err()
        );
    }
}

#[test]
fn wrong_suites_names_identities_and_noncanonical_points_are_rejected() {
    for name in [
        "age-tpm-wsl-0123456789abcdef0123456789abcdef",
        "age-tpm-wsl-pq-0123456789ABCDEF0123456789abcdef",
        "../age-tpm-wsl-pq-0123456789abcdef0123456789abcdef",
    ] {
        assert!(
            Frame::post_quantum_create(name).is_err() && Frame::post_quantum_recover(name).is_err()
        );
    }
    let (identity, enc, body) = fixture();
    for (offset, value) in [(0, 1), (1, 1), (2, 0xff), (48, b'G')] {
        let mut frame = Frame::post_quantum_create(NAME).unwrap();
        frame.payload[offset] = value;
        assert!(frame.post_quantum_request().is_err());
    }
    for offset in [0, 1, 2, 3, 4, 1254, 1301] {
        let mut frame = Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap();
        frame.payload[offset] ^= 0xff;
        assert!(frame.post_quantum_request().is_err());
    }
    let mut noncanonical = Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap();
    noncanonical.payload[5..8].fill(0xff); // two ML-KEM coefficients outside the field
    assert!(noncanonical.post_quantum_request().is_err());
    let mut bad_point = enc;
    bad_point[1088..].fill(0);
    bad_point[1088] = 4;
    assert!(Frame::post_quantum_unwrap(&identity, &bad_point, &body).is_err());
    let mut frame = Frame::post_quantum_unwrap(&identity, &fixture().1, &body).unwrap();
    frame.payload[2 + 1300 + 1088..2 + 1300 + 1153].copy_from_slice(&bad_point[1088..]);
    assert!(frame.post_quantum_request().is_err());
}
