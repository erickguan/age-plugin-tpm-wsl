use super::*;
use age_plugin_tpm_wsl::wire::{CREATE, CREATE_POST_QUANTUM, RECOVER, UNWRAP};
use zeroize::Zeroizing;

const SUFFIX: &str = "0123456789abcdef0123456789abcdef";
fn input(mode: &str, expected: Option<&Identity>) -> Vec<String> {
    let mut args = [
        "--acknowledge",
        ACK,
        "--namespace",
        &format!("{ROOT_PREFIX}{SUFFIX}"),
        mode,
    ]
    .map(String::from)
    .to_vec();
    if let Some(identity) = expected {
        args.push("--expected-identity".into());
        args.push(
            identity
                .bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
        );
    }
    args
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
        Identity::new(&bytes("public_key"), &format!("age-tpm-wsl-pq-{SUFFIX}")).unwrap(),
        bytes("enc"),
        bytes("body"),
    )
}
fn identity_frame(operation: u8, identity: &Identity) -> Frame {
    Frame {
        operation,
        status: 0,
        payload: Zeroizing::new(identity.bytes().to_vec()),
    }
}

#[test]
fn acknowledgment_and_modes_are_explicit() {
    assert!(Arguments::parse(&[]).is_err());
    for index in [0, 1, 2, 4] {
        let mut args = input("--serve", None);
        args[index] = "unexpected".into();
        assert!(Arguments::parse(&args).is_err());
    }
    let mut args = input("--serve", None);
    args.push("--extra".into());
    assert!(Arguments::parse(&args).is_err());
}

#[test]
fn namespace_never_accepts_production_paths_or_case_variants() {
    for value in [
        "age-plugin-tpm-wsl",
        "custody/v1",
        "../x",
        "",
        "age-tpm-wsl-post-quantum-client-ABCDEF0123456789abcdef0123456789",
        "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef",
    ] {
        let mut args = input("--serve", None);
        args[3] = value.into();
        assert!(Arguments::parse(&args).is_err());
    }
    let args = Arguments::parse(&input("--serve", None)).unwrap();
    assert_eq!(args.namespace.directory(), format!("{ROOT_PREFIX}{SUFFIX}"));
    assert_eq!(
        args.namespace.key_name(),
        format!("age-tpm-wsl-pq-{SUFFIX}")
    );
}

#[test]
fn preparation_and_removal_require_their_own_authority_states() {
    let (identity, _, _) = fixture();
    assert!(Arguments::parse(&input("--prepare-root", None)).is_ok());
    assert!(Arguments::parse(&input("--prepare-root", Some(&identity))).is_err());
    assert!(Arguments::parse(&input("--remove-root", None)).is_err());
    assert!(Arguments::parse(&input("--remove-root", Some(&identity))).is_ok());
    let args = Arguments::parse(&input("--absence", None)).unwrap();
    assert!(
        args.authorize(&Frame::post_quantum_create(identity.name()).unwrap())
            .is_err()
    );
}

#[test]
fn retained_identity_is_canonical_and_bound_to_namespace() {
    let (identity, _, _) = fixture();
    let other = Identity::new(
        identity.public(),
        "age-tpm-wsl-pq-00000000000000000000000000000000",
    )
    .unwrap();
    assert!(Arguments::parse(&input("--serve", Some(&other))).is_err());
    let mut truncated = input("--serve", Some(&identity));
    truncated.last_mut().unwrap().pop();
    assert!(Arguments::parse(&truncated).is_err());
    let mut uppercase = input("--serve", Some(&identity));
    let last = uppercase.last_mut().unwrap();
    *last = last.to_uppercase();
    assert!(Arguments::parse(&uppercase).is_err());
}

#[test]
fn unbound_fixture_can_only_create_its_dedicated_key() {
    let (identity, enc, body) = fixture();
    let args = Arguments::parse(&input("--serve", None)).unwrap();
    assert!(
        args.authorize(&Frame::post_quantum_create(identity.name()).unwrap())
            .is_ok()
    );
    assert!(
        args.authorize(
            &Frame::post_quantum_create("age-tpm-wsl-pq-00000000000000000000000000000000").unwrap()
        )
        .is_err()
    );
    for request in [
        identity_frame(INSPECT, &identity),
        identity_frame(DELETE, &identity),
        Frame::post_quantum_recover(identity.name()).unwrap(),
        Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap(),
    ] {
        assert!(args.authorize(&request).is_err());
    }
}

#[test]
fn retained_fixture_accepts_only_matching_existing_operations() {
    let (identity, enc, body) = fixture();
    let args = Arguments::parse(&input("--serve", Some(&identity))).unwrap();
    for request in [
        identity_frame(INSPECT, &identity),
        identity_frame(DELETE, &identity),
        Frame::post_quantum_recover(identity.name()).unwrap(),
        Frame::post_quantum_unwrap(&identity, &enc, &body).unwrap(),
    ] {
        assert!(args.authorize(&request).is_ok());
    }
    assert!(
        args.authorize(&Frame::post_quantum_create(identity.name()).unwrap())
            .is_err()
    );
    let mut bad_status = Frame::post_quantum_recover(identity.name()).unwrap();
    bad_status.status = 1;
    assert!(args.authorize(&bad_status).is_err());
}

#[test]
fn same_name_does_not_authorize_substituted_public_material() {
    let (identity, enc, body) = fixture();
    let args = Arguments::parse(&input("--serve", Some(&identity))).unwrap();
    let mut public = identity.public().to_vec();
    let coefficient = u16::from(public[0]) | (u16::from(public[1] & 15) << 8);
    public[0] = u8::from(coefficient == 0);
    public[1] &= 0xf0;
    let changed = Identity::new(&public, identity.name()).unwrap();
    assert!(changed != identity);
    for request in [
        identity_frame(INSPECT, &changed),
        identity_frame(DELETE, &changed),
        Frame::post_quantum_unwrap(&changed, &enc, &body).unwrap(),
    ] {
        assert!(args.authorize(&request).is_err());
    }
    assert!(args.check_identity_response(&changed.bytes()).is_err());
    assert!(args.check_identity_response(&identity.bytes()).is_ok());
}

#[test]
fn legacy_and_malformed_requests_never_gain_fixture_authority() {
    let args = Arguments::parse(&input("--serve", None)).unwrap();
    for operation in [CREATE, RECOVER, UNWRAP, CREATE_POST_QUANTUM, 255] {
        let request = Frame {
            operation,
            status: 0,
            payload: Zeroizing::new(Vec::new()),
        };
        assert!(args.authorize(&request).is_err());
    }
}
