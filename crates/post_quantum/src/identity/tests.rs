use super::*;

pub(super) const NAME: &str = "age-tpm-wsl-pq-00000000000000000000000000000000";
pub(super) fn public() -> Vec<u8> {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../notes/aws-lc-hybrid-evaluation/kat-components.json"
    ))
    .unwrap();
    assert_eq!(fixture["public_fixture_only"], true);
    hex::decode(fixture["public_key"].as_str().unwrap()).unwrap()
}

#[test]
fn canonical_identity_and_independent_descriptor_known_answers() {
    let identity = Identity::new(&public(), NAME).unwrap();
    let encoded = identity.bytes();
    assert_eq!(encoded.len(), 1300);
    assert_eq!(&encoded[..3], &[3, 0, 2]);
    assert_eq!(encoded[1252], 47);
    assert_eq!(&encoded[1253..], NAME.as_bytes());
    assert!(Identity::parse(&encoded).unwrap() == identity);
    // Computed separately with Python hashlib over the published public fixture
    // and literal contract domains/encodings, without calling these Rust methods.
    assert_eq!(
        hex::encode(identity.commitment()),
        "adf2ac8f02ef17b9af7f898e9e952e30db0d1ce71fa290b96a4a49008bc7d146"
    );
    assert_eq!(
        hex::encode(identity.binding()),
        "f0b039796d9468c02aeba58aeb716af41fb27c4135c605d3ce3cdd0db4f62df0"
    );
    let other =
        Identity::new(&public(), "age-tpm-wsl-pq-11111111111111111111111111111111").unwrap();
    assert_eq!(identity.commitment(), other.commitment());
    assert_ne!(identity.binding(), other.binding());
}

#[test]
fn names_are_exclusive_to_the_new_scheme_and_have_no_path_syntax() {
    let public = public();
    for name in [
        "age-tpm-wsl-00000000000000000000000000000000",
        "age-tpm-wsl-pq-0000000000000000000000000000000A",
        "age-tpm-wsl-pq-0000000000000000000000000000000/",
        "age-tpm-wsl-pq-0000000000000000000000000000000:",
    ] {
        assert!(Identity::new(&public, name).is_err());
    }
}

#[test]
fn malformed_lengths_versions_suites_and_components_fail_before_binding() {
    let identity = Identity::new(&public(), NAME).unwrap();
    let encoded = identity.bytes();
    for end in 0..encoded.len() {
        assert!(Identity::parse(&encoded[..end]).is_err());
    }
    let mut trailing = encoded.to_vec();
    trailing.push(0);
    assert!(Identity::parse(&trailing).is_err());
    for (index, value) in [
        (0, 2),
        (1, 1),
        (2, 1),
        (1252, 44),
        (1253, 0xff),
        (3 + 1184, 2),
    ] {
        let mut altered = encoded;
        altered[index] = value;
        assert!(Identity::parse(&altered).is_err());
    }
    // First packed ML-KEM coefficient becomes q=3329, violating canonical range.
    let mut coefficient = encoded;
    coefficient[3] = 1;
    coefficient[4] = (coefficient[4] & 0xf0) | 0x0d;
    assert!(Identity::parse(&coefficient).is_err());
    let mut point = encoded;
    point[3 + 1184..1252].fill(0);
    point[3 + 1184] = 4;
    assert!(Identity::parse(&point).is_err());
}
