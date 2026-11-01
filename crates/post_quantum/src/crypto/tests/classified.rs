//! Software components only: operational errors must never become auth receipts.
use super::*;

fn rejected(result: Result<Zeroizing<Vec<u8>>, OpenFailure>) -> OpenFailure {
    match result {
        Err(failure) => failure,
        Ok(_) => panic!("unexpected receiver success"),
    }
}

#[test]
fn agreement_failure_after_valid_control_is_operational() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    let (post_quantum, t) = components(&record);
    assert!(
        open_classified(&public, &enc, &body, &post_quantum, |peer| raw_agree(
            &t, peer
        ))
        .is_ok()
    );
    let error = rejected(open_classified(&public, &enc, &body, &post_quantum, |_| {
        Err(io::Error::other("injected NCryptSecretAgreement failure"))
    }));
    assert!(matches!(error, OpenFailure::Operational(_)));
}

#[test]
fn selected_valid_shape_component_mutations_reach_authentication_failure() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    let (post_quantum, t) = components(&record);
    for component in 0..3 {
        let mut changed_enc = enc.clone();
        let mut changed_body = body.clone();
        match component {
            0 => changed_enc[0] ^= 1,
            1 => changed_enc[1088..].copy_from_slice(&public[1184..]),
            _ => changed_body[31] ^= 1,
        }
        let error = rejected(open_classified(
            &public,
            &changed_enc,
            &changed_body,
            &post_quantum,
            |peer| raw_agree(&t, peer),
        ));
        assert!(matches!(error, OpenFailure::Authentication));
    }
}

#[test]
fn malformed_inputs_and_wrong_seed_are_not_authentication_rejections() {
    let record = fixture();
    let public = bytes(&record, "public_key");
    let enc = bytes(&record, "enc");
    let body = bytes(&record, "body");
    let (post_quantum, _) = components(&record);
    let error = rejected(open_classified(
        &public,
        &enc,
        &body[..31],
        &post_quantum,
        |_| panic!("bad input must not request agreement"),
    ));
    assert!(matches!(error, OpenFailure::Operational(_)));
    let error = rejected(open_classified(
        &public,
        &enc[..1152],
        &body,
        &post_quantum,
        |_| panic!("bad encapsulation must not request agreement"),
    ));
    assert!(matches!(error, OpenFailure::Operational(_)));
    let wrong = DecapsulationKey::from_seed(&ML_KEM_768, &[0x99; 64]).unwrap();
    let error = rejected(open_classified(&public, &enc, &body, &wrong, |_| {
        panic!("wrong seed must not request agreement")
    }));
    assert!(matches!(error, OpenFailure::Operational(_)));
}
