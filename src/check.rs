//! Disposable hardware validation; deliberately separate from the plugin CLI.
use age_plugin_tpm_wsl::{
    Identity, LABEL, PublicKey, Scheme,
    client::{Helper, HelperFailure},
    invalid, keys, schemes,
    wire::{DELETE, Frame, INSPECT, RECOVER},
};
use std::{io, time::Instant};
use zeroize::Zeroizing;

fn identity_call(helper: &Helper, operation: u8, identity: &Identity) -> io::Result<Frame> {
    helper.call(Frame {
        operation,
        status: 0,
        payload: Zeroizing::new(identity.bytes()),
    })
}
fn unwrap(helper: &Helper, identity: &Identity, body: &[u8]) -> io::Result<Frame> {
    helper.call(Frame::unwrap(identity, body))
}
fn require_failure(result: io::Result<Frame>, check: &str) -> io::Result<u32> {
    match result {
        Ok(_) => Err(io::Error::other(format!("checker accepted {check}"))),
        Err(error) => match error
            .get_ref()
            .and_then(|e| e.downcast_ref::<HelperFailure>())
        {
            Some(HelperFailure(status)) if *status != 0xA0010002 => Ok(*status),
            _ => Err(error),
        },
    }
}
fn cleanup(
    identities: &[Identity],
    mut call: impl FnMut(u8, &Identity) -> io::Result<Frame>,
) -> io::Result<()> {
    for (index, identity) in identities.iter().enumerate() {
        let result = (|| {
            call(DELETE, identity)?;
            let status = require_failure(call(INSPECT, identity), "independent missing-key check")?;
            if status != 0x80090016 {
                return Err(invalid("unexpected absence status"));
            }
            Ok(())
        })();
        if let Err(error) = result {
            // Cleanup uncertainty suspends authority to delete any remaining keys.
            for remaining in &identities[index + 1..] {
                eprintln!("checker cleanup not attempted for {}", remaining.name);
            }
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "checker cleanup failed for {}: {error}; stop and inspect the reported disposable keys",
                    identity.name
                ),
            ));
        }
    }
    Ok(())
}
fn run(scheme: Scheme) -> io::Result<serde_json::Value> {
    let helper = Helper::configured()?;
    let mut identities = vec![];
    let result = (|| {
        let start = Instant::now();
        identities.push(keys::create(&helper, scheme)?);
        let create_ms = start.elapsed().as_millis();
        identities.push(keys::create(&helper, scheme)?);
        let identity = &identities[0];
        let recovered = helper.call(Frame {
            operation: RECOVER,
            status: 0,
            payload: Zeroizing::new(identity.name.as_bytes().to_vec()),
        })?;
        if Identity::parse(&recovered.payload)?.bytes() != identity.bytes() {
            return Err(invalid("recovered identity mismatch"));
        }
        let inspected = identity_call(&helper, INSPECT, identity)?;
        let inspection: serde_json::Value = serde_json::from_slice(&inspected.payload)
            .map_err(|_| invalid("invalid inspection JSON"))?;
        let plain = Zeroizing::new([0x5au8; 16]);
        let cipher = schemes::wrap(&identity.recipient, plain.as_slice())?;
        let mut latency = vec![];
        for _ in 0..6 {
            let start = Instant::now();
            let response = unwrap(&helper, identity, &cipher)?;
            if response.payload.as_slice() != *plain {
                return Err(invalid("checker value mismatch"));
            }
            latency.push(start.elapsed().as_millis());
        }
        let mut negative = vec![];
        let mut rejected = |result, name: &str, expected: Option<u32>| -> io::Result<()> {
            let status = require_failure(result, name)?;
            if expected.is_some_and(|expected| expected != status) {
                return Err(io::Error::other(format!(
                    "unexpected status for {name}: 0x{status:08X}"
                )));
            }
            negative.push(serde_json::json!({"check": name, "result": "pass", "status": format!("0x{status:08X}")}));
            Ok(())
        };
        rejected(
            helper.call(keys::create_request(&identity.name, scheme)),
            "existing key overwrite",
            Some(0x8009000F),
        )?;
        identity_call(&helper, INSPECT, identity)?;
        rejected(unwrap(&helper, &identities[1], &cipher), "wrong key", None)?;
        let mut tampered = cipher.clone();
        *tampered.last_mut().unwrap() ^= 1;
        rejected(
            unwrap(&helper, identity, &tampered),
            "altered ciphertext/tag",
            None,
        )?;
        rejected(
            unwrap(&helper, identity, &cipher[..cipher.len() - 1]),
            "short ciphertext",
            Some(0xA0010001),
        )?;
        match &identity.recipient.key {
            PublicKey::Rsa(key) => {
                let wrong_label = key.encrypt_oaep(plain.as_slice(), b"wrong-label")?;
                rejected(
                    unwrap(&helper, identity, &wrong_label),
                    "wrong OAEP label",
                    None,
                )?;
                let wrong_length = key.encrypt_oaep(&[0u8; 17], LABEL.as_bytes())?;
                rejected(
                    unwrap(&helper, identity, &wrong_length),
                    "wrong plaintext length",
                    Some(0xA0010001),
                )?;
            }
            PublicKey::P256(_) => {
                for (name, prefix) in [
                    ("zero peer", 0),
                    ("off-curve peer", 4),
                    ("compressed peer", 2),
                ] {
                    let mut invalid_peer = cipher.clone();
                    invalid_peer[..65].fill(0);
                    invalid_peer[0] = prefix;
                    rejected(
                        unwrap(&helper, identity, &invalid_peer),
                        name,
                        Some(0xA0010001),
                    )?;
                    let control = unwrap(&helper, identity, &cipher)?;
                    if control.payload.as_slice() != *plain {
                        return Err(invalid("post-rejection control failed"));
                    }
                }
            }
        }
        let mismatched = Identity {
            recipient: identities[1].recipient.clone(),
            name: identity.name.clone(),
        };
        rejected(
            identity_call(&helper, INSPECT, &mismatched),
            "fingerprint mismatch",
            Some(0xA0010001),
        )?;
        rejected(
            identity_call(&helper, DELETE, &mismatched),
            "deletion with wrong fingerprint",
            Some(0xA0010001),
        )?;
        identity_call(&helper, INSPECT, identity)?;
        let missing = Identity {
            recipient: identity.recipient.clone(),
            name: keys::key_name(),
        };
        rejected(
            unwrap(&helper, &missing, &cipher),
            "missing key",
            Some(0x80090016),
        )?;
        Ok(serde_json::json!({
            "result": "pass", "scheme": scheme.name(), "inspection": inspection,
            "key_names": identities.iter().map(|identity| &identity.name).collect::<Vec<_>>(),
            "create_ms": create_ms, "whole_process_unwrap_ms": latency,
            "silent_round_trip": "pass", "identity_recovery": "pass", "negative_checks": negative
        }))
    })();
    if let Err(error) = cleanup(&identities, |operation, identity| {
        identity_call(&helper, operation, identity)
    }) {
        if let Err(error) = &result {
            eprintln!("check failed before cleanup: {error}");
        }
        return Err(error);
    }
    let mut report = result?;
    report["cleanup"] =
        serde_json::json!({"result":"pass", "keys_deleted_and_absence_verified":identities.len()});
    Ok(report)
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = (|| {
        let scheme = match args.as_slice() {
            [flag, name] if flag == "--algorithm" => Scheme::parse(name)?,
            _ => {
                return Err(invalid(
                    "use age-tpm-wsl-check --algorithm rsa2048|p256-hpke",
                ));
            }
        };
        let report = run(scheme)?;
        println!("{}", serde_json::to_string_pretty(&report)?);
        Ok::<_, io::Error>(())
    })();
    if let Err(error) = result {
        eprintln!("age-tpm-wsl-check: {error}");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn identities() -> Vec<Identity> {
        let mut public = vec![0xff; 257];
        public[0] = 1;
        (0..3)
            .map(|index| Identity {
                recipient: age_plugin_tpm_wsl::Recipient::parse(&public).unwrap(),
                name: format!("age-tpm-wsl-{index:032x}"),
            })
            .collect()
    }

    fn deleted() -> Frame {
        Frame {
            operation: DELETE,
            status: 0,
            payload: Zeroizing::new(vec![]),
        }
    }

    #[test]
    fn cleanup_stops_at_first_delete_or_absence_failure() {
        let identities = identities();
        for failing_index in [0, 1] {
            for failing_operation in [DELETE, INSPECT] {
                let mut calls = vec![];
                let error = cleanup(&identities, |operation, identity| {
                    calls.push((operation, identity.name.clone()));
                    if identity.name == identities[failing_index].name
                        && operation == failing_operation
                    {
                        return Err(io::Error::new(io::ErrorKind::TimedOut, "injected deadline"));
                    }
                    match operation {
                        DELETE => Ok(deleted()),
                        INSPECT => Err(io::Error::other(HelperFailure(0x80090016))),
                        _ => panic!("unexpected cleanup operation"),
                    }
                })
                .unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::TimedOut);
                assert!(error.to_string().contains(&identities[failing_index].name));
                assert!(error.to_string().contains("injected deadline"));
                let mut expected = vec![];
                for identity in &identities[..failing_index] {
                    expected.extend([
                        (DELETE, identity.name.clone()),
                        (INSPECT, identity.name.clone()),
                    ]);
                }
                expected.push((DELETE, identities[failing_index].name.clone()));
                if failing_operation == INSPECT {
                    expected.push((INSPECT, identities[failing_index].name.clone()));
                }
                assert_eq!(calls, expected);
            }
        }
    }

    #[test]
    fn cleanup_requires_exact_absence_before_advancing() {
        let identities = identities();
        for status in [None, Some(0xA0010002), Some(0x80090027)] {
            let mut calls = vec![];
            assert!(
                cleanup(&identities, |operation, identity| {
                    calls.push((operation, identity.name.clone()));
                    if operation == DELETE {
                        return Ok(deleted());
                    }
                    match status {
                        Some(status) => Err(io::Error::other(HelperFailure(status))),
                        None => Ok(Frame {
                            operation: INSPECT,
                            status: 0,
                            payload: Zeroizing::new(vec![]),
                        }),
                    }
                })
                .is_err()
            );
            assert_eq!(
                calls,
                [
                    (DELETE, identities[0].name.clone()),
                    (INSPECT, identities[0].name.clone())
                ]
            );
        }
        let mut calls = vec![];
        cleanup(&identities, |operation, identity| {
            calls.push((operation, identity.name.clone()));
            match operation {
                DELETE => Ok(deleted()),
                INSPECT => Err(io::Error::other(HelperFailure(0x80090016))),
                _ => panic!("unexpected cleanup operation"),
            }
        })
        .unwrap();
        assert_eq!(
            calls,
            identities
                .iter()
                .flat_map(|identity| [
                    (DELETE, identity.name.clone()),
                    (INSPECT, identity.name.clone())
                ])
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn rejection_requires_numeric_helper_error_and_preserves_cleanup_failure() {
        assert_eq!(
            require_failure(Err(io::Error::other(HelperFailure(0x80090027))), "tamper").unwrap(),
            0x80090027
        );
        for kind in [
            io::ErrorKind::TimedOut,
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidData,
            io::ErrorKind::BrokenPipe,
        ] {
            assert!(
                require_failure(Err(io::Error::new(kind, "transport failed")), "tamper").is_err()
            );
        }
        assert!(
            require_failure(Err(io::Error::other(HelperFailure(0xA0010002))), "tamper").is_err()
        );
        assert!(
            require_failure(
                Ok(Frame {
                    operation: 3,
                    status: 0,
                    payload: Zeroizing::new(vec![0; 16])
                }),
                "tamper"
            )
            .is_err()
        );
    }
}
