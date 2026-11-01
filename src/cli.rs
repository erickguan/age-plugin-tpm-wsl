//! Shared command-line entry for the single `age-plugin-tpm-wsl` executable.
//! Clients may discover the same executable through the `age-plugin-tagpq`
//! symlink. The state machine reads recipient names from their encoded HRPs.
use crate::{
    Identity, Scheme, client::Helper, invalid, keys, plugin::Handler, post_quantum, wire::Frame,
};
use age_core::primitives::{bech32_decode, bech32_encode};
use bech32::Hrp;
use std::io;
use zeroize::Zeroizing;

/// One identity file holds exactly one plugin identity, classical or post-quantum.
pub enum AnyIdentity {
    Classical(Box<Identity>),
    PostQuantum(Box<age_tpm_wsl_post_quantum::Identity>),
}
impl AnyIdentity {
    pub fn bytes(&self) -> Vec<u8> {
        match self {
            Self::Classical(identity) => identity.bytes(),
            Self::PostQuantum(identity) => identity.bytes().to_vec(),
        }
    }
}

fn read_identity(path: &str) -> io::Result<AnyIdentity> {
    let input = std::fs::read_to_string(path)?;
    let identities: Vec<_> = input
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
        .collect();
    if identities.len() != 1 {
        return Err(invalid("expected exactly one identity"));
    }
    let bytes = bech32_decode(
        identities[0],
        |_| invalid("invalid identity encoding"),
        |hrp| {
            if hrp.as_str() == "AGE-PLUGIN-TPM-WSL-" {
                Ok(())
            } else {
                Err(invalid("invalid identity namespace"))
            }
        },
        |_, bytes| Ok(bytes.collect::<Vec<_>>()),
    )?;
    if bytes.first() == Some(&3) {
        Ok(AnyIdentity::PostQuantum(Box::new(
            post_quantum::parse_identity(&bytes)?,
        )))
    } else {
        Ok(AnyIdentity::Classical(Box::new(Identity::parse(&bytes)?)))
    }
}

/// Mirror the library's identity-file shape with the fixed post-quantum recipient HRP.
fn print_post_quantum_identity(identity: &age_tpm_wsl_post_quantum::Identity) {
    println!(
        "# recipient: {}",
        bech32_encode(
            Hrp::parse_unchecked(post_quantum::RECIPIENT_HRP),
            identity.public()
        )
    );
    let encoded = bech32_encode(
        Hrp::parse_unchecked("age-plugin-tpm-wsl-"),
        &identity.bytes(),
    );
    println!("{}", encoded.to_uppercase());
}

pub fn run() -> io::Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [arg] if arg.starts_with("--age-plugin=") => {
            age_plugin::run_state_machine(arg.trim_start_matches("--age-plugin="), Handler)
        }
        [command, rest @ ..] if command == "keygen" => {
            let algorithm = match rest {
                [] => None,
                [flag, name] if flag == "--algorithm" => Some(name.as_str()),
                _ => {
                    return Err(invalid(
                        "use keygen [--algorithm rsa2048|p256-hpke|mlkem768-p256]",
                    ));
                }
            };
            let helper = Helper::configured()?;
            match algorithm {
                Some(post_quantum::ALGORITHM) => {
                    print_post_quantum_identity(&post_quantum::create(&helper)?);
                    Ok(())
                }
                Some(name) => {
                    let identity = keys::create(&helper, Scheme::parse(name)?)?;
                    age_plugin::print_new_identity(
                        "tpm-wsl",
                        &identity.bytes(),
                        &identity.recipient.bytes(),
                    );
                    Ok(())
                }
                None => {
                    let identity = keys::create(&helper, Scheme::Rsa2048)?;
                    age_plugin::print_new_identity(
                        "tpm-wsl",
                        &identity.bytes(),
                        &identity.recipient.bytes(),
                    );
                    Ok(())
                }
            }
        }
        [command, name] if command == "recover" => {
            let helper = Helper::configured()?;
            if name.starts_with("age-tpm-wsl-pq-") {
                post_quantum::valid_name(name)?;
                let response = helper.call(post_quantum::recover_request(name)?)?;
                let identity = post_quantum::parse_identity(&response.payload)?;
                if identity.name() != name {
                    return Err(invalid("helper returned unexpected key name"));
                }
                print_post_quantum_identity(&identity);
                Ok(())
            } else {
                crate::validate_name(name)?;
                let response = helper.call(Frame {
                    operation: crate::wire::RECOVER,
                    status: 0,
                    payload: Zeroizing::new(name.as_bytes().to_vec()),
                })?;
                let identity = Identity::parse(&response.payload)?;
                if identity.name != *name {
                    return Err(invalid("helper returned unexpected key name"));
                }
                age_plugin::print_new_identity(
                    "tpm-wsl",
                    &identity.bytes(),
                    &identity.recipient.bytes(),
                );
                Ok(())
            }
        }
        [command] if command == "schemes" => {
            println!(
                "rsa2048: RSA-2048 OAEP-SHA256 / MGF1-SHA256 (default)\np256-hpke: RFC 9180 base / DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / ChaCha20Poly1305\nmlkem768-p256: ML-KEM-768 + P-256 hybrid (tagged recipients, TPM custody)\nBuilt-in support only; hardware availability requires explicit validation."
            );
            Ok(())
        }
        [command, path] if command == "inspect" || command == "delete" => {
            let identity = read_identity(path)?;
            let operation = if command == "inspect" {
                crate::wire::INSPECT
            } else {
                crate::wire::DELETE
            };
            let response = Helper::configured()?.call(Frame {
                operation,
                status: 0,
                payload: Zeroizing::new(identity.bytes()),
            })?;
            if operation == crate::wire::DELETE {
                if !response.payload.is_empty() {
                    return Err(invalid("unexpected deletion response"));
                }
                eprintln!("key deleted; absence verified by helper");
            } else {
                let text = std::str::from_utf8(&response.payload)
                    .map_err(|_| invalid("invalid inspection output"))?;
                println!("{text}");
            }
            Ok(())
        }
        [command, path] if command == "recipient" => {
            let identity = read_identity(path)?;
            match &identity {
                AnyIdentity::Classical(identity) => println!(
                    "{}",
                    bech32_encode(
                        Hrp::parse_unchecked("age1tpm-wsl"),
                        &identity.recipient.bytes()
                    )
                ),
                AnyIdentity::PostQuantum(identity) => println!(
                    "{}",
                    bech32_encode(
                        Hrp::parse_unchecked(post_quantum::RECIPIENT_HRP),
                        identity.public()
                    )
                ),
            }
            Ok(())
        }
        [command] if command == "--help" => {
            println!(
                "age-plugin-tpm-wsl keygen [--algorithm rsa2048|p256-hpke|mlkem768-p256] | schemes | recover KEY_NAME | recipient IDENTITY | inspect IDENTITY | delete IDENTITY\nDisposable validation: age-tpm-wsl-check --algorithm rsa2048|p256-hpke\nSet AGE_TPM_WSL_HELPER to the absolute Windows helper executable path."
            );
            Ok(())
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "use --help for commands",
        )),
    }
}
