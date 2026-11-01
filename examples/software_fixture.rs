//! Test-only software helper. Never install it as the Windows helper.
use age_plugin_tpm_wsl::{
    Identity, LABEL, PublicKey, Recipient, Scheme, invalid, schemes, wire::Frame,
};
use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der},
    rsa::{KeySize, OAEP_SHA256_MGF1SHA256, OaepPrivateDecryptingKey, PrivateDecryptingKey},
};
use p256::elliptic_curve::sec1::ToSec1Point;
use std::{io, path::PathBuf};
use zeroize::Zeroizing;

#[path = "software_fixture/scalar.rs"]
mod scalar;

fn rsa_recipient(private: &PrivateDecryptingKey) -> io::Result<Recipient> {
    let der: PublicKeyX509Der<'static> = private
        .public_key()
        .as_der()
        .map_err(|_| invalid("fixture public encoding failed"))?;
    let public = aws_lc_rs::rsa::PublicKey::from_der(der.as_ref())
        .map_err(|_| invalid("invalid fixture public key"))?;
    if public.exponent().big_endian_without_leading_zero() != [1, 0, 1] {
        return Err(invalid("invalid fixture exponent"));
    }
    let mut bytes = vec![1];
    bytes.extend(public.modulus().big_endian_without_leading_zero());
    Recipient::parse(&bytes)
}

fn run() -> io::Result<()> {
    let dir = PathBuf::from(
        std::env::var_os("TPM_WSL_FIXTURE_DIR")
            .ok_or_else(|| invalid("fixture directory required"))?,
    );
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("generate") {
        let scheme = match args.as_slice() {
            [_] => Scheme::Rsa2048,
            [_, flag, name] if flag == "--algorithm" => Scheme::parse(name)?,
            _ => return Err(invalid("use generate [--algorithm SCHEME]")),
        };
        let recipient = match scheme {
            Scheme::Rsa2048 => {
                let private = PrivateDecryptingKey::generate(KeySize::Rsa2048)
                    .map_err(|_| invalid("fixture keygen failed"))?;
                let der: Pkcs8V1Der<'static> = private
                    .as_der()
                    .map_err(|_| invalid("fixture encoding failed"))?;
                std::fs::write(dir.join("private.der"), der.as_ref())?;
                rsa_recipient(&private)?
            }
            Scheme::P256Hpke => {
                let private = scalar::generate()?;
                std::fs::write(
                    dir.join("private.p256"),
                    Zeroizing::new(private.to_bytes()).as_slice(),
                )?;
                let mut bytes = vec![2, 0, 1];
                bytes.extend(private.public_key().to_sec1_point(false).as_bytes());
                Recipient::parse(&bytes)?
            }
        };
        let identity = Identity {
            recipient,
            name: "age-tpm-wsl-00000000000000000000000000000000".into(),
        };
        age_plugin::print_new_identity("tpm-wsl", &identity.bytes(), &identity.recipient.bytes());
        return Ok(());
    }
    let request = Frame::read(io::stdin().lock())?;
    if request.status != 0 {
        return Err(invalid("invalid fixture request"));
    }
    let (identity, body) = request.unwrap_parts()?;
    let decrypted = match &identity.recipient.key {
        PublicKey::Rsa(_) => {
            let der = Zeroizing::new(std::fs::read(dir.join("private.der"))?);
            let private = PrivateDecryptingKey::from_pkcs8(&der)
                .map_err(|_| invalid("invalid fixture private key"))?;
            if rsa_recipient(&private)? != identity.recipient {
                return Err(invalid("fixture fingerprint mismatch"));
            }
            let key = OaepPrivateDecryptingKey::new(private)
                .map_err(|_| invalid("invalid fixture OAEP key"))?;
            let mut plain = Zeroizing::new(vec![0; key.min_output_size()]);
            let length = key
                .decrypt(
                    &OAEP_SHA256_MGF1SHA256,
                    body,
                    &mut plain,
                    Some(LABEL.as_bytes()),
                )
                .map_err(|_| invalid("fixture OAEP failed"))?
                .len();
            plain.truncate(length);
            plain
        }
        PublicKey::P256(public) => {
            let bytes = Zeroizing::new(std::fs::read(dir.join("private.p256"))?);
            let private = p256::SecretKey::from_slice(&bytes)
                .map_err(|_| invalid("invalid fixture scalar"))?;
            if private.public_key().to_sec1_point(false).as_bytes() != public {
                return Err(invalid("fixture fingerprint mismatch"));
            }
            schemes::open_p256(&identity.recipient, body, |enc| {
                let peer =
                    p256::PublicKey::from_sec1_bytes(enc).map_err(|_| invalid("invalid peer"))?;
                let raw = p256::ecdh::diffie_hellman(private.to_nonzero_scalar(), peer.as_affine());
                Ok(Zeroizing::new(
                    raw.raw_secret_bytes()
                        .as_slice()
                        .try_into()
                        .map_err(|_| invalid("invalid raw secret"))?,
                ))
            })?
        }
    };
    if decrypted.len() != 16 {
        return Err(invalid("invalid fixture file key length"));
    }
    Frame {
        operation: request.operation,
        status: 0,
        payload: decrypted,
    }
    .write(io::stdout().lock())
}
fn main() {
    if run().is_err() {
        eprintln!("software fixture failed");
        std::process::exit(1);
    }
}
