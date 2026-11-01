//! Linux post-quantum scheme: offline public wrapping and stanza routing only.
//! Windows owns every private operation through the helper's post-quantum requests. This
//! module never opens the helper beyond explicit validated request constructors.
use crate::{client::Helper, invalid, wire::Frame};
use age_core::format::Stanza;
use age_tpm_wsl_post_quantum::{
    ENC_LEN, Identity, PUBLIC_LEN, routing_tag, validate_name, validate_public, wrap,
};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use std::io;

/// CLI algorithm name; the classical names stay in `Scheme`.
pub const ALGORITHM: &str = "mlkem768-p256";
/// Plugin name supplied by the age-plugin parser from the `age1tagpq` HRP.
pub const PLUGIN_NAME: &str = "tagpq";
/// Stanza type with exactly two argument fields: routing tag and encapsulation.
pub const TAG: &str = "mlkem768p256tag";
/// Required recipient label for any batch containing post-quantum material.
pub const LABEL: &str = "postquantum";
/// Native recipient Bech32 HRP; never wrapped as `age1tpm-wsl`.
pub const RECIPIENT_HRP: &str = "age1tagpq";
const NAME_PREFIX: &str = "age-tpm-wsl-pq-";

/// A validated native post-quantum recipient (exactly 1,249 canonical bytes).
#[derive(Clone, PartialEq, Eq)]
pub struct Recipient([u8; PUBLIC_LEN]);
impl Recipient {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        validate_public(bytes)?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| invalid("invalid post-quantum public"))?,
        ))
    }
    pub fn bytes(&self) -> &[u8; PUBLIC_LEN] {
        &self.0
    }
    /// Offline wrap producing the canonical `mlkem768p256tag` stanza.
    pub fn stanza(&self, file_key: &[u8; 16]) -> io::Result<Stanza> {
        let wrapped = wrap(&self.0, file_key)?;
        let tag = routing_tag(&self.0, &wrapped.enc)?;
        Ok(Stanza {
            tag: TAG.into(),
            args: vec![
                BASE64_STANDARD_NO_PAD.encode(tag),
                BASE64_STANDARD_NO_PAD.encode(&wrapped.enc),
            ],
            body: wrapped.body,
        })
    }
}

/// A validated `mlkem768p256tag` stanza: canonical arguments and exact body.
pub struct Encapsulation {
    pub tag: [u8; 4],
    pub enc: [u8; ENC_LEN],
    pub body: [u8; 32],
}
impl Encapsulation {
    pub fn parse(stanza: &Stanza) -> io::Result<Self> {
        if stanza.tag != TAG {
            return Err(invalid("unknown stanza tag"));
        }
        if stanza.args.len() != 2 || stanza.body.len() != 32 {
            return Err(invalid("invalid post-quantum stanza shape"));
        }
        let decode = |text: &str, length: usize| -> io::Result<Vec<u8>> {
            let bytes = BASE64_STANDARD_NO_PAD
                .decode(text)
                .map_err(|_| invalid("invalid post-quantum stanza base64"))?;
            if bytes.len() != length || BASE64_STANDARD_NO_PAD.encode(&bytes) != text {
                return Err(invalid("noncanonical post-quantum stanza argument"));
            }
            Ok(bytes)
        };
        Ok(Self {
            tag: decode(&stanza.args[0], 4)?
                .try_into()
                .map_err(|_| invalid("invalid post-quantum routing tag"))?,
            enc: decode(&stanza.args[1], ENC_LEN)?
                .try_into()
                .map_err(|_| invalid("invalid post-quantum encapsulation"))?,
            body: stanza
                .body
                .as_slice()
                .try_into()
                .map_err(|_| invalid("invalid post-quantum stanza body"))?,
        })
    }
    /// The routing tag is a public prefilter, never identity authority.
    pub fn routes_to(&self, identity: &Identity) -> io::Result<bool> {
        Ok(routing_tag(identity.public(), &self.enc)? == self.tag)
    }
}

pub fn key_name() -> String {
    let mut random = [0; 16];
    OsRng.fill_bytes(&mut random);
    format!(
        "{NAME_PREFIX}{}",
        random
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

/// Explicit creation through the helper's bounded post-quantum operation 8.
pub fn create(helper: &Helper) -> io::Result<Identity> {
    let name = key_name();
    // Keep the reference visible if a deadline interrupts creation.
    eprintln!("creating {ALGORITHM} key {name}");
    let response = helper.call(Frame::post_quantum_create(&name)?)?;
    let identity =
        Identity::parse(&response.payload).map_err(|_| invalid("invalid post-quantum identity"))?;
    if identity.name() != name {
        return Err(invalid(
            "helper returned unexpected key name; inspect the reported key",
        ));
    }
    Ok(identity)
}

pub fn recover_request(name: &str) -> io::Result<Frame> {
    Frame::post_quantum_recover(name)
}

pub fn unwrap_request(identity: &Identity, encapsulation: &Encapsulation) -> io::Result<Frame> {
    Frame::post_quantum_unwrap(identity, &encapsulation.enc, &encapsulation.body)
}

pub fn parse_identity(bytes: &[u8]) -> io::Result<Identity> {
    Identity::parse(bytes).map_err(|_| invalid("invalid post-quantum identity"))
}

pub fn valid_name(name: &str) -> io::Result<()> {
    validate_name(name).map_err(|_| invalid("invalid post-quantum key name"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age_tpm_wsl_post_quantum::Identity;

    // Real component keys: an ML-KEM keypair from the pinned AWS-LC and an
    // uncompressed P-256 point from the pinned HPKE provider.
    fn native_public() -> Vec<u8> {
        use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768};
        let key = DecapsulationKey::generate(&ML_KEM_768).unwrap();
        let mut public = key
            .encapsulation_key()
            .unwrap()
            .key_bytes()
            .unwrap()
            .as_ref()
            .to_vec();
        assert_eq!(public.len(), 1184);
        public.extend(p256_point());
        public
    }
    fn p256_point() -> [u8; 65] {
        use hpke::{Kem, Serializable, kem::DhP256HkdfSha256};
        let (_, public) = DhP256HkdfSha256::gen_keypair();
        let encoded = public.to_bytes();
        let point: [u8; 65] = encoded.as_slice().try_into().unwrap();
        point
    }

    #[test]
    fn native_recipient_rejects_wrong_length_and_trailing_bytes() {
        let public = native_public();
        assert!(Recipient::parse(&public).is_ok());
        let mut short = public.clone();
        short.truncate(public.len() - 1);
        assert!(Recipient::parse(&short).is_err());
        let mut long = public.clone();
        long.push(0);
        assert!(Recipient::parse(&long).is_err());
        // A corrupted point tail must make the recipient unusable: parsing or
        // wrapping fails before any stanza is produced.
        let mut off_curve = public.clone();
        off_curve[1184] = 3;
        assert!(
            Recipient::parse(&off_curve)
                .and_then(|recipient| recipient.stanza(&[0x42; 16]))
                .is_err()
        );
    }

    #[test]
    fn stanza_round_trip_and_tamper_rejection() {
        let public = native_public();
        let recipient = Recipient::parse(&public).unwrap();
        let stanza = recipient.stanza(&[0x42; 16]).unwrap();
        assert_eq!(stanza.tag, TAG);
        assert_eq!(stanza.args.len(), 2);
        let parsed = Encapsulation::parse(&stanza).unwrap();
        let identity = Identity::new(&public, &format!("{NAME_PREFIX}{}", "0".repeat(32))).unwrap();
        // The routing tag must route back to the wrapping public key.
        assert!(parsed.routes_to(&identity).unwrap());
        let rebuilt = |args: Vec<String>, body: Vec<u8>, tag: &str| Stanza {
            tag: tag.to_string(),
            args,
            body,
        };
        let mut tampered_tag = stanza.args[0].clone();
        tampered_tag.insert(0, 'A');
        assert!(
            Encapsulation::parse(&rebuilt(
                vec![tampered_tag, stanza.args[1].clone()],
                stanza.body.clone(),
                TAG,
            ))
            .is_err()
        );
        assert!(
            Encapsulation::parse(&rebuilt(
                stanza.args.clone(),
                stanza.body.clone(),
                "mlkem768p256other",
            ))
            .is_err()
        );
        let mut extra_arg = stanza.args.clone();
        extra_arg.push(String::new());
        assert!(Encapsulation::parse(&rebuilt(extra_arg, stanza.body.clone(), TAG)).is_err());
        let mut short_body = stanza.body.clone();
        short_body.pop();
        assert!(Encapsulation::parse(&rebuilt(stanza.args.clone(), short_body, TAG,)).is_err());
    }

    #[test]
    fn post_quantum_names_use_the_dedicated_prefix() {
        let name = key_name();
        assert_eq!(name.len(), 47);
        assert!(valid_name(&name).is_ok());
        assert!(valid_name("age-tpm-wsl-00112233445566778899aabbccddeeff").is_err());
        assert!(valid_name(&format!("{NAME_PREFIX}xyz")).is_err());
    }
}
