use age_core::format::Stanza;
use age_plugin_tpm_wsl::{
    Identity, Recipient, Scheme, TAG,
    keys::create_request,
    plugin::validate_stanza,
    wire::{CREATE, CREATE_SCHEME, Frame, UNWRAP, UNWRAP_SCHEME},
};
use hpke::{Kem, Serializable};
fn recipient_bytes() -> Vec<u8> {
    let mut bytes = vec![0xff; 257];
    bytes[0] = 1;
    bytes
}
fn p256_bytes() -> Vec<u8> {
    let (_, public) = hpke::kem::DhP256HkdfSha256::gen_keypair();
    let mut bytes = vec![2, 0, 1];
    bytes.extend(public.to_bytes());
    bytes
}
fn identity(bytes: &[u8]) -> Identity {
    Identity {
        recipient: Recipient::parse(bytes).unwrap(),
        name: "age-tpm-wsl-0123456789abcdef0123456789abcdef".into(),
    }
}
#[test]
fn enforces_canonical_versions_names_and_lengths() {
    for bytes in [recipient_bytes(), p256_bytes()] {
        let identity = identity(&bytes);
        assert_eq!(identity.recipient.bytes(), bytes);
        let encoded = identity.bytes();
        // Fixed wire sizes from the written specification, including the
        // 44-byte key name. Catch arithmetic drift in docs and serializers.
        assert_eq!(identity.name.len(), 44);
        assert_eq!(
            encoded.len(),
            match identity.recipient.scheme() {
                Scheme::Rsa2048 => 302,
                Scheme::P256Hpke => 113,
            }
        );
        assert_eq!(Identity::parse(&encoded).unwrap().bytes(), encoded);
        for length in 0..encoded.len() {
            assert!(Identity::parse(&encoded[..length]).is_err());
        }
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(Identity::parse(&trailing).is_err());
        let mut bad_name = encoded;
        *bad_name.last_mut().unwrap() = b'G';
        assert!(Identity::parse(&bad_name).is_err());
    }
    let bytes = recipient_bytes();
    for length in [0, 1, 256, 258] {
        assert!(Recipient::parse(&vec![1; length]).is_err());
    }
    for (offset, value) in [(0, 2), (1, 0x7f), (256, 0xfe)] {
        let mut broken = bytes.clone();
        broken[offset] = value;
        assert!(Recipient::parse(&broken).is_err());
    }
    let bytes = p256_bytes();
    for offset in [0, 1, 2, 3] {
        let mut broken = bytes.clone();
        broken[offset] ^= 1;
        assert!(Recipient::parse(&broken).is_err());
    }
    for length in [0, 1, 2, 3, 67, 69] {
        assert!(Recipient::parse(&vec![0; length]).is_err());
    }
    let mut invalid_point = vec![2, 0, 1, 4];
    invalid_point.extend([0; 64]);
    assert!(Recipient::parse(&invalid_point).is_err());
}
#[test]
fn enforces_stanza_format_and_fingerprint() {
    for bytes in [recipient_bytes(), p256_bytes()] {
        let recipient = Recipient::parse(&bytes).unwrap();
        let scheme = recipient.scheme();
        let mut stanza = Stanza {
            tag: scheme.tag().into(),
            args: vec![scheme.stanza_version().into(), recipient.fingerprint()],
            body: vec![0; scheme.body_len()],
        };
        assert!(validate_stanza(&stanza).is_ok());
        stanza.args[0] = "99".into();
        assert!(validate_stanza(&stanza).is_err());
        stanza.args[0] = scheme.stanza_version().into();
        stanza.args[1].push('=');
        assert!(validate_stanza(&stanza).is_err());
        stanza.args[1] = recipient.fingerprint();
        stanza.body.pop();
        assert!(validate_stanza(&stanza).is_err());
        stanza.tag = TAG.into();
        assert!(validate_stanza(&stanza).is_err());
    }
}
#[test]
fn helper_requests_bind_operation_scheme_and_exact_lengths() {
    for (bytes, operation) in [(recipient_bytes(), UNWRAP), (p256_bytes(), UNWRAP_SCHEME)] {
        let identity = identity(&bytes);
        // Literal protocol expectations stay independent of shared identifiers.
        let create = create_request(&identity.name, identity.recipient.scheme());
        if operation == UNWRAP {
            assert_eq!(create.operation, CREATE);
            assert_eq!(&*create.payload, identity.name.as_bytes());
        } else {
            assert_eq!(create.operation, CREATE_SCHEME);
            assert_eq!(&create.payload[..2], &[0, 1]);
            assert_eq!(&create.payload[2..], identity.name.as_bytes());
        }
        let body = vec![0; identity.recipient.scheme().body_len()];
        let mut frame = Frame::unwrap(&identity, &body);
        assert_eq!(frame.operation, operation);
        let (parsed, parsed_body) = frame.unwrap_parts().unwrap();
        assert_eq!(parsed.bytes(), identity.bytes());
        assert_eq!(parsed_body, body);
        for length in 0..frame.payload.len() {
            let mut short = Frame::unwrap(&identity, &body);
            short.payload.truncate(length);
            assert!(short.unwrap_parts().is_err());
        }
        frame.payload.push(0);
        assert!(frame.unwrap_parts().is_err());
        frame = Frame::unwrap(&identity, &body);
        frame.operation = if operation == UNWRAP {
            UNWRAP_SCHEME
        } else {
            UNWRAP
        };
        assert!(frame.unwrap_parts().is_err());
    }
    assert!(Scheme::parse("auto").is_err());
}
