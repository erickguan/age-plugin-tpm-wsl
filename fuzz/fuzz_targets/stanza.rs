#![no_main]
use age_core::format::Stanza;
use age_plugin_tpm_wsl::{Scheme, plugin::validate_stanza, post_quantum};
use base64::{Engine, prelude::BASE64_STANDARD_NO_PAD};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // NUL-delimited arguments, followed by arbitrary binary body. This seam
    // never invokes the plugin identity handler or any Windows helper.
    let mut parts = data.splitn(4, |byte| *byte == 0);
    let version = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let fingerprint = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
    let extra = parts.next().unwrap_or_default();
    let body = parts.next().unwrap_or_default().to_vec();
    let mut args = vec![version, fingerprint];
    if !extra.is_empty() {
        args.push(String::from_utf8_lossy(extra).into_owned());
    }
    for scheme in [Scheme::Rsa2048, Scheme::P256Hpke] {
        let stanza = Stanza {
            tag: scheme.tag().into(),
            args: args.clone(),
            body: body.clone(),
        };
        if let Ok(fingerprint) = validate_stanza(&stanza) {
            assert_eq!(stanza.args.len(), 2);
            assert_eq!(stanza.args[0], scheme.stanza_version());
            assert_eq!(stanza.body.len(), scheme.body_len());
            assert_eq!(fingerprint.len(), 43);
        }
    }
    let stanza = Stanza {
        tag: post_quantum::TAG.into(),
        args,
        body,
    };
    if let Ok(parsed) = post_quantum::Encapsulation::parse(&stanza) {
        assert_eq!(stanza.args.len(), 2);
        assert_eq!(stanza.args[0], BASE64_STANDARD_NO_PAD.encode(parsed.tag));
        assert_eq!(stanza.args[1], BASE64_STANDARD_NO_PAD.encode(parsed.enc));
        assert_eq!(stanza.body, parsed.body);
        // A tagged stanza cannot be reinterpreted by the classical parser.
        assert!(validate_stanza(&stanza).is_err());
    }
});
