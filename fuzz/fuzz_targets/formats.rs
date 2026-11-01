#![no_main]
use age_plugin_tpm_wsl::{Identity, Recipient, post_quantum, validate_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(recipient) = Recipient::parse(data) {
        assert_eq!(recipient.bytes(), data);
        let parsed = Recipient::parse(&recipient.bytes()).unwrap();
        assert_eq!(parsed.fingerprint(), recipient.fingerprint());
    }
    if let Ok(identity) = Identity::parse(data) {
        assert_eq!(identity.bytes(), data);
        validate_name(&identity.name).unwrap();
        let parsed = Identity::parse(&identity.bytes()).unwrap();
        assert_eq!(parsed.name, identity.name);
        assert_eq!(
            parsed.recipient.fingerprint(),
            identity.recipient.fingerprint()
        );
    }
    if let Ok(recipient) = post_quantum::Recipient::parse(data) {
        assert_eq!(recipient.bytes(), data);
        assert!(post_quantum::Recipient::parse(recipient.bytes()).unwrap() == recipient);
        // Native tagged recipients cannot enter the classical parser.
        assert!(Recipient::parse(data).is_err());
    }
    if let Ok(identity) = post_quantum::parse_identity(data) {
        assert_eq!(identity.bytes(), data);
        post_quantum::valid_name(identity.name()).unwrap();
        assert!(post_quantum::parse_identity(&identity.bytes()).unwrap() == identity);
        assert!(Identity::parse(data).is_err());
    }
    if let Ok(name) = std::str::from_utf8(data) {
        let _ = validate_name(name);
        let _ = post_quantum::valid_name(name);
    }
});
