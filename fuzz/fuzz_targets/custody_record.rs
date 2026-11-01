#![no_main]
use age_tpm_wsl_post_quantum::{IDENTITY_LEN, Identity, MAX_RECORD, Record, validate_name};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // No machine state or private operation: every byte is a public parser input.
    if let Ok(name) = std::str::from_utf8(data) {
        let _ = validate_name(name);
    }
    if let Ok(identity) = Identity::parse(data) {
        assert_eq!(identity.bytes(), data);
        validate_name(identity.name()).unwrap();
        assert_eq!(
            Identity::parse(&identity.bytes()).unwrap().binding(),
            identity.binding()
        );
    }
    // A separate public prefix models the caller's retained expectation. The
    // record cannot choose its own authority, even when its encoding is valid.
    let Some(prefix) = data.get(..IDENTITY_LEN) else {
        return;
    };
    let Ok(expected) = Identity::parse(prefix) else {
        return;
    };
    let record_bytes = &data[IDENTITY_LEN..];
    if let Ok(record) = Record::parse(record_bytes, &expected) {
        assert!(record_bytes.len() <= MAX_RECORD);
        assert!(record.identity() == &expected);
        assert_eq!(record.encode(), record_bytes);
        let mut other_name = expected.name().as_bytes().to_vec();
        let last = other_name.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        let other =
            Identity::new(expected.public(), std::str::from_utf8(&other_name).unwrap()).unwrap();
        assert!(Record::parse(record_bytes, &other).is_err());
    }
});
