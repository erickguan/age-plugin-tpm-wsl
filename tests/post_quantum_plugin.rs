//! post-quantum recipient/identity ingestion, labels and offline wrapping through the
//! plugin state machine. No helper process is involved; unwrap routing is
//! covered by the native campaign.
use age_core::{
    format::{FileKey, Stanza},
    plugin::Result as PluginResult,
    secrecy::SecretString,
};
use age_plugin::recipient::RecipientPluginV1;
use age_plugin::{Callbacks, recipient};
use age_plugin_tpm_wsl::plugin::Recipients;
use age_plugin_tpm_wsl::post_quantum;

struct Silent;
impl Callbacks<recipient::Error> for Silent {
    fn message(&mut self, _: &str) -> PluginResult<()> {
        Ok(Ok(()))
    }
    fn confirm(&mut self, _: &str, _: &str, _: Option<&str>) -> PluginResult<bool> {
        Ok(Ok(true))
    }
    fn request_public(&mut self, _: &str) -> PluginResult<String> {
        Err(std::io::Error::other("unused"))
    }
    fn request_secret(&mut self, _: &str) -> PluginResult<SecretString> {
        Err(std::io::Error::other("unused"))
    }
    fn error(&mut self, _: recipient::Error) -> PluginResult<()> {
        Ok(Ok(()))
    }
}

/// `recipient::Error` implements neither `Debug` nor `Display`; pull the
/// human-readable message out of its variants.
fn describe(error: &recipient::Error) -> String {
    match error {
        recipient::Error::Recipient { message, .. }
        | recipient::Error::Identity { message, .. }
        | recipient::Error::Internal { message } => message.clone(),
    }
}

/// `recipient::Error` is not `Debug`, so failures are reported by message.
fn ingested(result: Result<(), recipient::Error>) {
    if let Err(error) = result {
        panic!("unexpected ingestion failure: {}", describe(&error));
    }
}

fn wrapped(recipients: &mut Recipients) -> Vec<Vec<Stanza>> {
    let key = FileKey::try_init_with_mut(|out| -> std::io::Result<()> {
        out.fill(0x5c);
        Ok(())
    })
    .unwrap();
    match recipients.wrap_file_keys(vec![key], Silent) {
        Ok(Ok(files)) => files,
        Ok(Err(errors)) => panic!(
            "wrap failed: {}",
            errors.iter().map(describe).collect::<Vec<_>>().join(", ")
        ),
        Err(error) => panic!("wrap transport failed: {error}"),
    }
}

fn native_public() -> Vec<u8> {
    use aws_lc_rs::kem::{DecapsulationKey, ML_KEM_768};
    use hpke::{Kem, Serializable, kem::DhP256HkdfSha256};
    let key = DecapsulationKey::generate(&ML_KEM_768).unwrap();
    let mut public = key
        .encapsulation_key()
        .unwrap()
        .key_bytes()
        .unwrap()
        .as_ref()
        .to_vec();
    let (_, point) = DhP256HkdfSha256::gen_keypair();
    public.extend(point.to_bytes().as_slice());
    public
}

fn classical_recipient_bytes() -> Vec<u8> {
    use hpke::{Kem, Serializable, kem::DhP256HkdfSha256};
    let (_, public) = DhP256HkdfSha256::gen_keypair();
    let mut bytes = vec![2, 0, 1];
    bytes.extend(public.to_bytes().as_slice());
    bytes
}

fn post_quantum_identity_bytes(public: &[u8]) -> Vec<u8> {
    age_tpm_wsl_post_quantum::Identity::new(
        public,
        "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef",
    )
    .unwrap()
    .bytes()
    .to_vec()
}

#[test]
fn namespaces_are_strict_and_mixtures_are_rejected_at_ingestion() {
    let post_quantum_public = native_public();
    let mut recipients = Recipients::default();
    ingested(recipients.add_recipient(0, post_quantum::PLUGIN_NAME, &post_quantum_public));
    // Classical material cannot join a post-quantum batch, in either direction and
    // through either channel (recipient or identity).
    assert!(
        recipients
            .add_recipient(1, "tpm-wsl", &classical_recipient_bytes())
            .is_err()
    );
    ingested(recipients.add_identity(
        2,
        "tpm-wsl",
        &post_quantum_identity_bytes(&post_quantum_public),
    ));
    let mut classical_only = Recipients::default();
    ingested(classical_only.add_recipient(0, "tpm-wsl", &classical_recipient_bytes()));
    assert!(
        classical_only
            .add_recipient(1, post_quantum::PLUGIN_NAME, &post_quantum_public)
            .is_err()
    );
    // The native post-quantum format is only accepted under the tagpq namespace, and the
    // classical namespace rejects it by length.
    assert!(
        Recipients::default()
            .add_recipient(0, "tpm-wsl", &post_quantum_public)
            .is_err()
    );
    assert!(
        Recipients::default()
            .add_recipient(0, post_quantum::PLUGIN_NAME, &classical_recipient_bytes())
            .is_err()
    );
}

#[test]
fn labels_are_required_exactly_for_batches_with_post_quantum_material() {
    let mut recipients = Recipients::default();
    assert!(recipients.labels().is_empty());
    ingested(recipients.add_recipient(0, post_quantum::PLUGIN_NAME, &native_public()));
    let labels = recipients.labels();
    assert_eq!(
        labels,
        std::collections::HashSet::from([post_quantum::LABEL.into()])
    );
}

#[test]
fn post_quantum_recipients_wrap_offline_into_canonical_stanzas() {
    let mut recipients = Recipients::default();
    ingested(recipients.add_recipient(0, post_quantum::PLUGIN_NAME, &native_public()));
    let files = wrapped(&mut recipients);
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].len(), 1);
    let stanza = &files[0][0];
    assert_eq!(stanza.tag, post_quantum::TAG);
    let parsed = post_quantum::Encapsulation::parse(stanza).unwrap();
    assert_eq!(parsed.body.len(), 32);
    // Malformed variations never parse.
    let mut args = stanza.args.clone();
    args[1].pop();
    let broken = Stanza {
        tag: stanza.tag.clone(),
        args,
        body: stanza.body.clone(),
    };
    assert!(post_quantum::Encapsulation::parse(&broken).is_err());
}

#[test]
fn version_three_identities_join_post_quantum_batches_and_route_by_tag() {
    let public = native_public();
    let identity_bytes = post_quantum_identity_bytes(&public);
    let mut recipients = Recipients::default();
    ingested(recipients.add_identity(0, "tpm-wsl", &identity_bytes));
    assert_eq!(recipients.labels().len(), 1);
    let files = wrapped(&mut recipients);
    let stanza = &files[0][0];
    let parsed = post_quantum::Encapsulation::parse(stanza).unwrap();
    let identity = post_quantum::parse_identity(&identity_bytes).unwrap();
    assert!(parsed.routes_to(&identity).unwrap());
    // A different post-quantum identity must not route to this stanza.
    let other =
        post_quantum::parse_identity(&post_quantum_identity_bytes(&native_public())).unwrap();
    assert!(!parsed.routes_to(&other).unwrap());
}
