//! Explicitly ignored Windows-only native validation. Production has no test root.
use super::super::tpm::{Context, Native, Transport};
use super::*;
use serde_json::{Value, json};
use std::io::Write;

mod request_roundtrip;

const PREFIX: &str = "age-tpm-wsl-pq-native-";
const ACK: &str = "isolated-disposable-only";
const REPORT: &str = "ATW_PQ_NATIVE_REPORT=";
#[derive(Clone, Copy)]
pub(super) enum Checkpoint {
    Receipt,
    Partial,
    Pending,
    Rollback,
}

struct Input {
    mode: String,
    namespace: String,
    name: String,
    expected: Option<Identity>,
}
fn namespace(value: &str) -> Result<&str> {
    let suffix = value
        .strip_prefix(PREFIX)
        .ok_or("reserved native-test namespace required")?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("fresh lowercase-hex native-test namespace required".into());
    }
    Ok(suffix)
}
fn decode(text: &str) -> Result<Identity> {
    if text.len() != 2600 {
        return Err("canonical public reference required".into());
    }
    let bytes = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| {
            let s = std::str::from_utf8(b).map_err(|_| "invalid public reference")?;
            u8::from_str_radix(s, 16).map_err(|_| "invalid public reference")
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Identity::parse(&bytes).map_err(|_| "invalid public reference".into())
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
impl Input {
    fn parse(mode: String, root: String, encoded: Option<String>) -> Result<Self> {
        let suffix = namespace(&root)?;
        if !matches!(
            mode.as_str(),
            "create-final"
                | "create-receipt"
                | "create-partial"
                | "create-pending"
                | "create-rollback"
                | "unwrap"
                | "inspect"
                | "recover"
                | "denials"
                | "replace-pcp"
                | "delete"
                | "absence"
                | "remove-root"
                | "fault-absence"
                | "fault-close"
        ) {
            return Err("unknown explicit native-test operation".into());
        }
        let name = format!("age-tpm-wsl-pq-{suffix}");
        age_tpm_wsl_post_quantum::validate_name(&name)
            .map_err(|_| "invalid dedicated native-test key name")?;
        let expected = encoded.as_deref().map(decode).transpose()?;
        if expected.as_ref().is_some_and(|i| i.name() != name) {
            return Err("public reference/native namespace mismatch".into());
        }
        if matches!(
            mode.as_str(),
            "unwrap" | "inspect" | "recover" | "denials" | "replace-pcp" | "delete"
        ) && expected.is_none()
        {
            return Err("independently retained public reference required".into());
        }
        Ok(Self {
            mode,
            namespace: root,
            name,
            expected,
        })
    }
    fn expected(&self) -> Outcome<&Identity> {
        self.expected
            .as_ref()
            .ok_or("missing independent public reference".into())
    }
    fn store(&self, create: bool) -> Outcome<Store> {
        let control = match self.mode.as_str() {
            "create-receipt" => Some(Checkpoint::Receipt),
            "create-partial" => Some(Checkpoint::Partial),
            "create-pending" => Some(Checkpoint::Pending),
            "create-rollback" => Some(Checkpoint::Rollback),
            _ => None,
        };
        Ok(Store {
            root: fs(Root::open(
                &[&self.namespace],
                if create {
                    RootMode::CreateNew
                } else {
                    RootMode::Existing
                },
            ))?,
            control,
        })
    }
}
fn denied<T>(value: Outcome<T>, reasons: &[&str]) -> Outcome<()> {
    match value {
        Err(failure) if failure.cleanup_failed => Err(failure),
        Err(failure) if reasons.contains(&failure.message.as_str()) => Ok(()),
        Err(_) => Err("negative native control failed for another cause".into()),
        Ok(_) => Err("negative native control unexpectedly succeeded".into()),
    }
}
fn cleanup<T>(value: Outcome<T>) -> Outcome<T> {
    match value {
        Err(mut e) => {
            e.cleanup_failed = true;
            Err(e)
        }
        ok => ok,
    }
}
fn roundtrip(store: &Store, identity: &Identity) -> Outcome<()> {
    let key = random::<16>()?;
    let wrapped = age_tpm_wsl_post_quantum::wrap(identity.public(), key.as_ref())
        .map_err(|_| "native public wrapping failed")?;
    if store
        .unwrap(identity, &wrapped.enc, &wrapped.body)?
        .as_slice()
        != key.as_ref()
    {
        return Err("native restored file key mismatch".into());
    }
    Ok(())
}
/// Canonical SEC 2 P-256 base point, uncompressed. The explicit size keeps a
/// transcription slip from reaching the ignored native case.
const GENERATOR: [u8; 65] = [
    4, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
    0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
    0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
    0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
    0xf5,
];
fn alternate(identity: &Identity, component: &str) -> Outcome<Identity> {
    let mut public = identity.public().to_vec();
    if component == "mlkem" {
        let coefficient = u16::from(public[0]) | (u16::from(public[1] & 15) << 8);
        public[0] = u8::from(coefficient == 0);
        public[1] &= 0xf0;
    } else {
        public[1184..].copy_from_slice(&GENERATOR);
    }
    let other = Identity::new(&public, identity.name())
        .map_err(|_| "invalid alternative public fixture")?;
    if &other == identity {
        return Err("alternative public fixture equals original".into());
    }
    Ok(other)
}
/// Alter only a known slot through the test's held root. Never repair during
/// decryption. A fatal private cleanup failure prevents even fixture restoration.
fn with_file(
    store: &Store,
    expected: &Identity,
    slot: Slot,
    changed: &[u8],
    check: impl FnOnce() -> Outcome<()>,
) -> Outcome<()> {
    let lease = fs(store.root.open_for_delete(expected.name()))?;
    receipt(&lease, expected)?;
    let original = Zeroizing::new(fs(lease.read(slot))?);
    cleanup(fs(lease.remove_file(slot)))?;
    cleanup(fs(lease.write_new(slot, changed)))?;
    drop(lease);
    let operation = check();
    if operation.as_ref().is_err_and(|e| e.cleanup_failed) {
        return operation;
    }
    let restored = (|| -> Outcome<()> {
        let lease = fs(store.root.open_for_delete(expected.name()))?;
        if fs(lease.read(slot))? != changed {
            return Err("native fixture changed unexpectedly; no overwrite allowed".into());
        }
        fs(lease.remove_file(slot))?;
        fs(lease.write_new(slot, &original))?;
        if fs(lease.read(slot))? != original.as_slice() {
            return Err("native fixture restore mismatch".into());
        }
        Ok(())
    })();
    Failure::complete(operation, restored.map_err(|e| e.message))
}
fn checks(store: &Store, expected: &Identity, report: &mut Value) -> Outcome<()> {
    let file_key = random::<16>()?;
    let wrapped = age_tpm_wsl_post_quantum::wrap(expected.public(), file_key.as_ref())
        .map_err(|_| "native wrap failed")?;
    report["denials"] = json!([]);
    for component in ["mlkem", "p256"] {
        let other = alternate(expected, component)?;
        denied(
            store.unwrap(&other, &wrapped.enc, &wrapped.body),
            &["receipt differs from expected post-quantum identity"],
        )?;
        denied(
            store.delete(&other),
            &["receipt differs from expected post-quantum identity"],
        )?;
        report["denials"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("{component}_identity_and_delete")));
    }
    for component in ["mlkem", "p256", "body"] {
        let mut enc = wrapped.enc.clone();
        let mut body = wrapped.body.clone();
        match component {
            "mlkem" => enc[0] ^= 1,
            "p256" => enc[1088..].copy_from_slice(point(&alternate(expected, "p256")?)),
            _ => body[0] ^= 1,
        }
        denied(
            store.unwrap(expected, &enc, &body),
            &["post-quantum HPKE authentication failed"],
        )?;
        report["denials"]
            .as_array_mut()
            .unwrap()
            .push(json!(format!("{component}_ciphertext")));
    }
    let mut invalid = wrapped.enc.clone();
    invalid[1088..].fill(0);
    denied(
        store.unwrap(expected, &invalid, &wrapped.body),
        &["invalid post-quantum encapsulation"],
    )?;
    with_file(
        store,
        expected,
        Slot::Receipt,
        &alternate(expected, "mlkem")?.bytes(),
        || {
            denied(
                store.unwrap(expected, &wrapped.enc, &wrapped.body),
                &["receipt differs from expected post-quantum identity"],
            )
        },
    )?;
    report["denials"]
        .as_array_mut()
        .unwrap()
        .push(json!("invalid_point_and_receipt"));
    let bytes = {
        let enrollment = fs(store.root.open_enrollment(expected.name()))?;
        fs(enrollment.read(Slot::Final))?
    };
    let parsed = record(&bytes, expected)?;
    let mut trailing = bytes.clone();
    trailing.push(0);
    for damaged in [&bytes[..bytes.len() - 1], &trailing] {
        with_file(store, expected, Slot::Final, damaged, || {
            denied(
                store.unwrap(expected, &wrapped.enc, &wrapped.body),
                &["invalid expected custody record"],
            )
        })?;
    }
    let substitution = Record::new(
        alternate(expected, "mlkem")?,
        parsed.parent(),
        parsed.private(),
        parsed.public(),
    )
    .map_err(|_| "invalid record fixture")?
    .encode();
    with_file(store, expected, Slot::Final, &substitution, || {
        denied(
            store.unwrap(expected, &wrapped.enc, &wrapped.body),
            &["invalid expected custody record"],
        )
    })?;
    report["denials"]
        .as_array_mut()
        .unwrap()
        .push(json!("record_truncation_trailing_identity"));
    let mut parent = parsed.parent().to_vec();
    *parent.last_mut().ok_or("missing parent fixture")? ^= 1;
    let changed = Record::new(expected.clone(), &parent, parsed.private(), parsed.public())
        .map_err(|_| "invalid parent fixture")?
        .encode();
    with_file(store, expected, Slot::Final, &changed, || {
        denied(
            store.unwrap(expected, &wrapped.enc, &wrapped.body),
            &["custody owner parent changed"],
        )
    })?;
    let mut private = Zeroizing::new(parsed.private().to_vec());
    *private.last_mut().ok_or("missing private fixture")? ^= 1;
    let changed = Record::new(expected.clone(), parsed.parent(), &private, parsed.public())
        .map_err(|_| "invalid private fixture")?
        .encode();
    with_file(store, expected, Slot::Final, &changed, || {
        denied(
            store.unwrap(expected, &wrapped.enc, &wrapped.body),
            &["TPM status 0x0000009f", "TPM status 0x000001df"],
        )
    })?;
    report["denials"]
        .as_array_mut()
        .unwrap()
        .push(json!("actual_parent_and_tpm_blob"));
    let wrong_seed = random::<64>()?;
    if public(&restore(&wrong_seed)?, point(expected))? == expected.public() {
        return Err("test seed unexpectedly matches original public".into());
    }
    let changed = seal(&wrong_seed, expected)?.encode();
    with_file(store, expected, Slot::Final, &changed, || {
        denied(
            store.unwrap(expected, &wrapped.enc, &wrapped.body),
            &["seed/public/PCP relation mismatch"],
        )
    })?;
    // A separately sealed payload uses the correct child authorization but a
    // deliberately incorrect bound suffix. No seed leaves this Windows process.
    let mut context = Context::new(Native::open()?);
    let operation = (|| -> Outcome<Record> {
        let (parent, public) = context.parent()?;
        if public != parsed.parent() {
            return Err("control owner parent changed".into());
        }
        let child = context.load(parent, parsed.private(), parsed.public())?;
        let mut payload = context.unseal(child, &expected.binding())?;
        payload[95] ^= 1;
        let (private, child_public) = context.seal(parent, &payload, &expected.binding())?;
        Record::new(expected.clone(), &public, &private, &child_public)
            .map_err(|_| "invalid bound suffix fixture".into())
    })();
    let changed = context.complete(operation)?.encode();
    with_file(store, expected, Slot::Final, &changed, || {
        denied(
            store.unwrap(expected, &wrapped.enc, &wrapped.body),
            &["unsealed custody binding mismatch"],
        )
    })?;
    report["denials"]
        .as_array_mut()
        .unwrap()
        .push(json!("seed_public_and_binding_suffix"));
    let classical = crate::cng::Provider::open().map_err(|_| "classical provider unavailable")?;
    if !matches!(classical.recover(expected.name()), Err(crate::cng::INVALID)) {
        return Err("classical recover accepted post-quantum namespace".into());
    }
    denied(
        store.create(expected.name()),
        &["Native filesystem status 0xc0000035"],
    )?;
    report["denials"]
        .as_array_mut()
        .unwrap()
        .push(json!("classical_namespace_and_no_overwrite"));
    roundtrip(store, expected)?;
    report["valid_after_denials"] = json!(true);
    Ok(())
}
struct FaultTransport {
    native: Native,
    mode: String,
    flushes: usize,
    absences: usize,
    closed: bool,
}
impl Transport for FaultTransport {
    fn submit(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let out = self.native.submit(command)?;
        let code = u32::from_be_bytes(command[6..10].try_into().unwrap());
        if out.len() >= 10 && out[..2] == [0x80, 1] && out[2..6] == (out.len() as u32).to_be_bytes()
        {
            let status = u32::from_be_bytes(out[6..10].try_into().unwrap());
            if code == 0x165 && status == 0 && out.len() == 10 {
                self.flushes += 1;
            }
            if code == 0x173
                && matches!(status, 0x8b | 0x18b)
                && out.len() == 10
                && self.flushes == 1
            {
                self.absences += 1;
                if self.mode == "fault-absence" {
                    return Err(
                        "controlled reported absence failure after actual verified flush".into(),
                    );
                }
            }
        }
        Ok(out)
    }
    fn close(&mut self) -> Result<()> {
        self.native.close()?;
        self.closed = true;
        if self.mode == "fault-close" && self.flushes == 1 && self.absences == 1 {
            Err("controlled reported close failure after actual close".into())
        } else {
            Ok(())
        }
    }
}
fn fault(input: &Input, report: &mut Value) -> Outcome<()> {
    // Public stand-in control uses ONE transient parent, NO PCP key or files.
    // Shared counters survive consuming Context::complete for physical checks.
    use std::{cell::RefCell, rc::Rc};
    struct Observed(Rc<RefCell<FaultTransport>>);
    impl Transport for Observed {
        fn submit(&mut self, command: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
            self.0.borrow_mut().submit(command)
        }
        fn close(&mut self) -> Result<()> {
            self.0.borrow_mut().close()
        }
    }
    let transport = Rc::new(RefCell::new(FaultTransport {
        native: Native::open()?,
        mode: input.mode.clone(),
        flushes: 0,
        absences: 0,
        closed: false,
    }));
    let mut context = Context::new(Observed(transport.clone()));
    let operation = context.parent().map(|_| ()).map_err(Failure::from);
    let failure = match context.complete(operation) {
        Err(e) => e,
        Ok(()) => return Err("controlled cleanup failure was not surfaced".into()),
    };
    let actual = transport.borrow();
    let reason = if input.mode == "fault-absence" {
        "controlled reported absence failure after actual verified flush"
    } else {
        "controlled reported close failure after actual close"
    };
    if !failure.cleanup_failed
        || !failure.message.contains(reason)
        || actual.flushes != 1
        || actual.absences != 1
        || !actual.closed
    {
        return Err(failure);
    }
    let mut continued = false;
    let failure = failure.rollback(|| {
        continued = true;
        Err("forbidden destructive continuation".into())
    });
    if continued {
        return Err("fatal cleanup permitted destructive continuation".into());
    }
    report["controlled_only_after_real_release"] = json!(true);
    report["actual_transient_flushes"] = json!(actual.flushes);
    report["actual_absence_checks"] = json!(actual.absences);
    report["actual_context_closed"] = json!(actual.closed);
    report["destructive_continuation"] = json!(false);
    Err(failure)
}
fn run(input: &Input, report: &mut Value) -> Outcome<()> {
    if input.mode.starts_with("fault-") {
        return fault(input, report);
    }
    if input.mode == "absence" {
        pcp::absence(&input.name)?;
        report["key_absent"] = json!(true);
        match Root::open(&[&input.namespace], RootMode::Existing) {
            Err(FsError::Native(MISSING)) => report["root_absent"] = json!(true),
            Err(e) => return fs(Err(e)),
            Ok(_) => report["root_absent"] = json!(false),
        }
        return Ok(());
    }
    if input.mode == "remove-root" {
        cleanup(
            fs(Root::open(&[&input.namespace], RootMode::Delete))
                .and_then(|r| fs(r.remove_empty())),
        )?;
        return Ok(());
    }
    if input.mode.starts_with("create-") {
        pcp::absence(&input.name)?;
        let store = input.store(true)?;
        report["root_created_exclusively"] = json!(true);
        let result = store.create(&input.name);
        if input.mode == "create-rollback" {
            denied(
                result,
                &["controlled ordinary creator failure after receipt"],
            )?;
            pcp::absence(&input.name)?;
            match store.root.open_enrollment(&input.name) {
                Err(FsError::Native(MISSING)) => report["creator_rollback_verified"] = json!(true),
                Err(e) => return fs(Err(e)),
                Ok(_) => return Err("rollback left enrollment state".into()),
            }
        } else {
            let identity = result?;
            report["expected_identity_hex"] = json!(hex(&identity.bytes()));
            report["retained_stage"] = json!(input.mode.strip_prefix("create-").unwrap());
        }
        return Ok(());
    }
    if input.mode == "unwrap" {
        return request_roundtrip::roundtrip(input, input.expected()?);
    }
    let expected = input.expected()?;
    let store = input.store(false)?;
    match input.mode.as_str() {
        "inspect" => {
            let value: Value = serde_json::from_slice(&store.inspect(expected)?)
                .map_err(|_| "invalid public inspection")?;
            if value["seed_relation_checked"] != false || value["attestation"] != false {
                return Err("inspection assurance classification changed".into());
            }
            report["public_inspection"] = value;
        }
        "recover" => {
            let identity = store.recover(&input.name)?;
            if &identity != expected {
                return Err("explicit recovery produced a different public reference".into());
            }
            report["expected_identity_hex"] = json!(hex(&identity.bytes()));
            report["recovery_authority"] =
                json!("new expectation from protected receipt; no prior continuity claim");
        }
        "denials" => checks(&store, expected, report)?,
        "replace-pcp" => {
            pcp::delete_matching(expected.name(), point(expected))?;
            let replacement = pcp::Owned::create(expected.name())?;
            let check = denied(
                pcp::Existing::open(expected.name(), point(expected)).map_err(Failure::from),
                &["actual PCP public identity changed"],
            );
            Failure::complete(check, replacement.cleanup())?;
            report["replacement_rejected_and_deleted"] = json!(true);
        }
        "delete" => store.delete(expected)?,
        _ => return Err("unsupported native-test operation".into()),
    }
    Ok(())
}
#[test]
fn isolated_namespace_rejects_production_paths_uppercase_and_unbounded_names() {
    namespace("age-tpm-wsl-pq-native-0123456789abcdef0123456789abcdef").unwrap();
    for value in [
        "age-plugin-tpm-wsl",
        "custody/v1",
        "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef",
        "age-tpm-wsl-pq-native-0123456789ABCDEF0123456789abcdef",
        "age-tpm-wsl-pq-native-../x",
    ] {
        assert!(namespace(value).is_err());
    }
}
#[test]
fn p256_generator_fixture_is_the_sec2_base_point() {
    let expected: Vec<u8> = (0..65)
        .map(|i| u8::from_str_radix(&"046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    assert_eq!(GENERATOR.as_slice(), expected.as_slice());
}
#[test]
fn native_input_requires_explicit_operations_and_retained_public_authority() {
    let ns = "age-tpm-wsl-pq-native-0123456789abcdef0123456789abcdef".to_owned();
    assert!(Input::parse("unknown".into(), ns.clone(), None).is_err());
    assert!(Input::parse("delete".into(), ns.clone(), None).is_err());
    assert!(Input::parse("recover".into(), ns.clone(), Some("00".repeat(1300))).is_err());
    assert!(Input::parse("create-final".into(), ns, None).is_ok());
}
#[test]
#[ignore = "requires reviewed driver, explicit disposable acknowledgment and fresh isolated Windows namespace"]
fn isolated_native_case() {
    let mut report = json!({"result":"fail", "cleanup_failed":false, "scope":"ignored Windows test-only isolated Store; no production root access"});
    let outcome = (|| -> Outcome<()> {
        if std::env::var("ATW_PQ_NATIVE_ACK").as_deref() != Ok(ACK) {
            return Err("explicit isolated disposable acknowledgment required".into());
        }
        let input = Input::parse(
            std::env::var("ATW_PQ_NATIVE_MODE").map_err(|_| "explicit native mode required")?,
            std::env::var("ATW_PQ_NATIVE_NAMESPACE")
                .map_err(|_| "fresh native namespace required")?,
            std::env::var("ATW_PQ_NATIVE_EXPECTED").ok(),
        )?;
        report["operation"] = json!(input.mode);
        report["namespace"] = json!(input.namespace);
        report["name"] = json!(input.name);
        run(&input, &mut report)
    })();
    let mut exit = 0;
    match outcome {
        Ok(()) => report["result"] = json!("pass"),
        Err(failure) => {
            report["error"] = json!(failure.message);
            report["cleanup_failed"] = json!(failure.cleanup_failed);
            exit = if failure.cleanup_failed { 97 } else { 1 };
            if report["controlled_only_after_real_release"] == true {
                report["result"] = json!("controlled_failure");
            }
        }
    }
    println!("{REPORT}{}", serde_json::to_string(&report).unwrap());
    std::io::stdout().flush().unwrap();
    if exit != 0 {
        std::process::exit(exit);
    }
}
