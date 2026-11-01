//! The verified directory handle carries storage authority throughout each call.
use super::*;
use windows_custody_fs::{Enrollment, Error as FsError, Root, RootMode, Slot};
const ROOT: &[&str] = &["age-plugin-tpm-wsl", "custody", "v1"];
const MISSING: i32 = 0xc0000034u32 as i32;
fn fs<T>(value: windows_custody_fs::Result<T>) -> Outcome<T> {
    value.map_err(|error| Failure {
        cleanup_failed: matches!(error, FsError::Cleanup { .. }),
        kind: super::lifecycle::FailureKind::Operational,
        message: error.to_string(),
    })
}
fn receipt(enrollment: &Enrollment<'_>, expected: &Identity) -> Outcome<()> {
    if fs(enrollment.read(Slot::Receipt))? != expected.bytes() {
        return Err("receipt differs from expected post-quantum identity".into());
    }
    Ok(())
}
fn record(bytes: &[u8], expected: &Identity) -> Outcome<Record> {
    Record::parse(bytes, expected).map_err(|_| "invalid expected custody record".into())
}
fn remove_if_present(enrollment: &Enrollment<'_>, slot: Slot) -> Outcome<()> {
    match enrollment.remove_file(slot) {
        Ok(()) | Err(FsError::Native(MISSING)) => Ok(()),
        Err(error) => fs(Err(error)),
    }
}
pub(crate) struct Store {
    root: Root,
    #[cfg(test)]
    control: Option<native_tests::Checkpoint>,
}
impl Store {
    /// A verified directory handle carries storage authority. Callers choose
    /// its location before constructing the store; requests carry no path.
    pub(crate) fn from_verified_root(root: Root) -> Self {
        Self {
            root,
            #[cfg(test)]
            control: None,
        }
    }
    pub(super) fn create_root() -> Outcome<Self> {
        Ok(Self::from_verified_root(fs(Root::open(
            ROOT,
            RootMode::CreateMissing,
        ))?))
    }
    pub(super) fn existing() -> Outcome<Self> {
        Ok(Self::from_verified_root(fs(Root::open(
            ROOT,
            RootMode::Existing,
        ))?))
    }
    pub(super) fn create(&self, name: &str) -> Outcome<Identity> {
        age_tpm_wsl_post_quantum::validate_name(name)
            .map_err(|_| "invalid dedicated post-quantum name")?;
        let enrollment = fs(self.root.create(name))?;
        let mut original = Some(enrollment);
        let mut owned = None;
        let mut written = Vec::new();
        let operation = (|| -> Outcome<Identity> {
            owned = Some(pcp::Owned::create(name)?);
            let enrollment = original
                .as_ref()
                .ok_or("missing original enrollment handle")?;
            let key = owned.as_ref().ok_or("missing creator handle")?;
            let seed = random::<64>()?;
            let private = restore(&seed)?;
            let identity = Identity::new(&public(&private, key.point())?, name)
                .map_err(|_| "invalid created post-quantum identity")?;
            // Known slots remain owned even when write/flush fails after creation.
            written.push(Slot::Receipt);
            fs(enrollment.write_new(Slot::Receipt, &identity.bytes()))?;
            #[cfg(test)]
            match self.control {
                Some(native_tests::Checkpoint::Rollback) => {
                    return Err("controlled ordinary creator failure after receipt".into());
                }
                Some(native_tests::Checkpoint::Receipt) => return Ok(identity),
                _ => (),
            }
            let bytes = seal(&seed, &identity)?.encode();
            #[cfg(test)]
            let bytes = if matches!(self.control, Some(native_tests::Checkpoint::Partial)) {
                bytes[..bytes.len() - 1].to_vec()
            } else {
                bytes
            };
            drop(private);
            drop(seed);
            written.push(Slot::Pending);
            fs(enrollment.write_new(Slot::Pending, &bytes))?;
            #[cfg(test)]
            if matches!(
                self.control,
                Some(native_tests::Checkpoint::Pending | native_tests::Checkpoint::Partial)
            ) {
                return Ok(identity);
            }
            let pending = fs(enrollment.read(Slot::Pending))?;
            verify(&record(&pending, &identity)?)?;
            // Rename may succeed before its flush/reopen check fails.
            written.push(Slot::Final);
            let committed = fs(enrollment.commit_pending(&pending))?;
            written.retain(|slot| !matches!(slot, Slot::Pending));
            record(&committed, &identity)?;
            receipt(enrollment, &identity)?;
            verify(&record(&fs(enrollment.read(Slot::Final))?, &identity)?)?;
            Ok(identity)
        })();
        match operation {
            Ok(identity) => {
                owned.take().ok_or("missing creator handle")?.retain();
                Ok(identity)
            }
            Err(operation) => {
                let failure = operation.rollback(|| {
                    if let Some(key) = owned.take() {
                        key.cleanup()?;
                    }
                    if let Some(enrollment) = original.take() {
                        for slot in written {
                            remove_if_present(&enrollment, slot)?;
                        }
                        fs(enrollment.remove_empty())?;
                        match self.root.open_enrollment(name) {
                            Err(FsError::Native(MISSING)) => (),
                            Err(error) => return fs(Err(error)),
                            Ok(_) => return Err("rollback enrollment absence not verified".into()),
                        }
                    }
                    Ok(())
                });
                Err(failure)
            }
        }
    }
    pub(super) fn unwrap(
        &self,
        expected: &Identity,
        enc: &[u8],
        body: &[u8],
    ) -> Outcome<Zeroizing<Vec<u8>>> {
        let enrollment = fs(self.root.open_enrollment(expected.name()))?;
        receipt(&enrollment, expected)?;
        // Decryption reads final state only; it cannot commit or repair pending.
        open(
            &record(&fs(enrollment.read(Slot::Final))?, expected)?,
            enc,
            body,
        )
    }
    pub(super) fn recover(&self, name: &str) -> Outcome<Identity> {
        // Explicit name-only recovery establishes a new public expectation.
        self.recover_authorized(name, None)
    }
    pub(crate) fn recover_authorized(
        &self,
        name: &str,
        expected: Option<&Identity>,
    ) -> Outcome<Identity> {
        age_tpm_wsl_post_quantum::validate_name(name)
            .map_err(|_| "invalid dedicated post-quantum name")?;
        let enrollment = fs(self.root.open_enrollment(name))?;
        let stored_receipt = fs(enrollment.read(Slot::Receipt))?;
        super::recovery::with_receipt(&stored_receipt, name, expected, |identity| {
            // Receipt authority is resolved before private verification or a
            // pending-record commit, using the same retained directory handle.
            let (bytes, pending) = match enrollment.read(Slot::Final) {
                Ok(bytes) => (bytes, false),
                Err(FsError::Native(MISSING)) => (fs(enrollment.read(Slot::Pending))?, true),
                Err(error) => return fs(Err(error)),
            };
            verify(&record(&bytes, &identity)?)?;
            if pending {
                let committed = fs(enrollment.commit_pending(&bytes))?;
                verify(&record(&committed, &identity)?)?;
            }
            receipt(&enrollment, &identity)?;
            Ok(identity)
        })
    }
    pub(super) fn inspect(&self, expected: &Identity) -> Outcome<Vec<u8>> {
        let enrollment = fs(self.root.open_enrollment(expected.name()))?;
        receipt(&enrollment, expected)?;
        record(&fs(enrollment.read(Slot::Final))?, expected)?;
        let _key = pcp::Existing::open(expected.name(), point(expected))?;
        serde_json::to_vec(&serde_json::json!({
            "provider": "Microsoft Platform Crypto Provider", "hardware": true,
            "name": expected.name(), "scheme": "mlkem768-p256", "export_policy": 0,
            "attestation": false, "seed_relation_checked": false,
            "custody": "canonical final record and actual PCP point match the expected identity",
            "limits": "hardware flags and zero export policy are not individual-key attestation or enforced export/usage assurance"
        })).map_err(|_| "post-quantum inspection encoding failed".into())
    }
    pub(super) fn delete(&self, expected: &Identity) -> Outcome<()> {
        let deletion = fs(self.root.open_for_delete(expected.name()))?;
        receipt(&deletion, expected)?;
        pcp::delete_matching(expected.name(), point(expected))?;
        // After authorized deletion begins, any failure is a cleanup failure.
        let cleanup = (|| -> Outcome<()> {
            for slot in [Slot::Pending, Slot::Final, Slot::Receipt] {
                remove_if_present(&deletion, slot)?;
            }
            fs(deletion.remove_empty())?;
            match self.root.open_enrollment(expected.name()) {
                Err(FsError::Native(MISSING)) => Ok(()),
                Err(error) => fs(Err(error)),
                Ok(_) => Err("deleted enrollment absence not verified".into()),
            }
        })();
        Failure::complete(Ok(()), cleanup.map_err(|failure| failure.message))
    }
}

#[cfg(test)]
mod native_tests;
