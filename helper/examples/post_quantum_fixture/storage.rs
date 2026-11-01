//! One verified reserved directory; no production path or arbitrary path input.
#![forbid(unsafe_code)]
use super::arguments::Namespace;
use crate::post_quantum::{
    dispatch::StoreLocation,
    lifecycle::{Failure, FailureKind, Outcome},
    pcp,
    store::Store,
};
use serde_json::{Value, json};
use windows_custody_fs::{Error, Root, RootMode};

const MISSING: i32 = 0xc0000034u32 as i32;
fn checked<T>(value: windows_custody_fs::Result<T>) -> Outcome<T> {
    value.map_err(|error| Failure {
        cleanup_failed: matches!(error, Error::Cleanup { .. }),
        kind: FailureKind::Operational,
        message: error.to_string(),
    })
}

pub struct IsolatedLocation<'a>(pub &'a Namespace);
impl IsolatedLocation<'_> {
    fn open(&self, mode: RootMode) -> Outcome<Root> {
        checked(Root::open(&[self.0.directory()], mode))
    }

    /// Establish root ownership before key creation. The controller journals
    /// this successful public receipt before allowing an ATW1 create request.
    pub fn prepare(&self) -> Outcome<Value> {
        pcp::absence(self.0.key_name())?;
        self.open(RootMode::CreateNew)?;
        Ok(json!({
            "root_created_exclusively": true,
            "namespace": self.0.directory(),
            "name": self.0.key_name()
        }))
    }

    pub fn absence(&self) -> Outcome<Value> {
        pcp::absence(self.0.key_name())?;
        let root_absent = match Root::open(&[self.0.directory()], RootMode::Existing) {
            Err(Error::Native(MISSING)) => true,
            Ok(_) => false,
            Err(error) => return checked(Err(error)),
        };
        Ok(json!({ "key_absent": true, "root_absent": root_absent }))
    }

    /// Arguments already require the retained full identity. The controller
    /// must also hold the exclusive-root receipt. Never remove a nonempty root
    /// or a root while its derived dedicated key still exists.
    pub fn remove_root(&self) -> Outcome<Value> {
        let cleanup = (|| -> Outcome<()> {
            pcp::absence(self.0.key_name())?;
            checked(self.open(RootMode::Delete)?.remove_empty())?;
            let result = self.absence()?;
            if result["root_absent"] != true {
                return Err("fixture root absence not verified".into());
            }
            Ok(())
        })();
        Failure::complete(Ok(()), cleanup.map_err(|error| error.message))?;
        Ok(json!({ "key_absent": true, "root_absent": true }))
    }
}
impl StoreLocation for IsolatedLocation<'_> {
    fn for_creation(&self) -> Outcome<Store> {
        // Root preparation is a separate explicit operation so its exclusive
        // ownership receipt can be retained before any persistent key exists.
        self.existing()
    }
    fn existing(&self) -> Outcome<Store> {
        Ok(Store::from_verified_root(self.open(RootMode::Existing)?))
    }
}
