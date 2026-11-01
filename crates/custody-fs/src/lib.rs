//! Handle-relative Windows filesystem operations for a bounded custody store.
//!
//! This isolated module stores public receipts and encrypted TPM blobs. The caller
//! must validate the independently retained identity before private operations or
//! deletion. Filesystem permissions do not protect against the allowed live user
//! or an administrator. A successful flush/rename is not a power-loss proof.

use std::fmt;

pub const MAX_FILE: usize = 4096;

#[derive(Debug)]
pub enum Error {
    Invalid(&'static str),
    Windows(u32),
    Native(i32),
    Io(std::io::Error),
    Cleanup {
        operation: Box<Error>,
        cleanup: Box<Error>,
    },
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::Windows(code) => write!(f, "Windows filesystem status {code}"),
            Self::Native(code) => write!(f, "Native filesystem status 0x{:08x}", *code as u32),
            Self::Io(error) => write!(f, "Filesystem I/O status {:?}", error.raw_os_error()),
            Self::Cleanup { operation, cleanup } => {
                write!(f, "{operation}; owned-object cleanup failed: {cleanup}")
            }
        }
    }
}
impl std::error::Error for Error {}
impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}
pub type Result<T> = std::result::Result<T, Error>;

/// The complete set of filenames available to custody lifecycle operations.
#[derive(Clone, Copy, Debug)]
pub enum Slot {
    Receipt,
    Pending,
    Final,
}
impl Slot {
    pub fn name(self) -> &'static str {
        match self {
            Self::Receipt => "receipt.bin",
            Self::Pending => "pending.bin",
            Self::Final => "custody.bin",
        }
    }
}

/// Opening an existing root never creates or repairs directories.
#[derive(Clone, Copy, Debug)]
pub enum RootMode {
    Existing,
    CreateMissing,
    /// Create the final root exclusively; used for a new owned disposable namespace.
    CreateNew,
    /// Acquires DELETE on the final root only; fail if other retained handles conflict.
    Delete,
}

#[cfg(any(windows, test))]
fn component(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 96
        || !value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Invalid("invalid storage component"));
    }
    Ok(())
}

#[cfg(any(windows, test))]
fn enrollment(value: &str) -> Result<()> {
    let suffix = value
        .strip_prefix("age-tpm-wsl-pq-")
        .ok_or(Error::Invalid("invalid PQ enrollment name"))?;
    if suffix.len() != 32
        || !suffix
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Invalid("invalid PQ enrollment name"));
    }
    Ok(())
}

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::{Enrollment, Root};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_components_reject_paths_streams_and_namespace_escapes() {
        for value in [
            "", ".", "..", "a/b", "a\\b", "a:b", "a\0b", "a.", "a ", "A", "\\??\\C:", "a*b",
        ] {
            assert!(component(value).is_err(), "{value:?}");
        }
        assert!(component(&"a".repeat(97)).is_err());
        for value in [
            "age-plugin-tpm-wsl",
            "custody",
            "v1",
            "age-tpm-wsl-fs-0123456789abcdef",
        ] {
            component(value).unwrap();
        }
    }

    #[test]
    fn enrollment_requires_the_dedicated_pq_namespace() {
        enrollment("age-tpm-wsl-pq-0123456789abcdef0123456789abcdef").unwrap();
        for value in [
            "age-tpm-wsl-0123456789abcdef0123456789abcdef",
            "age-tpm-wsl-pq-0123456789ABCDEF0123456789abcdef",
            "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef/receipt.bin",
            "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef:stream",
            "age-tpm-wsl-pq-0123456789abcdef0123456789abcdeg",
        ] {
            assert!(enrollment(value).is_err(), "{value:?}");
        }
    }
}
