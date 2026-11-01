//! Application format identifiers shared by the plugin and Windows helper.
//! These values are wire contracts; changing one requires a new format.

/// P-256 recipient format version followed by the plugin's big-endian suite ID.
/// The suite selects the complete fixed construction; it is not an RFC KDF ID.
pub const P256_RECIPIENT_PREFIX: [u8; 3] = [2, 0, 1];
/// Suite selector used by the helper's create-scheme operation.
pub const P256_SUITE_ID: [u8; 2] = [P256_RECIPIENT_PREFIX[1], P256_RECIPIENT_PREFIX[2]];
pub const HPKE_RECIPIENT_LEN: usize = P256_RECIPIENT_PREFIX.len() + 65;
pub const HPKE_TAG: &str = "tpm-wsl-hpke";
pub const HPKE_STANZA_VERSION: &str = "2";
/// The terminating NUL separates this domain from the canonical recipient.
pub const HPKE_INFO_PREFIX: &[u8] = b"age-plugin-tpm-wsl/HPKE-v2\0";

/// Complete fixed MLKEM768-P256 suite selected by post-quantum enrollment operation 8.
pub const POST_QUANTUM_SUITE_ID: [u8; 2] = [0, 2];
