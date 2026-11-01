//! CNG adapter. All FFI buffers remain alive for each synchronous call.
use crate::key_format;
use age_plugin_tpm_wsl::{Identity, LABEL, PublicKey, Recipient, Scheme, schemes, validate_name};
use std::ptr::null;
use windows_sys::{
    Win32::Security::Cryptography::*,
    core::{PCWSTR, w},
};
use zeroize::Zeroizing;

pub type Result<T> = std::result::Result<T, u32>;
pub const INVALID: u32 = 0xA0010001;
pub const CLEANUP_FAILED: u32 = 0xA0010002;
const BAD_KEYSET: u32 = 0x80090016;
const PROVIDER: &str = "Microsoft Platform Crypto Provider";

fn check(status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(status as u32)
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}

struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: this adapter owns the live handle and frees it once.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
impl Handle {
    fn delete(mut self) -> Result<()> {
        // SAFETY: self owns the live key; successful deletion also releases it.
        // PCP rejects NCRYPT_SILENT_FLAG on deletion with NTE_BAD_FLAGS.
        // Deletion is an explicit operator action; zero is the supported flags value.
        check(unsafe { NCryptDeleteKey(self.0, 0) })?;
        self.0 = 0;
        Ok(())
    }
}

fn property(handle: usize, name: PCWSTR, maximum: usize) -> Result<Vec<u8>> {
    let mut output = vec![0; maximum];
    let mut length = 0;
    // SAFETY: output is a writable buffer with the stated capacity; name is a static CNG string.
    check(unsafe {
        NCryptGetProperty(
            handle,
            name,
            output.as_mut_ptr(),
            maximum as u32,
            &mut length,
            0,
        )
    })?;
    if length == 0 || length as usize > maximum {
        return Err(INVALID);
    }
    output.truncate(length as usize);
    Ok(output)
}
fn dword(handle: usize, name: PCWSTR) -> Result<u32> {
    let bytes = property(handle, name, 4)?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| INVALID)?))
}
fn string_property(handle: usize, name: PCWSTR) -> Result<String> {
    let bytes = property(handle, name, 1024)?;
    if bytes.len() % 2 != 0 {
        return Err(INVALID);
    }
    let mut units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    if units.pop() != Some(0) || units.contains(&0) {
        return Err(INVALID);
    }
    String::from_utf16(&units).map_err(|_| INVALID)
}
fn set_dword(handle: usize, name: PCWSTR, value: u32) -> Result<()> {
    let bytes = value.to_le_bytes();
    // SAFETY: fixed four-byte input remains alive and names are static CNG strings.
    check(unsafe { NCryptSetProperty(handle, name, bytes.as_ptr(), 4, 0) })
}

fn software_export_control(scheme: Scheme) -> Result<serde_json::Value> {
    let mut provider = 0;
    // SAFETY: writes one provider handle using a static terminated name.
    check(unsafe {
        NCryptOpenStorageProvider(
            &mut provider,
            w!("Microsoft Software Key Storage Provider"),
            0,
        )
    })?;
    let provider = Handle(provider);
    let mut key = 0;
    // SAFETY: a null name creates an ephemeral control key; it is never persisted.
    check(unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut key,
            match scheme {
                Scheme::Rsa2048 => BCRYPT_RSA_ALGORITHM,
                Scheme::P256Hpke => BCRYPT_ECDH_P256_ALGORITHM,
            },
            null(),
            0,
            0,
        )
    })?;
    let key = Handle(key);
    if scheme == Scheme::Rsa2048 {
        set_dword(key.0, NCRYPT_LENGTH_PROPERTY, 2048)?;
    }
    set_dword(
        key.0,
        NCRYPT_EXPORT_POLICY_PROPERTY,
        NCRYPT_ALLOW_EXPORT_FLAG | NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG,
    )?;
    // SAFETY: initialized ephemeral key is live.
    check(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
    let mut results = vec![];
    let formats = match scheme {
        Scheme::Rsa2048 => vec![
            (
                "RSAPRIVATEBLOB",
                BCRYPT_RSAPRIVATE_BLOB,
                BCRYPT_RSAPRIVATE_MAGIC,
            ),
            (
                "RSAFULLPRIVATEBLOB",
                BCRYPT_RSAFULLPRIVATE_BLOB,
                BCRYPT_RSAFULLPRIVATE_MAGIC,
            ),
        ],
        Scheme::P256Hpke => vec![(
            "ECCPRIVATEBLOB",
            BCRYPT_ECCPRIVATE_BLOB,
            BCRYPT_ECDH_PRIVATE_P256_MAGIC,
        )],
    };
    for (name, format, magic) in formats {
        let mut output = Zeroizing::new(vec![0; 8192]);
        let mut length = 0;
        // SAFETY: valid control key, bounded writable output, no export wrapping key.
        check(unsafe {
            NCryptExportKey(
                key.0,
                0,
                format,
                null(),
                output.as_mut_ptr(),
                output.len() as u32,
                &mut length,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        if length < 24
            || length as usize > output.len()
            || u32::from_le_bytes(output[..4].try_into().unwrap()) != magic
        {
            return Err(INVALID);
        }
        results.push(serde_json::json!({"format": name, "status": "0x00000000", "result": "pass", "returned_length": length}));
    }
    Ok(
        serde_json::json!({"provider": "Microsoft Software Key Storage Provider", "ephemeral": true, "exports": results}),
    )
}

pub struct Provider {
    handle: Handle,
    flags: u32,
}
impl Provider {
    pub fn open() -> Result<Self> {
        let mut handle = 0;
        // SAFETY: writes one handle; provider name is static and terminated.
        check(unsafe {
            NCryptOpenStorageProvider(&mut handle, w!("Microsoft Platform Crypto Provider"), 0)
        })?;
        let handle = Handle(handle);
        let flags = dword(handle.0, NCRYPT_IMPL_TYPE_PROPERTY)?;
        if flags & NCRYPT_IMPL_HARDWARE_FLAG == 0
            || string_property(handle.0, NCRYPT_NAME_PROPERTY)? != PROVIDER
        {
            return Err(INVALID);
        }
        Ok(Self { handle, flags })
    }
    fn open_key(&self, name: &str) -> Result<Handle> {
        validate_name(name).map_err(|_| INVALID)?;
        let name = wide(name);
        let mut key = 0;
        // SAFETY: provider is live, name is terminated and output points to a handle slot.
        check(unsafe {
            NCryptOpenKey(
                self.handle.0,
                &mut key,
                name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        Ok(Handle(key))
    }
    pub fn absence(&self, name: &str) -> Result<()> {
        match self.open_key(name) {
            Err(BAD_KEYSET) => Ok(()),
            Err(code) => Err(code),
            Ok(_) => Err(CLEANUP_FAILED),
        }
    }
    fn public_key(&self, key: &Handle) -> Result<Recipient> {
        let algorithm = string_property(key.0, NCRYPT_ALGORITHM_PROPERTY)?;
        if key_format::is_ecdh(&algorithm) {
            let mut blob = [0u8; 72];
            let mut length = 0;
            // SAFETY: owned key and exact bounded ECC public output.
            check(unsafe {
                NCryptExportKey(
                    key.0,
                    0,
                    BCRYPT_ECCPUBLIC_BLOB,
                    null(),
                    blob.as_mut_ptr(),
                    blob.len() as u32,
                    &mut length,
                    NCRYPT_SILENT_FLAG,
                )
            })?;
            if length as usize != blob.len() {
                return Err(INVALID);
            }
            return key_format::p256_recipient(&algorithm, &blob).map_err(|_| INVALID);
        }
        if string_property(key.0, NCRYPT_ALGORITHM_PROPERTY)? != "RSA" {
            return Err(INVALID);
        }
        let mut blob = [0u8; 1024];
        let mut length = 0;
        // SAFETY: key is live; bounded output and length are writable; no export wrapping key is used.
        check(unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_RSAPUBLIC_BLOB,
                null(),
                blob.as_mut_ptr(),
                blob.len() as u32,
                &mut length,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        if length != 24 + 3 + 256 {
            return Err(INVALID);
        }
        let field = |offset| u32::from_le_bytes(blob[offset..offset + 4].try_into().unwrap());
        if field(0) != BCRYPT_RSAPUBLIC_MAGIC
            || field(4) != 2048
            || field(8) != 3
            || field(12) != 256
            || field(16) != 0
            || field(20) != 0
            || blob[24..27] != [1, 0, 1]
        {
            return Err(INVALID);
        }
        let mut bytes = vec![1];
        bytes.extend(&blob[27..283]);
        Recipient::parse(&bytes).map_err(|_| INVALID)
    }
    fn validate(&self, key: &Handle, expected: Option<&Identity>, name: &str) -> Result<Recipient> {
        let algorithm = string_property(key.0, NCRYPT_ALGORITHM_PROPERTY)?;
        if algorithm != "RSA" && !key_format::is_ecdh(&algorithm)
            || (algorithm == "RSA"
                && (dword(key.0, NCRYPT_LENGTH_PROPERTY)? != 2048
                    || dword(key.0, NCRYPT_KEY_USAGE_PROPERTY)? & NCRYPT_ALLOW_DECRYPT_FLAG == 0))
            || dword(key.0, NCRYPT_EXPORT_POLICY_PROPERTY)? != 0
            || string_property(key.0, NCRYPT_NAME_PROPERTY)? != name
        {
            return Err(INVALID);
        }
        let bytes = property(
            key.0,
            NCRYPT_PROVIDER_HANDLE_PROPERTY,
            std::mem::size_of::<usize>(),
        )?;
        let provider = Handle(usize::from_le_bytes(bytes.try_into().map_err(|_| INVALID)?));
        // CNG transfers ownership of the provider-handle property to the caller.
        if string_property(provider.0, NCRYPT_NAME_PROPERTY)? != PROVIDER
            || dword(provider.0, NCRYPT_IMPL_TYPE_PROPERTY)? & NCRYPT_IMPL_HARDWARE_FLAG == 0
        {
            return Err(INVALID);
        }
        let public = self.public_key(key)?;
        if expected.is_some_and(|identity| identity.recipient.key != public.key) {
            return Err(INVALID);
        }
        Ok(public)
    }
    pub fn create(&self, name: &str, scheme: Scheme) -> Result<Identity> {
        validate_name(name).map_err(|_| INVALID)?;
        let key_name = wide(name);
        let mut handle = 0;
        // SAFETY: output is a handle slot; no overwrite/machine flags are set.
        check(unsafe {
            NCryptCreatePersistedKey(
                self.handle.0,
                &mut handle,
                match scheme {
                    Scheme::Rsa2048 => BCRYPT_RSA_ALGORITHM,
                    Scheme::P256Hpke => BCRYPT_ECDH_P256_ALGORITHM,
                },
                key_name.as_ptr(),
                0,
                0,
            )
        })?;
        let mut key = Some(Handle(handle));
        let result = (|| {
            let handle = key.as_ref().unwrap().0;
            if scheme == Scheme::Rsa2048 {
                set_dword(handle, NCRYPT_LENGTH_PROPERTY, 2048)?;
                set_dword(handle, NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_DECRYPT_FLAG)?;
            }
            // PCP rejects explicit key-agreement usage for ECDH on the tested TPM.
            set_dword(handle, NCRYPT_EXPORT_POLICY_PROPERTY, 0)?;
            let policy = NCRYPT_UI_POLICY {
                dwVersion: 1,
                dwFlags: 0,
                pszCreationTitle: null(),
                pszFriendlyName: null(),
                pszDescription: null(),
            };
            // SAFETY: policy has the SDK layout and remains alive during this synchronous call.
            check(unsafe {
                NCryptSetProperty(
                    handle,
                    NCRYPT_UI_POLICY_PROPERTY,
                    (&policy as *const NCRYPT_UI_POLICY).cast(),
                    std::mem::size_of::<NCRYPT_UI_POLICY>() as u32,
                    0,
                )
            })?;
            // SAFETY: key is live and initialized; silent mode rejects required UI.
            check(unsafe { NCryptFinalizeKey(handle, NCRYPT_SILENT_FLAG) })?;
            let recipient = self.validate(key.as_ref().unwrap(), None, name)?;
            if recipient.scheme() != scheme {
                return Err(INVALID);
            }
            // Retain the owned handle for failure cleanup while checking persistence.
            let identity = Identity {
                recipient,
                name: name.into(),
            };
            let reopened = self.open_key(name)?;
            self.validate(&reopened, Some(&identity), name)?;
            if let PublicKey::P256(point) = &identity.recipient.key {
                // Verify actual agreement capability; PCP length/usage properties are insufficient.
                let _secret = self.agree(&identity, point)?;
            }
            Ok(identity)
        })();
        if result.is_err() {
            let cleanup = match key.take() {
                Some(key) => key.delete(),
                None => Err(CLEANUP_FAILED),
            };
            if cleanup.is_err() || self.absence(name).is_err() {
                eprintln!("cleanup failed for newly created key {name}");
                return Err(CLEANUP_FAILED);
            }
        }
        result
    }
    pub fn recover(&self, name: &str) -> Result<Identity> {
        let key = self.open_key(name)?;
        let recipient = self.validate(&key, None, name)?;
        Ok(Identity {
            recipient,
            name: name.into(),
        })
    }
    pub fn delete(&self, identity: &Identity) -> Result<()> {
        let key = self.open_key(&identity.name)?;
        self.validate(&key, Some(identity), &identity.name)?;
        key.delete()?;
        self.absence(&identity.name)
    }
    pub fn inspect(&self, identity: &Identity) -> Result<Vec<u8>> {
        let key = self.open_key(&identity.name)?;
        self.validate(&key, Some(identity), &identity.name)?;
        use windows_sys::Win32::System::TpmBaseServices::{
            TPM_DEVICE_INFO, TPM_VERSION_20, Tbsi_GetDeviceInfo,
        };
        let mut device = TPM_DEVICE_INFO::default();
        // SAFETY: SDK-layout structure is writable with its exact size.
        let status = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
                (&mut device as *mut TPM_DEVICE_INFO).cast(),
            )
        };
        if status != 0 {
            return Err(status);
        }
        if device.structVersion != 1 || device.tpmVersion != TPM_VERSION_20 {
            return Err(INVALID);
        }
        let mut exports = vec![];
        let formats = match identity.recipient.scheme() {
            Scheme::Rsa2048 => vec![
                ("RSAPRIVATEBLOB", BCRYPT_RSAPRIVATE_BLOB),
                ("RSAFULLPRIVATEBLOB", BCRYPT_RSAFULLPRIVATE_BLOB),
            ],
            Scheme::P256Hpke => vec![("ECCPRIVATEBLOB", BCRYPT_ECCPRIVATE_BLOB)],
        };
        for (name, format) in formats {
            let mut output = Zeroizing::new(vec![0; 8192]);
            let mut length = 0;
            // SAFETY: key is live and output is bounded. Unexpected private material is wiped.
            let status = unsafe {
                NCryptExportKey(
                    key.0,
                    0,
                    format,
                    null(),
                    output.as_mut_ptr(),
                    output.len() as u32,
                    &mut length,
                    NCRYPT_SILENT_FLAG,
                )
            } as u32;
            if status == 0 {
                return Err(INVALID);
            }
            // NTE_BAD_KEY_STATE can describe an invalid/unfinalized key; it
            // does not distinguish export-policy enforcement from other causes.
            exports.push(serde_json::json!({"format": name, "status": format!("0x{status:08X}"), "result": "inconclusive"}));
        }
        let report = serde_json::json!({
            "provider": PROVIDER, "implementation_flags": self.flags,
            "hardware": true, "algorithm": string_property(key.0, NCRYPT_ALGORITHM_PROPERTY)?,
            "scheme": identity.recipient.scheme().name(),
            "bits": if identity.recipient.scheme() == Scheme::Rsa2048 { 2048 } else { 256 },
            "export_policy": 0, "usage": dword(key.0, NCRYPT_KEY_USAGE_PROPERTY)?,
            "fingerprint": identity.recipient.fingerprint(), "name": identity.name,
            "attestation": false,
            "tbs": {"status": 0, "structure_version": device.structVersion, "tpm_version": device.tpmVersion, "interface_type": device.tpmInterfaceType},
            "private_export_attempts": exports,
            "software_export_positive_control": software_export_control(identity.recipient.scheme())?
        });
        serde_json::to_vec(&report).map_err(|_| INVALID)
    }
    fn agree(&self, identity: &Identity, point: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>> {
        schemes::validate_point(point).map_err(|_| INVALID)?;
        let key = self.open_key(&identity.name)?;
        self.validate(&key, Some(identity), &identity.name)?;
        if identity.recipient.scheme() != Scheme::P256Hpke {
            return Err(INVALID);
        }
        let mut blob = Vec::with_capacity(72);
        blob.extend(BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
        blob.extend(32u32.to_le_bytes());
        blob.extend(&point[1..]);
        let mut peer = 0;
        // SAFETY: same validated PCP provider, canonical public blob and writable handle slot.
        check(unsafe {
            NCryptImportKey(
                self.handle.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                &mut peer,
                blob.as_ptr(),
                blob.len() as u32,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        let peer = Handle(peer);
        let mut secret = 0;
        // SAFETY: live handles from the same PCP provider; silent mode rejects UI.
        check(unsafe { NCryptSecretAgreement(key.0, peer.0, &mut secret, NCRYPT_SILENT_FLAG) })?;
        let secret = Handle(secret);
        let mut raw = Zeroizing::new([0u8; 32]);
        let mut length = 0;
        // SAFETY: owned secret handle and exact output capacity. PCP requires zero derivation flags.
        check(unsafe {
            NCryptDeriveKey(
                secret.0,
                BCRYPT_KDF_RAW_SECRET,
                null(),
                raw.as_mut_ptr(),
                raw.len() as u32,
                &mut length,
                0,
            )
        })?;
        if length != 32 {
            return Err(INVALID);
        }
        // CNG raw ECDH is little-endian; RFC 9180 uses big-endian x-coordinate bytes.
        raw.reverse();
        Ok(raw)
    }

    pub fn unwrap(&self, identity: &Identity, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if identity.recipient.scheme() == Scheme::P256Hpke {
            return schemes::open_p256(&identity.recipient, ciphertext, |point| {
                self.agree(identity, point).map_err(|status| {
                    std::io::Error::other(age_plugin_tpm_wsl::client::HelperFailure(status))
                })
            })
            .map_err(|error| {
                error
                    .get_ref()
                    .and_then(|source| {
                        source.downcast_ref::<age_plugin_tpm_wsl::client::HelperFailure>()
                    })
                    .map_or(INVALID, |source| source.0)
            });
        }
        if ciphertext.len() != 256 {
            return Err(INVALID);
        }
        let key = self.open_key(&identity.name)?;
        self.validate(&key, Some(identity), &identity.name)?;
        let mut label = LABEL.as_bytes().to_vec();
        let padding = BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: label.as_mut_ptr(),
            cbLabel: label.len() as u32,
        };
        // Capacity includes the modulus length. Accept only a complete 16-byte file key.
        let mut output = Zeroizing::new(vec![0; 256]);
        let mut length = 0;
        // SAFETY: ciphertext, padding/label and writable output remain alive with exact stated lengths.
        check(unsafe {
            NCryptDecrypt(
                key.0,
                ciphertext.as_ptr(),
                ciphertext.len() as u32,
                (&padding as *const BCRYPT_OAEP_PADDING_INFO).cast(),
                output.as_mut_ptr(),
                output.len() as u32,
                &mut length,
                NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG,
            )
        })?;
        if length != 16 {
            return Err(INVALID);
        }
        // Copy into a separate wiping allocation; keep unused native buffer bytes wiped on drop.
        Ok(Zeroizing::new(output[..16].to_vec()))
    }
}
