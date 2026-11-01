//! Dedicated PCP operations owned by the Windows post-quantum custody adapter.
//! Never opens a software provider or exports private key bytes.
use super::{
    Result,
    lifecycle::{Failure, Outcome},
};
use crate::key_format;
use age_plugin_tpm_wsl::PublicKey;
use std::ptr::null;
use windows_sys::{
    Win32::Security::Cryptography::*,
    core::{PCWSTR, w},
};
use zeroize::Zeroizing;

const PROVIDER: &str = "Microsoft Platform Crypto Provider";
const BAD_KEYSET: u32 = 0x80090016;
fn check(code: i32) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(format!("PCP status 0x{:08x}", code as u32))
    }
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
struct Handle(usize);
impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: exclusively owned live CNG object; release once.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}
impl Handle {
    fn delete(mut self) -> Result<()> {
        // SAFETY: exclusively owned newly created key. PCP requires zero flags.
        check(unsafe { NCryptDeleteKey(self.0, 0) })?;
        self.0 = 0; // successful deletion also frees the handle
        Ok(())
    }
}
fn property(handle: usize, name: PCWSTR, maximum: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; maximum];
    let mut length = 0;
    // SAFETY: live handle, static name, writable bounded output and length.
    check(unsafe {
        NCryptGetProperty(
            handle,
            name,
            bytes.as_mut_ptr(),
            maximum as u32,
            &mut length,
            0,
        )
    })?;
    if length == 0 || length as usize > maximum {
        return Err("invalid PCP property length".into());
    }
    bytes.truncate(length as usize);
    Ok(bytes)
}
fn dword(handle: usize, name: PCWSTR) -> Result<u32> {
    Ok(u32::from_le_bytes(
        property(handle, name, 4)?
            .try_into()
            .map_err(|_| "invalid DWORD")?,
    ))
}
fn text(handle: usize, name: PCWSTR) -> Result<String> {
    let bytes = property(handle, name, 1024)?;
    if bytes.len() % 2 != 0 {
        return Err("invalid PCP string".into());
    }
    let mut units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    if units.pop() != Some(0) || units.contains(&0) {
        return Err("invalid PCP string terminator".into());
    }
    String::from_utf16(&units).map_err(|_| "invalid PCP UTF16".into())
}
struct Provider(Handle);
impl Provider {
    fn open() -> Result<Self> {
        let mut raw = 0;
        // SAFETY: static terminated provider name and writable handle slot.
        check(unsafe {
            NCryptOpenStorageProvider(&mut raw, w!("Microsoft Platform Crypto Provider"), 0)
        })?;
        let handle = Handle(raw);
        if text(raw, NCRYPT_NAME_PROPERTY)? != PROVIDER
            || dword(raw, NCRYPT_IMPL_TYPE_PROPERTY)? & NCRYPT_IMPL_HARDWARE_FLAG == 0
        {
            return Err("required PCP hardware provider unavailable".into());
        }
        Ok(Self(handle))
    }
    fn open_key_raw(&self, name: &str) -> std::result::Result<Handle, u32> {
        let name = wide(name);
        let mut raw = 0;
        // SAFETY: live provider, terminated validated name, writable handle slot.
        let status =
            unsafe { NCryptOpenKey(self.0.0, &mut raw, name.as_ptr(), 0, NCRYPT_SILENT_FLAG) };
        if status == 0 {
            Ok(Handle(raw))
        } else {
            Err(status as u32)
        }
    }
    fn absence(&self, name: &str) -> Result<()> {
        match self.open_key_raw(name) {
            Err(BAD_KEYSET) => Ok(()),
            Err(code) => Err(format!("PCP absence query failed 0x{code:08x}")),
            Ok(_) => Err("dedicated PCP key still exists".into()),
        }
    }
    fn validate(&self, key: &Handle, name: &str) -> Result<[u8; 65]> {
        let algorithm = text(key.0, NCRYPT_ALGORITHM_PROPERTY)?;
        if !key_format::is_ecdh(&algorithm)
            || text(key.0, NCRYPT_NAME_PROPERTY)? != name
            || dword(key.0, NCRYPT_EXPORT_POLICY_PROPERTY)? != 0
        {
            return Err("PCP identity properties mismatch".into());
        }
        let bytes = property(
            key.0,
            NCRYPT_PROVIDER_HANDLE_PROPERTY,
            std::mem::size_of::<usize>(),
        )?;
        // CNG transfers ownership of the provider-handle property to the caller.
        let provider = Handle(usize::from_le_bytes(
            bytes
                .try_into()
                .map_err(|_| "invalid provider handle size")?,
        ));
        if text(provider.0, NCRYPT_NAME_PROPERTY)? != PROVIDER
            || dword(provider.0, NCRYPT_IMPL_TYPE_PROPERTY)? & NCRYPT_IMPL_HARDWARE_FLAG == 0
        {
            return Err("PCP key provider mismatch".into());
        }
        let mut blob = [0; 72];
        let mut length = 0;
        // SAFETY: live key, static format, exact bounded ECC public output.
        check(unsafe {
            NCryptExportKey(
                key.0,
                0,
                BCRYPT_ECCPUBLIC_BLOB,
                null(),
                blob.as_mut_ptr(),
                72,
                &mut length,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        if length != 72 {
            return Err("invalid PCP public length".into());
        }
        match key_format::p256_recipient(&algorithm, &blob)
            .map_err(|_| "invalid PCP public point")?
            .key
        {
            PublicKey::P256(point) => Ok(point),
            _ => Err("required P256 public key".into()),
        }
    }
}

pub(crate) fn absence(name: &str) -> Result<()> {
    age_tpm_wsl_post_quantum::validate_name(name)
        .map_err(|_| "invalid dedicated post-quantum name")?;
    Provider::open()?.absence(name)
}

pub(super) struct Owned {
    key: Option<Handle>, // free before provider if the caller unwinds
    provider: Provider,
    name: String,
    point: [u8; 65],
}
impl Owned {
    pub(super) fn create(name: &str) -> Outcome<Self> {
        age_tpm_wsl_post_quantum::validate_name(name)
            .map_err(|_| "invalid dedicated post-quantum name")?;
        let provider = Provider::open()?;
        provider.absence(name)?;
        let wide_name = wide(name);
        let mut raw = 0;
        // SAFETY: live provider and terminated name; no overwrite/machine flags.
        check(unsafe {
            NCryptCreatePersistedKey(
                provider.0.0,
                &mut raw,
                BCRYPT_ECDH_P256_ALGORITHM,
                wide_name.as_ptr(),
                0,
                0,
            )
        })?;
        let mut owned = Self {
            key: Some(Handle(raw)),
            provider,
            name: name.into(),
            point: [0; 65],
        };
        let operations = (|| -> Result<()> {
            let policy = 0u32.to_le_bytes();
            // SAFETY: exact four-byte policy remains alive; key was exclusively created.
            check(unsafe {
                NCryptSetProperty(raw, NCRYPT_EXPORT_POLICY_PROPERTY, policy.as_ptr(), 4, 0)
            })?;
            let ui = NCRYPT_UI_POLICY {
                dwVersion: 1,
                dwFlags: 0,
                pszCreationTitle: null(),
                pszFriendlyName: null(),
                pszDescription: null(),
            };
            // SAFETY: SDK-layout policy remains alive for the synchronous call.
            check(unsafe {
                NCryptSetProperty(
                    raw,
                    NCRYPT_UI_POLICY_PROPERTY,
                    (&ui as *const NCRYPT_UI_POLICY).cast(),
                    std::mem::size_of::<NCRYPT_UI_POLICY>() as u32,
                    0,
                )
            })?;
            // SAFETY: initialized live key. Required UI fails rather than prompting.
            check(unsafe { NCryptFinalizeKey(raw, NCRYPT_SILENT_FLAG) })?;
            owned.point = owned
                .provider
                .validate(owned.key.as_ref().ok_or("missing owned key")?, name)?;
            // A fresh open validates persistence and actual agreement capability.
            let _secret = owned.agree(&owned.point)?;
            Ok(())
        })();
        if let Err(operation) = operations {
            let cleanup = owned.cleanup();
            return Failure::complete(Err(operation.into()), cleanup);
        }
        Ok(owned)
    }
    pub(super) fn point(&self) -> &[u8; 65] {
        &self.point
    }
    pub(super) fn agree(&self, point: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>> {
        agree(&self.provider, &self.name, &self.point, point)
    }
    /// Transfer persistence only after the caller validates the committed record.
    /// This closes the creator handle without deleting the enrolled object.
    pub(super) fn retain(self) {
        drop(self);
    }
    pub(super) fn cleanup(mut self) -> Result<()> {
        self.key
            .take()
            .ok_or("missing owned PCP handle")?
            .delete()?;
        absence(&self.name)
    }
}

pub(super) trait Agreement {
    fn point(&self) -> &[u8; 65];
    fn agree(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>>;
}
impl Agreement for Owned {
    fn point(&self) -> &[u8; 65] {
        Owned::point(self)
    }
    fn agree(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>> {
        Owned::agree(self, peer)
    }
}

/// A checked reference conveys no ownership of an existing persistent key.
pub(super) struct Existing {
    provider: Provider,
    name: String,
    point: [u8; 65],
}
impl Existing {
    pub(super) fn open(name: &str, expected: &[u8; 65]) -> Result<Self> {
        age_tpm_wsl_post_quantum::validate_name(name)
            .map_err(|_| "invalid dedicated post-quantum name")?;
        let provider = Provider::open()?;
        let key = provider
            .open_key_raw(name)
            .map_err(|code| format!("PCP reopen 0x{code:08x}"))?;
        if provider.validate(&key, name)? != *expected {
            return Err("actual PCP public identity changed".into());
        }
        Ok(Self {
            provider,
            name: name.into(),
            point: *expected,
        })
    }
}
impl Agreement for Existing {
    fn point(&self) -> &[u8; 65] {
        &self.point
    }
    fn agree(&self, peer: &[u8; 65]) -> Result<Zeroizing<[u8; 32]>> {
        agree(&self.provider, &self.name, &self.point, peer)
    }
}

/// Caller authorizes deletion with its trusted receipt/expected identity under
/// the filesystem deletion lease. Missing keys require exact absence evidence.
pub(super) fn delete_matching(name: &str, expected: &[u8; 65]) -> Outcome<()> {
    age_tpm_wsl_post_quantum::validate_name(name)
        .map_err(|_| "invalid dedicated post-quantum name")?;
    let provider = Provider::open()?;
    let key = match provider.open_key_raw(name) {
        Err(BAD_KEYSET) => None,
        Err(code) => return Err(format!("PCP delete open 0x{code:08x}").into()),
        Ok(key) => {
            if provider.validate(&key, name)? != *expected {
                return Err("PCP delete identity mismatch".into());
            }
            Some(key)
        }
    };
    // Input/provider/identity rejection above is an ordinary operation failure.
    // From the authorized delete onward, retain cleanup failure distinctly.
    Failure::delete_and_verify(
        || match key {
            Some(key) => key.delete(),
            None => Ok(()),
        },
        || absence(name),
    )
}

fn agree(
    provider: &Provider,
    name: &str,
    expected: &[u8; 65],
    point: &[u8; 65],
) -> Result<Zeroizing<[u8; 32]>> {
    // Validate peer through the existing strict public parser before CNG import.
    let mut peer_blob = Vec::with_capacity(72);
    peer_blob.extend(BCRYPT_ECDH_PUBLIC_P256_MAGIC.to_le_bytes());
    peer_blob.extend(32u32.to_le_bytes());
    peer_blob.extend(&point[1..]);
    if point[0] != 4 {
        return Err("invalid agreement peer".into());
    }
    key_format::p256_recipient("ECDH_P256", &peer_blob).map_err(|_| "invalid agreement peer")?;
    let key = provider
        .open_key_raw(name)
        .map_err(|code| format!("PCP reopen 0x{code:08x}"))?;
    if provider.validate(&key, name)? != *expected {
        return Err("actual PCP public identity changed".into());
    }
    let mut peer = 0;
    // SAFETY: valid public-only ECC blob, live provider, writable handle output.
    check(unsafe {
        NCryptImportKey(
            provider.0.0,
            0,
            BCRYPT_ECCPUBLIC_BLOB,
            null(),
            &mut peer,
            peer_blob.as_ptr(),
            72,
            NCRYPT_SILENT_FLAG,
        )
    })?;
    let peer = Handle(peer);
    let mut secret = 0;
    // SAFETY: live matching-provider key handles; silent mode rejects required UI.
    check(unsafe { NCryptSecretAgreement(key.0, peer.0, &mut secret, NCRYPT_SILENT_FLAG) })?;
    let secret = Handle(secret);
    let mut raw = Zeroizing::new([0; 32]);
    let mut length = 0;
    // SAFETY: live owned secret and exact wiping output; PCP requires zero flags.
    check(unsafe {
        NCryptDeriveKey(
            secret.0,
            BCRYPT_KDF_RAW_SECRET,
            null(),
            raw.as_mut_ptr(),
            32,
            &mut length,
            0,
        )
    })?;
    if length != 32 {
        return Err("invalid PCP agreement length".into());
    }
    raw.reverse();
    Ok(raw) // CNG little-endian to RFC9180 big-endian
}
