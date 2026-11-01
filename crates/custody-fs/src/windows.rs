use super::*;
use std::{
    ffi::{OsString, c_void},
    fs::File,
    io::{Read, Write},
    mem::{offset_of, size_of, size_of_val},
    os::windows::{
        ffi::{OsStrExt, OsStringExt},
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Component, PathBuf, Prefix},
    ptr::{null, null_mut},
    sync::Arc,
};
use windows_sys::{
    Wdk::{
        Foundation::OBJECT_ATTRIBUTES,
        Storage::FileSystem::{
            FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
            FILE_OPEN_REPARSE_POINT, FILE_RENAME_INFORMATION, FILE_SYNCHRONOUS_IO_NONALERT,
            FILE_WRITE_THROUGH, FileRenameInformation, NtCreateFile, NtSetInformationFile,
        },
    },
    Win32::{
        Foundation::{
            GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree, OBJ_CASE_INSENSITIVE,
            OBJ_DONT_REPARSE, STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
            STATUS_PENDING, WAIT_OBJECT_0,
        },
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{
            Com::CoTaskMemFree,
            IO::IO_STATUS_BLOCK,
            Threading::{GetCurrentProcess, INFINITE, OpenProcessToken, WaitForSingleObject},
            WindowsProgramming::DRIVE_FIXED,
        },
        UI::Shell::{FOLDERID_LocalAppData, SHGetKnownFolderPath},
    },
};

fn checked(value: i32) -> Result<()> {
    if value == 0 {
        // SAFETY: retrieve the error immediately after the failed calling-thread API.
        Err(Error::Windows(unsafe { GetLastError() }))
    } else {
        Ok(())
    }
}
struct Local(*mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        // SAFETY: this wrapper exclusively owns a LocalAlloc-family API allocation.
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct TaskString(*mut u16);
impl Drop for TaskString {
    fn drop(&mut self) {
        // SAFETY: SHGetKnownFolderPath allocates this string with CoTaskMemAlloc.
        unsafe {
            CoTaskMemFree(self.0.cast());
        }
    }
}
fn text(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn local_app_data() -> Result<PathBuf> {
    let mut path = null_mut();
    // SAFETY: valid known-folder identifier, current user and writable output pointer.
    let status = unsafe { SHGetKnownFolderPath(&FOLDERID_LocalAppData, 0, null_mut(), &mut path) };
    if status < 0 {
        return Err(Error::Native(status));
    }
    if path.is_null() {
        return Err(Error::Invalid("missing local application data path"));
    }
    let allocation = TaskString(path);
    let mut length = 0;
    // SAFETY: successful API returns a terminated wide string; enforce the Windows path bound.
    while length < 32768 && unsafe { *path.add(length) } != 0 {
        length += 1;
    }
    if length == 32768 {
        return Err(Error::Invalid("oversized application data path"));
    }
    // SAFETY: the bounded scan found the allocation's terminator.
    let value = OsString::from_wide(unsafe { std::slice::from_raw_parts(path, length) });
    drop(allocation);
    Ok(PathBuf::from(value))
}
fn current_user() -> Result<String> {
    let mut raw = null_mut();
    // SAFETY: live current process and writable token handle output.
    checked(unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) })?;
    // SAFETY: successful API transfers ownership of this token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut buffer = [0usize; 256];
    let mut returned = 0;
    // SAFETY: aligned, bounded writable storage and an owned live token.
    checked(unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size_of_val(&buffer) as u32,
            &mut returned,
        )
    })?;
    if returned as usize > size_of_val(&buffer) || (returned as usize) < size_of::<TOKEN_USER>() {
        return Err(Error::Invalid("invalid token user response"));
    }
    // SAFETY: successful, aligned TokenUser response has its documented minimum size.
    let sid = unsafe { (*(buffer.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut value = null_mut();
    // SAFETY: Windows supplies a valid SID in the still-live token information.
    checked(unsafe { ConvertSidToStringSidW(sid, &mut value) })?;
    let allocation = Local(value.cast());
    let mut length = 0;
    // SAFETY: converted SID is terminated; bound the scan independently.
    while length < 256 && unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    if length == 256 {
        return Err(Error::Invalid("oversized current user SID"));
    }
    // SAFETY: scan found the terminator inside this native allocation.
    let result = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) })
        .map_err(|_| Error::Invalid("invalid current user SID"));
    drop(allocation);
    result
}
fn sid(value: &str) -> Result<Local> {
    let mut output = null_mut();
    // SAFETY: valid terminated text, writable allocation output.
    checked(unsafe { ConvertStringSidToSidW(text(value).as_ptr(), &mut output) })?;
    Ok(Local(output))
}
struct Policy {
    user: Local,
    system: Local,
    directory: Local,
    file: Local,
}
impl Policy {
    fn new() -> Result<Self> {
        let user = current_user()?;
        fn descriptor(value: &str) -> Result<Local> {
            let mut output = null_mut();
            // SAFETY: terminated SDDL; output allocation is exclusively owned on success.
            checked(unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    text(value).as_ptr(),
                    1,
                    &mut output,
                    null_mut(),
                )
            })?;
            Ok(Local(output))
        }
        Ok(Self {
            user: sid(&user)?,
            system: sid("S-1-5-18")?,
            directory: descriptor(&format!("O:{user}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})"))?,
            file: descriptor(&format!("O:{user}D:P(A;;FA;;;SY)(A;;FA;;;{user})"))?,
        })
    }
    fn verify(&self, handle: HANDLE, directory: bool) -> Result<()> {
        let mut owner = null_mut();
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        // SAFETY: live owned file handle, writable outputs; returned descriptor owns all interior pointers.
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(Error::Windows(status));
        }
        let descriptor = Local(descriptor);
        // SAFETY: security API validates the returned descriptor, owner and ACL structures.
        if owner.is_null()
            || acl.is_null()
            || unsafe { IsValidSecurityDescriptor(descriptor.0) } == 0
            || unsafe { IsValidAcl(acl) } == 0
            || unsafe { EqualSid(owner, self.user.0) } == 0
            || unsafe { (*acl).AceCount } != 2
        {
            return Err(Error::Invalid("unexpected storage owner or ACL"));
        }
        let mut control = 0;
        let mut revision = 0;
        // SAFETY: live returned descriptor and writable fixed outputs.
        checked(unsafe {
            GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision)
        })?;
        if control & SE_DACL_PROTECTED == 0 {
            return Err(Error::Invalid("unprotected storage DACL"));
        }
        let mut seen = [false; 2];
        for index in 0..2 {
            let mut ace = null_mut();
            // SAFETY: validated two-entry ACL and writable output pointer.
            checked(unsafe { GetAce(acl, index, &mut ace) })?;
            // SAFETY: GetAce returns a validated ACE within the still-live ACL.
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceType != 0
                || header.AceFlags != if directory { 3 } else { 0 }
                || header.AceSize < 20
            {
                return Err(Error::Invalid("unexpected storage ACE"));
            }
            // SAFETY: checked allowed-ACE type and minimum SID-bearing size.
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            if allowed.Mask != FILE_ALL_ACCESS {
                return Err(Error::Invalid("unexpected storage access mask"));
            }
            let actual = (&allowed.SidStart as *const u32).cast_mut().cast();
            // SAFETY: Windows validated the SID-bearing ACE; expected converted SIDs remain live.
            let slot = if unsafe { EqualSid(actual, self.system.0) } != 0 {
                0
            } else if unsafe { EqualSid(actual, self.user.0) } != 0 {
                1
            } else {
                return Err(Error::Invalid("unexpected storage principal"));
            };
            if seen[slot] {
                return Err(Error::Invalid("duplicate storage principal"));
            }
            seen[slot] = true;
        }
        Ok(())
    }
}

struct Node {
    handle: OwnedHandle,
    // Retain every acquired ancestor, including the drive, until the last child closes.
    _parent: Option<Arc<Node>>,
}
impl Node {
    fn raw(&self) -> HANDLE {
        self.handle.as_raw_handle()
    }
}
fn metadata(handle: HANDLE, directory: bool) -> Result<()> {
    object_metadata(handle, directory, true)
}
fn object_metadata(handle: HANDLE, directory: bool, bounded: bool) -> Result<()> {
    // SAFETY: query of a live owned filesystem handle.
    if unsafe { GetFileType(handle) } != FILE_TYPE_DISK {
        return Err(Error::Invalid("non-disk storage rejected"));
    }
    let mut attributes: FILE_ATTRIBUTE_TAG_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: initialized output has the exact documented query size.
    checked(unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    })?;
    if attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        || (attributes.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0) != directory
    {
        return Err(Error::Invalid("reparse or wrong storage object type"));
    }
    let mut standard: FILE_STANDARD_INFO = unsafe { std::mem::zeroed() };
    // SAFETY: initialized output has the exact documented query size.
    checked(unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    })?;
    if standard.DeletePending
        || standard.Directory != directory
        || (!directory
            && (standard.NumberOfLinks != 1
                || standard.EndOfFile < 0
                || (bounded && standard.EndOfFile > MAX_FILE as i64)))
    {
        return Err(Error::Invalid(
            "linked, deleting or oversized storage object",
        ));
    }
    Ok(())
}
fn native_open(
    parent: &Arc<Node>,
    name: &[u16],
    directory: bool,
    disposition: u32,
    delete: bool,
    write: bool,
    policy: Option<&Policy>,
) -> Result<OwnedHandle> {
    if disposition == FILE_OPEN_IF {
        // Exclusive create establishes ownership for failure cleanup; a collision
        // reopens without modifying the existing object's security descriptor.
        return match native_open(parent, name, directory, FILE_CREATE, delete, write, policy) {
            Err(Error::Native(STATUS_OBJECT_NAME_COLLISION)) => {
                native_open(parent, name, directory, FILE_OPEN, delete, write, policy)
            }
            result => result,
        };
    }
    if name.is_empty()
        || name.len() > 255
        || name
            .iter()
            .any(|v| [0, b'\\' as u16, b'/' as u16, b':' as u16].contains(v))
        || name == [b'.' as u16]
        || name == [b'.' as u16, b'.' as u16]
    {
        return Err(Error::Invalid("invalid native storage component"));
    }
    let mut name = name.to_vec();
    let bytes =
        u16::try_from(name.len() * 2).map_err(|_| Error::Invalid("oversized native component"))?;
    let mut unicode = windows_sys::Win32::Foundation::UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: name.as_mut_ptr(),
    };
    let object = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.raw(),
        ObjectName: &mut unicode,
        Attributes: OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,
        SecurityDescriptor: policy.map_or(null(), |p| {
            if directory {
                p.directory.0.cast()
            } else {
                p.file.0.cast()
            }
        }),
        SecurityQualityOfService: null_mut(),
    };
    let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
    let mut raw = null_mut();
    let access = if directory {
        // Native opens do not add the attribute-query access that Win32 opens
        // may supply. Metadata verification needs it on every held ancestor.
        FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES
    } else {
        FILE_GENERIC_READ
    } | READ_CONTROL
        | SYNCHRONIZE
        | if delete || disposition == FILE_CREATE {
            DELETE
        } else {
            0
        }
        | if write { FILE_GENERIC_WRITE } else { 0 };
    let options = FILE_SYNCHRONOUS_IO_NONALERT
        | FILE_OPEN_REPARSE_POINT
        | if directory {
            FILE_DIRECTORY_FILE
        } else {
            FILE_NON_DIRECTORY_FILE
        }
        | if write { FILE_WRITE_THROUGH } else { 0 };
    // Directory write sharing permits the rename's internal target-directory open.
    // Access includes LIST/TRAVERSE, so denying DELETE participates in sharing checks.
    let sharing = if directory {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    } else {
        FILE_SHARE_READ
    };
    // SAFETY: all structures/buffers are initialized and remain live through synchronous completion;
    // single-component relative name, owned parent handle and optional live security descriptor.
    let mut status = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &object,
            &mut io,
            null(),
            FILE_ATTRIBUTE_NORMAL,
            sharing,
            disposition,
            options,
            null(),
            0,
        )
    };
    if status == STATUS_PENDING {
        // Synchronous opens should complete inline. Preserve all buffers until a pending
        // operation signals. The invoking helper retains its whole-process deadline.
        // SAFETY: pending successful acquisition returns a synchronizable owned handle.
        if raw.is_null() || unsafe { WaitForSingleObject(raw, INFINITE) } != WAIT_OBJECT_0 {
            // Returning could free an outstanding IO_STATUS_BLOCK. Termination is safer.
            std::process::abort();
        }
        // SAFETY: the signalled operation completed its initialized status block.
        status = unsafe { io.Anonymous.Status };
        if status == STATUS_PENDING {
            std::process::abort();
        }
    }
    if status < 0 {
        return Err(Error::Native(status));
    }
    if raw.is_null() || raw == INVALID_HANDLE_VALUE {
        return Err(Error::Invalid("missing native storage handle"));
    }
    // SAFETY: successful native acquisition returns exclusive ownership of this handle.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    if disposition == FILE_CREATE && io.Information != 2 {
        return Err(Error::Invalid(
            "native create did not establish new-object ownership",
        ));
    }
    // Explicit known-slot deletion reads no contents. Preserve every object and
    // security check while permitting removal of a corrupt oversized owned file.
    let bounded = !(delete && !write && disposition == FILE_OPEN);
    let verified = object_metadata(handle.as_raw_handle(), directory, bounded)
        .and_then(|()| policy.map_or(Ok(()), |p| p.verify(handle.as_raw_handle(), directory)));
    #[cfg(test)]
    let verified = tests::cleanup_tests::after_verify(verified, disposition);
    if let Err(operation) = verified {
        if disposition == FILE_CREATE {
            // The successful exclusive creation and FILE_CREATED result establish
            // ownership. No user bytes have been written; unlink this exact handle.
            let cleanup = remove(handle.as_raw_handle());
            #[cfg(test)]
            let cleanup = tests::cleanup_tests::after_unlink(cleanup);
            if let Err(cleanup) = cleanup {
                return Err(Error::Cleanup {
                    operation: Box::new(operation),
                    cleanup: Box::new(cleanup),
                });
            }
            drop(handle);
            let absent = matches!(
                native_open(parent, &name, directory, FILE_OPEN, false, false, None),
                Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
            );
            #[cfg(test)]
            let absent = tests::cleanup_tests::after_absence(absent);
            if !absent {
                return Err(Error::Cleanup {
                    operation: Box::new(operation),
                    cleanup: Box::new(Error::Invalid("new storage object absence not verified")),
                });
            }
        }
        return Err(operation);
    }
    Ok(handle)
}
fn anchor() -> Result<Arc<Node>> {
    let path = local_app_data()?;
    let mut parts = path.components();
    let drive = match parts.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(d) => d,
            _ => return Err(Error::Invalid("nonlocal application data path")),
        },
        _ => return Err(Error::Invalid("nonlocal application data path")),
    };
    if parts.next() != Some(Component::RootDir) {
        return Err(Error::Invalid("nonabsolute application data path"));
    }
    let drive_path = [drive as u16, b':' as u16, b'\\' as u16, 0];
    // SAFETY: terminated local drive-root string.
    if unsafe { GetDriveTypeW(drive_path.as_ptr()) } != DRIVE_FIXED {
        return Err(Error::Invalid("nonfixed storage drive"));
    }
    // SAFETY: literal drive root, synchronous open, no security/template pointers.
    let raw = unsafe {
        CreateFileW(
            drive_path.as_ptr(),
            FILE_LIST_DIRECTORY | FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Error::Windows(unsafe { GetLastError() }));
    }
    // SAFETY: successful CreateFileW transfers ownership.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    metadata(handle.as_raw_handle(), true)?;
    let mut node = Arc::new(Node {
        handle,
        _parent: None,
    });
    for part in parts {
        let Component::Normal(part) = part else {
            return Err(Error::Invalid("noncanonical application data path"));
        };
        let handle = native_open(
            &node,
            &part.encode_wide().collect::<Vec<_>>(),
            true,
            FILE_OPEN,
            false,
            false,
            None,
        )?;
        node = Arc::new(Node {
            handle,
            _parent: Some(node),
        });
    }
    Ok(node)
}

/// A protected root under the current user's known local application data folder.
/// All root components have protected current-user/SYSTEM DACLs. Local fixed
/// drive ancestors are acquired one component at a time without following reparses.
pub struct Root {
    node: Arc<Node>,
    policy: Policy,
    delete: bool,
}
impl Root {
    pub fn open(relative: &[&str], mode: RootMode) -> Result<Self> {
        if relative.is_empty() || relative.len() > 8 {
            return Err(Error::Invalid("invalid custody root depth"));
        }
        for part in relative {
            component(part)?;
        }
        let policy = Policy::new()?;
        let mut node = anchor()?;
        for (index, part) in relative.iter().enumerate() {
            let delete = matches!(mode, RootMode::Delete) && index + 1 == relative.len();
            let disposition = match mode {
                RootMode::CreateMissing => FILE_OPEN_IF,
                RootMode::CreateNew if index + 1 == relative.len() => FILE_CREATE,
                _ => FILE_OPEN,
            };
            let handle = native_open(
                &node,
                &part.encode_utf16().collect::<Vec<_>>(),
                true,
                disposition,
                delete,
                false,
                Some(&policy),
            )?;
            node = Arc::new(Node {
                handle,
                _parent: Some(node),
            });
        }
        Ok(Self {
            node,
            policy,
            delete: matches!(mode, RootMode::Delete | RootMode::CreateNew),
        })
    }
    fn child(&self, name: &str, disposition: u32, delete: bool) -> Result<Enrollment<'_>> {
        enrollment(name)?;
        let handle = native_open(
            &self.node,
            &name.encode_utf16().collect::<Vec<_>>(),
            true,
            disposition,
            delete,
            false,
            Some(&self.policy),
        )?;
        Ok(Enrollment {
            node: Arc::new(Node {
                handle,
                _parent: Some(self.node.clone()),
            }),
            root: self,
            delete: delete || disposition == FILE_CREATE,
        })
    }
    /// Exclusive directory creation; never adopt an existing enrollment.
    pub fn create(&self, name: &str) -> Result<Enrollment<'_>> {
        self.child(name, FILE_CREATE, false)
    }
    pub fn open_enrollment(&self, name: &str) -> Result<Enrollment<'_>> {
        self.child(name, FILE_OPEN, false)
    }
    /// Acquire an exclusive delete-capable directory before validating the expected
    /// receipt and PCP identity. Other retained readers cause failure, not a race.
    pub fn open_for_delete(&self, name: &str) -> Result<Enrollment<'_>> {
        self.child(name, FILE_OPEN, true)
    }
    /// Used only after explicit owned-directory cleanup. Never recursively deletes.
    pub fn remove_empty(self) -> Result<()> {
        if !self.delete {
            return Err(Error::Invalid("root was not acquired for deletion"));
        }
        remove(self.node.raw())
    }
}

pub struct Enrollment<'a> {
    node: Arc<Node>,
    root: &'a Root,
    delete: bool,
}
impl Enrollment<'_> {
    fn file(&self, slot: Slot, disposition: u32, delete: bool, write: bool) -> Result<File> {
        let handle = native_open(
            &self.node,
            &slot.name().encode_utf16().collect::<Vec<_>>(),
            false,
            disposition,
            delete,
            write,
            Some(&self.root.policy),
        )?;
        Ok(File::from(handle))
    }
    pub fn read(&self, slot: Slot) -> Result<Vec<u8>> {
        read(&self.file(slot, FILE_OPEN, false, false)?)
    }
    /// File creation has the protected ACL from its first instruction. Any later
    /// write/flush failure leaves a discoverable partial file; never auto-repairs.
    pub fn write_new(&self, slot: Slot, bytes: &[u8]) -> Result<()> {
        if bytes.len() > MAX_FILE {
            return Err(Error::Invalid("oversized custody write"));
        }
        let mut file = self.file(slot, FILE_CREATE, false, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        metadata(file.as_raw_handle(), false)
    }
    /// Caller must validate the complete pending record against its independently
    /// retained identity. Compare those exact bytes again on the rename handle.
    /// Publish without replacement, then close and reopen the final object.
    pub fn commit_pending(&self, validated: &[u8]) -> Result<Vec<u8>> {
        let file = self.file(Slot::Pending, FILE_OPEN, true, true)?;
        let expected = read(&file)?;
        if expected != validated {
            return Err(Error::Invalid("pending record changed after validation"));
        }
        file.sync_all()?;
        let name: Vec<u16> = Slot::Final.name().encode_utf16().collect();
        let offset = offset_of!(FILE_RENAME_INFORMATION, FileName);
        let length = offset
            .checked_add(name.len() * 2)
            .ok_or(Error::Invalid("rename size overflow"))?;
        let mut storage = vec![0usize; length.div_ceil(size_of::<usize>())];
        let information = storage.as_mut_ptr().cast::<FILE_RENAME_INFORMATION>();
        // SAFETY: usize-aligned zeroed storage covers every fixed field and the
        // complete trailing UTF-16 array. Zero flags select no replacement.
        unsafe {
            (*information).RootDirectory = self.node.raw();
            (*information).FileNameLength = (name.len() * 2) as u32;
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                storage.as_mut_ptr().cast::<u8>().add(offset).cast(),
                name.len(),
            );
        }
        let mut io: IO_STATUS_BLOCK = unsafe { std::mem::zeroed() };
        // SAFETY: live synchronous DELETE-capable source, held target directory,
        // aligned native information and status output stay live until completion.
        let mut status = unsafe {
            NtSetInformationFile(
                file.as_raw_handle(),
                &mut io,
                information.cast(),
                length as u32,
                FileRenameInformation,
            )
        };
        if status == STATUS_PENDING {
            // SAFETY: private synchronous source handle; no other IO is outstanding.
            if unsafe { WaitForSingleObject(file.as_raw_handle(), INFINITE) } != WAIT_OBJECT_0 {
                // Do not free buffers while the kernel could still use them.
                std::process::abort();
            }
            // SAFETY: the signalled operation completed its initialized status block.
            status = unsafe { io.Anonymous.Status };
            if status == STATUS_PENDING {
                std::process::abort();
            }
        }
        if status < 0 {
            return Err(Error::Native(status));
        }
        file.sync_all()?;
        drop(file);
        let actual = self.read(Slot::Final)?;
        if actual != expected {
            return Err(Error::Invalid("committed storage changed on reopen"));
        }
        Ok(actual)
    }
    /// Caller must first validate its independently retained identity against the
    /// receipt on this same exclusive directory and verify owned PCP deletion.
    pub fn remove_file(&self, slot: Slot) -> Result<()> {
        if !self.delete {
            return Err(Error::Invalid("enrollment was not acquired for deletion"));
        }
        let file = self.file(slot, FILE_OPEN, true, false)?;
        remove(file.as_raw_handle())
    }
    pub fn remove_empty(self) -> Result<()> {
        if !self.delete {
            return Err(Error::Invalid("enrollment was not acquired for deletion"));
        }
        remove(self.node.raw())
    }
}
fn read(file: &File) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take((MAX_FILE + 1) as u64).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_FILE {
        return Err(Error::Invalid("oversized custody read"));
    }
    Ok(bytes)
}
fn remove(handle: HANDLE) -> Result<()> {
    let information = FILE_DISPOSITION_INFO { DeleteFile: true };
    // SAFETY: owned DELETE-capable handle and correctly sized initialized structure.
    checked(unsafe {
        SetFileInformationByHandle(
            handle,
            FileDispositionInfo,
            (&information as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    })
}

#[cfg(test)]
mod tests;
