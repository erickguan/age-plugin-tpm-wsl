#[path = "cleanup_tests.rs"]
pub(super) mod cleanup_tests;
use super::*;
use cleanup_tests::Must;
use std::{
    fs,
    os::windows::fs::MetadataExt,
    panic::{AssertUnwindSafe, catch_unwind},
    path::Path,
};
use windows_sys::Win32::{
    Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom},
    System::{IO::DeviceIoControl, Ioctl::FSCTL_SET_REPARSE_POINT},
};

const NAME: &str = "age-tpm-wsl-pq-0123456789abcdef0123456789abcdef";
const RECEIPT: &[u8] = b"public disposable receipt";
const RECORD: &[u8] = b"public disposable sealed-record stand-in";

fn namespace() -> String {
    let mut bytes = [0u8; 16];
    // SAFETY: system-preferred RNG, writable exact output buffer, no algorithm handle.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    assert_eq!(status, 0);
    format!(
        "age-tpm-wsl-fs-{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn cleanup(root: &Path) -> std::io::Result<()> {
    let child = root.join(NAME);
    if let Ok(metadata) = fs::symlink_metadata(&child) {
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT == 0 {
            for name in [
                "receipt.bin",
                "pending.bin",
                "custody.bin",
                "alias.bin",
                "unexpected.bin",
            ] {
                let path = child.join(name);
                match fs::symlink_metadata(&path) {
                    Ok(metadata) if metadata.is_dir() => fs::remove_dir(&path)?,
                    Ok(_) => fs::remove_file(&path)?,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                    Err(error) => return Err(error),
                }
            }
        }
        // RemoveDirectory unlinks an owned junction, without traversing its target.
        fs::remove_dir(&child)?;
    }
    let target = root.join("age-tpm-wsl-pq-11111111111111111111111111111111");
    if target.try_exists()? {
        fs::remove_dir(&target)?;
    }
    fs::remove_dir(root)?;
    if root.try_exists()? {
        return Err(std::io::Error::other("disposable filesystem root remains"));
    }
    Ok(())
}

fn cleanup_or_stop(path: &Path, name: &str) {
    let result = match path.try_exists() {
        Ok(true) => cleanup(path),
        Ok(false) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = result {
        eprintln!("owned filesystem cleanup failed: {error:?}; namespace {name}");
        // Stop the sequential native campaign immediately. Do not run more cases
        // after a cleanup failure or remove paths outside the owned fixture.
        std::process::exit(97);
    }
}

fn fixture(operation: impl FnOnce(&Root, &Path)) {
    let name = namespace();
    cleanup_tests::namespace(&name);
    let path = local_app_data().must().join(&name);
    let root = Root::open(&[&name], RootMode::CreateNew).must();
    let result = catch_unwind(AssertUnwindSafe(|| operation(&root, &path)));
    drop(root);
    // Only this exclusive-created namespace and this fixture's fixed owned names
    // are cleaned. Unknown children make removal fail; never recurse.
    cleanup_or_stop(&path, &name);
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[test]
fn native_anchor_metadata_requires_no_storage_creation() {
    let node = anchor().expect("open and query existing application-data ancestors");
    metadata(node.raw(), true).expect("query the held application-data directory");
}

#[test]
fn native_bounded_lifecycle_exclusive_creation_and_no_replace_commit() {
    fixture(|root, _| {
        assert!(root.open_enrollment(NAME).guard_cleanup().is_err());
        let enrollment = root.create(NAME).must();
        assert!(root.create(NAME).guard_cleanup().is_err());
        enrollment.write_new(Slot::Receipt, RECEIPT).must();
        assert!(
            enrollment
                .write_new(Slot::Receipt, b"replacement")
                .guard_cleanup()
                .is_err()
        );
        assert_eq!(enrollment.read(Slot::Receipt).must(), RECEIPT);
        assert!(
            enrollment
                .write_new(Slot::Pending, &vec![0; MAX_FILE + 1])
                .guard_cleanup()
                .is_err()
        );
        assert!(matches!(
            enrollment.read(Slot::Pending),
            Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
        ));
        enrollment.write_new(Slot::Pending, RECORD).must();
        assert!(
            enrollment
                .commit_pending(b"unvalidated record")
                .guard_cleanup()
                .is_err()
        );
        assert_eq!(enrollment.read(Slot::Pending).must(), RECORD);
        assert_eq!(enrollment.commit_pending(RECORD).must(), RECORD);
        assert!(matches!(
            enrollment.read(Slot::Pending),
            Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
        ));
        enrollment.write_new(Slot::Pending, b"second record").must();
        assert!(matches!(
            enrollment.commit_pending(b"second record"),
            Err(Error::Native(STATUS_OBJECT_NAME_COLLISION))
        ));
        assert_eq!(enrollment.read(Slot::Final).must(), RECORD);
        assert_eq!(enrollment.read(Slot::Pending).must(), b"second record");
    });
}

#[test]
fn native_delete_lease_blocks_conflicting_readers_and_removes_only_known_files() {
    fixture(|root, path| {
        let enrollment = root.create(NAME).must();
        enrollment.write_new(Slot::Receipt, RECEIPT).must();
        assert!(root.open_for_delete(NAME).guard_cleanup().is_err());
        drop(enrollment);
        let reader = root.open_enrollment(NAME).must();
        let another_reader = root.open_enrollment(NAME).must();
        assert_eq!(another_reader.read(Slot::Receipt).must(), RECEIPT);
        assert!(root.open_for_delete(NAME).guard_cleanup().is_err());
        drop(reader);
        drop(another_reader);
        let deletion = root.open_for_delete(NAME).must();
        assert_eq!(deletion.read(Slot::Receipt).must(), RECEIPT);
        assert!(root.open_enrollment(NAME).guard_cleanup().is_err());
        deletion.remove_file(Slot::Receipt).must();
        fs::write(path.join(NAME).join("unexpected.bin"), b"public fixture").must();
        assert!(deletion.remove_empty().guard_cleanup().is_err());
        assert_eq!(
            fs::read(path.join(NAME).join("unexpected.bin")).must(),
            b"public fixture"
        );
        fs::remove_file(path.join(NAME).join("unexpected.bin")).must();
        root.open_for_delete(NAME).must().remove_empty().must();
        assert!(matches!(
            root.open_enrollment(NAME),
            Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
        ));
    });
}

#[test]
fn native_hard_link_alias_and_wrong_object_type_are_rejected() {
    fixture(|root, path| {
        let enrollment = root.create(NAME).must();
        enrollment.write_new(Slot::Final, RECORD).must();
        let final_path = path.join(NAME).join(Slot::Final.name());
        let alias = path.join(NAME).join("alias.bin");
        fs::hard_link(&final_path, &alias).must();
        assert!(matches!(
            enrollment.read(Slot::Final),
            Err(Error::Invalid(
                "linked, deleting or oversized storage object"
            ))
        ));
        fs::remove_file(alias).must();
        assert_eq!(enrollment.read(Slot::Final).must(), RECORD);
        fs::write(&final_path, vec![0; MAX_FILE + 1]).must();
        assert!(enrollment.read(Slot::Final).guard_cleanup().is_err());
        fs::write(&final_path, RECORD).must();
        assert_eq!(enrollment.read(Slot::Final).must(), RECORD);
        let directory = native_open(
            &enrollment.node,
            &Slot::Pending.name().encode_utf16().collect::<Vec<_>>(),
            true,
            FILE_CREATE,
            false,
            false,
            Some(&root.policy),
        )
        .must();
        drop(directory);
        assert!(enrollment.read(Slot::Pending).guard_cleanup().is_err());
    });
}

#[test]
fn native_oversized_record_is_unreadable_but_owned_unlink_is_nonallocating() {
    fixture(|root, path| {
        let enrollment = root.create(NAME).must();
        enrollment.write_new(Slot::Receipt, RECEIPT).must();
        enrollment.write_new(Slot::Final, RECORD).must();
        let final_path = path.join(NAME).join(Slot::Final.name());
        fs::write(&final_path, vec![0; MAX_FILE + 1]).must();
        assert!(enrollment.read(Slot::Final).guard_cleanup().is_err());
        drop(enrollment);
        let deletion = root.open_for_delete(NAME).must();
        assert_eq!(deletion.read(Slot::Receipt).must(), RECEIPT);
        assert!(deletion.read(Slot::Final).guard_cleanup().is_err());
        let alias = path.join(NAME).join("alias.bin");
        fs::hard_link(&final_path, &alias).must();
        assert!(deletion.remove_file(Slot::Final).guard_cleanup().is_err());
        assert!(final_path.try_exists().must());
        fs::remove_file(&alias).must();
        deletion.remove_file(Slot::Final).must();
        assert!(matches!(
            deletion.read(Slot::Final),
            Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
        ));
        deletion.remove_file(Slot::Receipt).must();
        deletion.remove_empty().must();
    });
}

#[test]
fn native_unexpected_acl_is_rejected_and_protected_acl_control_passes() {
    fixture(|root, path| {
        let enrollment = root.create(NAME).must();
        enrollment.write_new(Slot::Receipt, RECEIPT).must();
        assert_eq!(enrollment.read(Slot::Receipt).must(), RECEIPT);
        let file_path = path.join(NAME).join(Slot::Receipt.name());
        let wide: Vec<_> = file_path.as_os_str().encode_wide().chain(Some(0)).collect();
        let user = current_user().must();
        let sddl = text(&format!(
            "O:{user}D:P(A;;FA;;;SY)(A;;FA;;;{user})(A;;FR;;;WD)"
        ));
        let mut descriptor = null_mut();
        // SAFETY: public test SDDL and owned native output allocation.
        checked(unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        })
        .must();
        let descriptor = Local(descriptor);
        // SAFETY: target is this exclusive-created public fixture; descriptor is live.
        checked(unsafe {
            SetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor.0,
            )
        })
        .must();
        assert!(matches!(
            enrollment.read(Slot::Receipt),
            Err(Error::Invalid("unexpected storage owner or ACL"))
        ));
        // SAFETY: restore the exact validated policy on the same known owned test file.
        checked(unsafe {
            SetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                root.policy.file.0,
            )
        })
        .must();
        assert_eq!(enrollment.read(Slot::Receipt).must(), RECEIPT);
    });
}

#[test]
fn native_held_ancestors_prevent_rename_and_existing_root_never_creates() {
    let name = namespace();
    assert!(matches!(
        Root::open(&[&name], RootMode::Existing),
        Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
    ));
    fixture(|root, path| {
        let moved = path.with_extension("moved");
        assert!(fs::rename(path, &moved).guard_cleanup().is_err());
        assert!(!moved.try_exists().must());
        let enrollment = root.create(NAME).must();
        enrollment.write_new(Slot::Receipt, RECEIPT).must();
        assert!(
            fs::rename(path.join(NAME), path.join("renamed"))
                .guard_cleanup()
                .is_err()
        );
        assert_eq!(enrollment.read(Slot::Receipt).must(), RECEIPT);
    });
}

fn junction(path: &Path, target: &Path) {
    let source: Vec<_> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: owned empty fixture directory, synchronous no-follow acquisition.
    let raw = unsafe {
        CreateFileW(
            source.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    assert_ne!(raw, INVALID_HANDLE_VALUE);
    // SAFETY: successful file open transfers ownership.
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let print: Vec<_> = target.as_os_str().encode_wide().collect();
    let substitute: Vec<_> = "\\??\\"
        .encode_utf16()
        .chain(print.iter().copied())
        .collect();
    let data_length = 8 + (substitute.len() + 1 + print.len() + 1) * 2;
    let mut data = Vec::new();
    data.extend_from_slice(&0xa0000003u32.to_le_bytes());
    data.extend_from_slice(&(data_length as u16).to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    for value in [
        0,
        substitute.len() * 2,
        (substitute.len() + 1) * 2,
        print.len() * 2,
    ] {
        data.extend_from_slice(&(value as u16).to_le_bytes());
    }
    for value in substitute
        .iter()
        .chain(Some(&0))
        .chain(print.iter())
        .chain(Some(&0))
    {
        data.extend_from_slice(&value.to_le_bytes());
    }
    let mut returned = 0;
    // SAFETY: correctly sized public mount-point buffer, owned directory handle,
    // synchronous request and no output buffer. This creates no symlink privilege requirement.
    checked(unsafe {
        DeviceIoControl(
            handle.as_raw_handle(),
            FSCTL_SET_REPARSE_POINT,
            data.as_ptr().cast(),
            data.len() as u32,
            null_mut(),
            0,
            &mut returned,
            null_mut(),
        )
    })
    .must();
}

#[test]
fn native_owned_junction_is_rejected_without_following_its_target() {
    fixture(|root, path| {
        let target_name = "age-tpm-wsl-pq-11111111111111111111111111111111";
        let target = root.create(target_name).must();
        drop(target);
        let leaf = root.create(NAME).must();
        drop(leaf);
        junction(&path.join(NAME), &path.join(target_name));
        assert_ne!(
            fs::symlink_metadata(path.join(NAME))
                .must()
                .file_attributes()
                & FILE_ATTRIBUTE_REPARSE_POINT,
            0
        );
        assert!(root.open_enrollment(NAME).guard_cleanup().is_err());
        // The ordinary protected target remains accessible: ACL/share errors on
        // every directory cannot masquerade as a successful reparse rejection.
        drop(root.open_enrollment(target_name).must());
    });
}

#[test]
fn native_cold_reopen_and_independent_absence_checks() {
    let name = namespace();
    cleanup_tests::namespace(&name);
    let path = local_app_data().must().join(&name);
    let initial = Root::open(&[&name], RootMode::CreateNew).must();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let enrollment = initial.create(NAME).must();
        enrollment.write_new(Slot::Receipt, RECEIPT).must();
        enrollment.write_new(Slot::Pending, RECORD).must();
        assert_eq!(enrollment.commit_pending(RECORD).must(), RECORD);
        drop(enrollment);
        drop(initial);
        let reopened = Root::open(&[&name], RootMode::Existing).must();
        let deletion = reopened.open_for_delete(NAME).must();
        assert_eq!(deletion.read(Slot::Receipt).must(), RECEIPT);
        assert_eq!(deletion.read(Slot::Final).must(), RECORD);
        deletion.remove_file(Slot::Final).must();
        deletion.remove_file(Slot::Receipt).must();
        deletion.remove_empty().must();
        drop(reopened);
        Root::open(&[&name], RootMode::Delete)
            .must()
            .remove_empty()
            .must();
        assert!(matches!(
            Root::open(&[&name], RootMode::Existing),
            Err(Error::Native(STATUS_OBJECT_NAME_NOT_FOUND))
        ));
        assert!(!path.try_exists().must());
    }));
    cleanup_or_stop(&path, &name);
    assert!(!path.try_exists().must());
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
