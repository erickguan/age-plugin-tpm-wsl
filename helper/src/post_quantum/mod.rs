//! Windows owns the complete post-quantum custody lifecycle and authenticated unwrap.
//! Only canonical public identities, inspection data and file keys leave here.
type Result<T> = std::result::Result<T, String>;
#[cfg(windows)]
pub(crate) mod dispatch;
pub(crate) mod lifecycle;
#[cfg(windows)]
pub(crate) mod pcp;
#[cfg(any(windows, test))]
mod recovery;
#[cfg(windows)]
pub(crate) mod store;
mod tpm;

#[cfg(windows)]
use age_tpm_wsl_post_quantum::{Identity, Record};
#[cfg(windows)]
use lifecycle::{Failure, Outcome};
#[cfg(windows)]
use zeroize::Zeroizing;

#[cfg(windows)]
fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut out = Zeroizing::new([0; N]);
    let length = u32::try_from(N).map_err(|_| "oversized Windows random request")?;
    // SAFETY: bounded live writable buffer, null algorithm selects the system RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            out.as_mut_ptr(),
            length,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 {
        return Err(format!("Windows RNG status 0x{:08x}", status as u32));
    }
    Ok(out)
}
#[cfg(windows)]
fn restore(seed: &[u8; 64]) -> Result<aws_lc_rs::kem::DecapsulationKey> {
    aws_lc_rs::kem::DecapsulationKey::from_seed(&aws_lc_rs::kem::ML_KEM_768, seed)
        .map_err(|_| "ML-KEM seed restoration failed".into())
}
#[cfg(windows)]
fn public(key: &aws_lc_rs::kem::DecapsulationKey, point: &[u8; 65]) -> Result<Vec<u8>> {
    let post_quantum = key
        .encapsulation_key()
        .map_err(|_| "ML-KEM public derivation failed")?;
    let bytes = post_quantum
        .key_bytes()
        .map_err(|_| "ML-KEM public export failed")?;
    if bytes.as_ref().len() != 1184 {
        return Err("invalid ML-KEM public size".into());
    }
    let mut public = bytes.as_ref().to_vec();
    public.extend(point);
    Ok(public)
}
#[cfg(windows)]
fn point(identity: &Identity) -> &[u8; 65] {
    identity.public()[1184..]
        .try_into()
        .expect("validated canonical public size")
}
#[cfg(windows)]
fn seal(seed: &[u8; 64], identity: &Identity) -> Outcome<Record> {
    let mut context = tpm::Context::new(tpm::Native::open()?);
    let operation = (|| -> Outcome<Record> {
        let (parent, public_parent) = context.parent()?;
        let mut payload = Zeroizing::new([0; 96]);
        payload[..64].copy_from_slice(seed);
        payload[64..].copy_from_slice(&identity.binding());
        let (private, public) = context.seal(parent, &payload, &identity.binding())?;
        Record::new(identity.clone(), &public_parent, &private, &public)
            .map_err(|_| "invalid sealed custody record".into())
    })();
    context.complete(operation)
}
#[cfg(windows)]
fn open(record: &Record, enc: &[u8], body: &[u8]) -> Outcome<Zeroizing<Vec<u8>>> {
    use pcp::Agreement;
    // Validate the ciphertext and actual PCP point before creating TPM objects.
    age_tpm_wsl_post_quantum::routing_tag(record.identity().public(), enc)
        .map_err(|_| "invalid post-quantum encapsulation")?;
    if body.len() != 32 {
        return Err("invalid post-quantum body size".into());
    }
    let key = pcp::Existing::open(record.identity().name(), point(record.identity()))?;
    let mut context = tpm::Context::new(tpm::Native::open()?);
    let operation = (|| -> Outcome<Zeroizing<Vec<u8>>> {
        let (parent, actual_parent) = context.parent()?;
        if actual_parent != record.parent() {
            return Err("custody owner parent changed".into());
        }
        let child = context.load(parent, record.private(), record.public())?;
        let payload = context.unseal(child, &record.identity().binding())?;
        let seed = record
            .bound_seed(payload.as_ref())
            .map_err(|_| "unsealed custody binding mismatch")?;
        let private = restore(seed)?;
        if public(&private, key.point())? != record.identity().public() {
            return Err("seed/public/PCP relation mismatch".into());
        }
        age_tpm_wsl_post_quantum::open_classified(
            record.identity().public(),
            enc,
            body,
            &private,
            |peer| key.agree(peer).map_err(std::io::Error::other),
        )
        .map_err(|failure| match failure {
            age_tpm_wsl_post_quantum::OpenFailure::Authentication => Failure::authentication(),
            age_tpm_wsl_post_quantum::OpenFailure::Operational(error) => {
                Failure::from(format!("post-quantum receiver operation failed: {error}"))
            }
        })
    })();
    // Drops/wipes any provisional plaintext if transient cleanup or close fails.
    context.complete(operation)
}
#[cfg(windows)]
fn verify(record: &Record) -> Outcome<()> {
    let file_key = random::<16>()?;
    let wrapped = age_tpm_wsl_post_quantum::wrap(record.identity().public(), file_key.as_ref())
        .map_err(|_| "post-quantum custody validation wrap failed")?;
    if open(record, &wrapped.enc, &wrapped.body)?.as_slice() != file_key.as_ref() {
        return Err("restored custody file key mismatch".into());
    }
    Ok(())
}

/// The helper supplies bounded protocol data; dispatch owns request validation
/// and maps cleanup failure to the fatal helper status.
#[cfg(windows)]
pub(super) use dispatch::dispatch;
