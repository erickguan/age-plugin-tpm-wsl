//! Minimal TPM command ownership for symmetric sealed-seed custody.
//! Native transport and scripted fault fixtures share this internal interface.
#![cfg_attr(not(windows), allow(dead_code))]
use super::{
    Result,
    lifecycle::{Failure, Outcome},
};
use zeroize::Zeroizing;

const OWNER: u32 = 0x4000_0001;
const READ_PUBLIC: u32 = 0x173;
const FLUSH: u32 = 0x165;
const PRIMARY_PREFIX: &[u8] = &[0, 0x25, 0, 11, 0, 3, 4, 0x72, 0, 0, 0, 6, 1, 0, 0, 0x43];
const CHILD_PREFIX: &[u8] = &[0, 8, 0, 11, 0, 0, 4, 0x52, 0, 0, 0, 16];

type Bytes = Zeroizing<Vec<u8>>;
fn word(out: &mut Vec<u8>, n: u16) {
    out.extend(n.to_be_bytes());
}
fn dword(out: &mut Vec<u8>, n: u32) {
    out.extend(n.to_be_bytes());
}
fn sized(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    word(
        out,
        bytes
            .len()
            .try_into()
            .map_err(|_| "oversized TPM parameter")?,
    );
    out.extend(bytes);
    Ok(())
}
fn frame(tag: u16, code: u32, parameters: &[u8]) -> Result<Bytes> {
    if parameters.len() > 8182 {
        return Err("oversized TPM command".into());
    }
    let mut out = Zeroizing::new(Vec::with_capacity(10 + parameters.len()));
    word(&mut out, tag);
    dword(&mut out, (10 + parameters.len()) as u32);
    dword(&mut out, code);
    out.extend(parameters);
    Ok(out)
}
struct Cursor<'a>(&'a [u8]);
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.0.len() {
            return Err("truncated TPM response".into());
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }
    fn word(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn dword(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let n = self.word()?;
        self.take(usize::from(n))
    }
    fn end(&self) -> Result<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err("trailing TPM data".into())
        }
    }
}
fn header(bytes: &[u8]) -> Result<(u16, u32)> {
    if bytes.len() > 8192 {
        return Err("oversized TPM response".into());
    }
    let mut c = Cursor(bytes);
    let tag = c.word()?;
    let size = c.dword()?;
    let code = c.dword()?;
    if !matches!(tag, 0x8001 | 0x8002)
        || size as usize != bytes.len()
        || (code != 0 && (tag != 0x8001 || size != 10))
    {
        return Err("invalid TPM response header".into());
    }
    Ok((tag, code))
}
fn parameters(bytes: &[u8], handle: bool) -> Result<&[u8]> {
    if header(bytes)? != (0x8002, 0) {
        return Err("expected TPM session success".into());
    }
    let mut c = Cursor(
        bytes
            .get(if handle { 14 } else { 10 }..)
            .ok_or("short TPM session response")?,
    );
    let n = c.dword()? as usize;
    let parameters = c.take(n)?;
    if !c.sized()?.is_empty() || c.take(1)? != [1] || !c.sized()?.is_empty() {
        return Err("invalid TPM password acknowledgment".into());
    }
    c.end()?;
    Ok(parameters)
}
fn area(bytes: &[u8], prefix: &[u8]) -> Result<()> {
    if !bytes.starts_with(prefix) {
        return Err("TPM changed custody template".into());
    }
    let mut c = Cursor(&bytes[prefix.len()..]);
    if c.sized()?.len() != 32 {
        return Err("invalid custody unique length".into());
    }
    c.end()
}
fn authorization(out: &mut Vec<u8>, handle: u32, auth: &[u8]) -> Result<()> {
    if auth.len() > 32 {
        return Err("oversized custody authorization".into());
    }
    dword(out, handle);
    dword(out, (9 + auth.len()) as u32);
    dword(out, 0x4000_0009);
    sized(out, &[])?;
    out.push(0);
    sized(out, auth)
}
fn creation_tail(c: &mut Cursor<'_>) -> Result<()> {
    c.sized()?;
    if c.sized()?.len() != 32 || c.word()? != 0x8021 || c.dword()? != OWNER {
        return Err("invalid TPM custody creation ticket".into());
    }
    c.sized()?;
    Ok(())
}

pub(super) trait Transport {
    fn submit(&mut self, command: &[u8]) -> Result<Bytes>;
    /// Exactly one explicit final attempt, even when it reports failure.
    fn close(&mut self) -> Result<()>;
}
pub(super) struct Context<T: Transport> {
    transport: T,
    owned: Vec<u32>,
}
impl<T: Transport> Context<T> {
    pub(super) fn new(transport: T) -> Self {
        Self {
            transport,
            owned: Vec::new(),
        }
    }
    fn submit(&mut self, command: &[u8]) -> Result<Bytes> {
        let out = self.transport.submit(command)?;
        let (_, code) = header(&out)?;
        if code != 0 {
            return Err(format!("TPM status 0x{code:08x}"));
        }
        Ok(out)
    }
    fn track(&mut self, bytes: &[u8]) -> Result<u32> {
        let handle = Cursor(bytes.get(10..).ok_or("short TPM handle response")?).dword()?;
        if handle >> 24 != 0x80 {
            return Err("invalid TPM transient handle".into());
        }
        // Register successful acquisition before parsing parameters or acknowledgments.
        self.owned.push(handle);
        Ok(handle)
    }
    pub(super) fn parent(&mut self) -> Result<(u32, Vec<u8>)> {
        let mut p = Zeroizing::new(Vec::new());
        authorization(&mut p, OWNER, &[])?;
        sized(&mut p, &[0; 4])?;
        let mut template = PRIMARY_PREFIX.to_vec();
        sized(&mut template, &[])?;
        sized(&mut p, &template)?;
        sized(&mut p, &[])?;
        dword(&mut p, 0);
        let out = self.submit(&frame(0x8002, 0x131, &p)?)?;
        let handle = self.track(&out)?;
        let mut c = Cursor(parameters(&out, true)?);
        let public = c.sized()?;
        area(public, PRIMARY_PREFIX)?;
        creation_tail(&mut c)?;
        let name = c.sized()?;
        if name.len() != 34 || name[..2] != [0, 11] {
            return Err("invalid custody parent name".into());
        }
        c.end()?;
        Ok((handle, public.to_vec()))
    }
    pub(super) fn seal(
        &mut self,
        parent: u32,
        payload: &[u8; 96],
        binding: &[u8; 32],
    ) -> Result<(Bytes, Vec<u8>)> {
        let mut p = Zeroizing::new(Vec::new());
        authorization(&mut p, parent, &[])?;
        let mut sensitive = Zeroizing::new(Vec::new());
        sized(&mut sensitive, binding)?;
        sized(&mut sensitive, payload)?;
        sized(&mut p, &sensitive)?;
        let mut template = CHILD_PREFIX.to_vec();
        sized(&mut template, &[])?;
        sized(&mut p, &template)?;
        sized(&mut p, &[])?;
        dword(&mut p, 0);
        let out = self.submit(&frame(0x8002, 0x153, &p)?)?;
        let mut c = Cursor(parameters(&out, false)?);
        let private = c.sized()?;
        if !(64..=2048).contains(&private.len()) {
            return Err("invalid custody private size".into());
        }
        let public = c.sized()?;
        area(public, CHILD_PREFIX)?;
        creation_tail(&mut c)?;
        c.end()?;
        Ok((Zeroizing::new(private.to_vec()), public.to_vec()))
    }
    pub(super) fn load(&mut self, parent: u32, private: &[u8], public: &[u8]) -> Result<u32> {
        if !(64..=2048).contains(&private.len()) {
            return Err("invalid custody private size".into());
        }
        area(public, CHILD_PREFIX)?;
        let mut p = Zeroizing::new(Vec::new());
        authorization(&mut p, parent, &[])?;
        sized(&mut p, private)?;
        sized(&mut p, public)?;
        let out = self.submit(&frame(0x8002, 0x157, &p)?)?;
        let handle = self.track(&out)?;
        let mut c = Cursor(parameters(&out, true)?);
        let name = c.sized()?;
        if name.len() != 34 || name[..2] != [0, 11] {
            return Err("invalid sealed child name".into());
        }
        c.end()?;
        Ok(handle)
    }
    pub(super) fn unseal(
        &mut self,
        handle: u32,
        binding: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 96]>> {
        let mut p = Zeroizing::new(Vec::new());
        authorization(&mut p, handle, binding)?;
        let out = self.submit(&frame(0x8002, 0x15e, &p)?)?;
        let mut c = Cursor(parameters(&out, false)?);
        let payload = c.sized()?;
        if payload.len() != 96 {
            return Err("invalid unsealed custody size".into());
        }
        c.end()?;
        let mut result = Zeroizing::new([0; 96]);
        result.copy_from_slice(payload);
        Ok(result)
    }
    fn cleanup(&mut self) -> Result<()> {
        while let Some(&handle) = self.owned.last() {
            self.submit(&frame(0x8001, READ_PUBLIC, &handle.to_be_bytes())?)?;
            let out = self.submit(&frame(0x8001, FLUSH, &handle.to_be_bytes())?)?;
            // A successful flush must never be retried, even if verification fails.
            self.owned.pop();
            if header(&out)? != (0x8001, 0) || out.len() != 10 {
                return Err("invalid TPM flush acknowledgment".into());
            }
            let absent =
                self.transport
                    .submit(&frame(0x8001, READ_PUBLIC, &handle.to_be_bytes())?)?;
            if !matches!(header(&absent)?, (0x8001, 0x8b | 0x18b)) {
                return Err("TPM transient absence not verified".into());
            }
        }
        Ok(())
    }
    /// No success value, including a plaintext file key, escapes before release.
    /// Cleanup stops at its first failure; context close is still attempted once.
    pub(super) fn complete<R>(mut self, operation: Outcome<R>) -> Outcome<R> {
        let cleanup = self.cleanup();
        let result = Failure::complete(operation, cleanup);
        Failure::complete(result, self.transport.close())
    }
}

#[cfg(windows)]
pub(super) struct Native(*mut std::ffi::c_void);
#[cfg(windows)]
impl Native {
    pub(super) fn open() -> Result<Self> {
        use windows_sys::Win32::System::TpmBaseServices::*;
        let parameters = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            Anonymous: TBS_CONTEXT_PARAMS2_0 { asUINT32: 4 },
        };
        let mut raw = std::ptr::null_mut();
        // SAFETY: version-2 parameters have the SDK prefix; writable handle output.
        let status = unsafe {
            Tbsi_Context_Create((&parameters as *const TBS_CONTEXT_PARAMS2).cast(), &mut raw)
        };
        if status != 0 {
            return Err(format!("TBS context status 0x{status:08x}"));
        }
        if raw.is_null() {
            return Err("missing TBS context".into());
        }
        Ok(Self(raw))
    }
}
#[cfg(windows)]
impl Transport for Native {
    fn submit(&mut self, command: &[u8]) -> Result<Bytes> {
        if command.len() > 8192 {
            return Err("oversized TBS command".into());
        }
        let mut out = Zeroizing::new(vec![0; 8192]);
        let mut size = out.len() as u32;
        // SAFETY: owned live context, bounded live input/output and writable length.
        let status = unsafe {
            windows_sys::Win32::System::TpmBaseServices::Tbsip_Submit_Command(
                self.0,
                0,
                200,
                command.as_ptr(),
                command.len() as u32,
                out.as_mut_ptr(),
                &mut size,
            )
        };
        if status != 0 {
            return Err(format!("TBS submission status 0x{status:08x}"));
        }
        if size as usize > out.len() {
            return Err("oversized TBS response".into());
        }
        out.truncate(size as usize);
        Ok(out)
    }
    fn close(&mut self) -> Result<()> {
        let raw = std::mem::replace(&mut self.0, std::ptr::null_mut());
        // SAFETY: exclusively owned context; pointer consumed even when release fails.
        let status =
            unsafe { windows_sys::Win32::System::TpmBaseServices::Tbsip_Context_Close(raw) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!("TBS close status 0x{status:08x}"))
        }
    }
}
#[cfg(windows)]
impl Drop for Native {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // Best effort for unwinding only. Explicit close never retries on Drop.
            let _ = self.close();
        }
    }
}

#[cfg(test)]
mod tests;
