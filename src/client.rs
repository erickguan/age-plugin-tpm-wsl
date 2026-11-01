use crate::{
    invalid,
    wire::{Frame, MAX_PAYLOAD, UNWRAP, UNWRAP_POST_QUANTUM, UNWRAP_SCHEME},
};
use std::{
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};
use wait_timeout::ChildExt;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct HelperFailure(pub u32);

impl std::fmt::Display for HelperFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "helper failed: 0x{:08X}", self.0)
    }
}
impl std::error::Error for HelperFailure {}

pub struct Helper {
    path: PathBuf,
    timeout: Duration,
}

impl Helper {
    pub fn configured() -> io::Result<Self> {
        let path = std::env::var_os("AGE_TPM_WSL_HELPER")
            .ok_or_else(|| invalid("set AGE_TPM_WSL_HELPER to an absolute helper path"))?;
        let seconds = match std::env::var("AGE_TPM_WSL_TIMEOUT") {
            Ok(value) => value
                .parse::<u64>()
                .map_err(|_| invalid("invalid helper timeout"))?,
            Err(std::env::VarError::NotPresent) => 10,
            Err(_) => return Err(invalid("invalid helper timeout")),
        };
        if !(1..=120).contains(&seconds) {
            return Err(invalid("helper timeout must be 1–120 seconds"));
        }
        Self::new(Path::new(&path), Duration::from_secs(seconds))
    }

    pub fn new(path: &Path, timeout: Duration) -> io::Result<Self> {
        if !path.is_absolute() || timeout.is_zero() {
            return Err(invalid(
                "helper requires an absolute path and positive timeout",
            ));
        }
        Ok(Self {
            path: path.into(),
            timeout,
        })
    }

    pub fn call(&self, request: Frame) -> io::Result<Frame> {
        if request.status != 0 {
            return Err(invalid("request status must be zero"));
        }
        // Serialize before launching so an invalid request cannot leave a helper behind.
        let mut encoded = Zeroizing::new(Vec::new());
        request.write(&mut *encoded)?;
        let deadline = Instant::now() + self.timeout;
        let mut child = Command::new(&self.path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().unwrap();
        let output = child.stdout.take().unwrap();
        let (write_tx, write_rx) = mpsc::channel();
        thread::spawn(move || {
            use std::io::Write;
            let mut input = input;
            let result = input.write_all(&encoded);
            drop(input);
            let _ = write_tx.send(result);
        });
        let (read_tx, read_rx) = mpsc::channel();
        thread::spawn(move || {
            let mut bytes = Zeroizing::new(Vec::new());
            let result = output
                .take((MAX_PAYLOAD + 14) as u64)
                .read_to_end(&mut bytes)
                .and_then(|_| Frame::read(bytes.as_slice()));
            let _ = read_tx.send(result);
        });
        let result = (|| {
            let remaining = || deadline.saturating_duration_since(Instant::now());
            let status = child.wait_timeout(remaining())?.ok_or_else(|| {
                io::Error::new(io::ErrorKind::TimedOut, "helper deadline exceeded")
            })?;
            if !status.success() {
                return Err(invalid("helper exited unsuccessfully"));
            }
            write_rx
                .recv_timeout(remaining())
                .map_err(|_| invalid("helper input interrupted"))??;
            let response = read_rx
                .recv_timeout(remaining())
                .map_err(|_| invalid("helper output interrupted or timed out"))??;
            if response.operation != request.operation {
                return Err(invalid("helper operation mismatch"));
            }
            if response.status != 0 {
                return Err(io::Error::other(HelperFailure(response.status)));
            }
            if matches!(
                request.operation,
                UNWRAP | UNWRAP_SCHEME | UNWRAP_POST_QUANTUM
            ) && response.payload.len() != 16
            {
                return Err(invalid("helper returned invalid file key length"));
            }
            Ok(response)
        })();
        if result.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        }
        result
    }
}
