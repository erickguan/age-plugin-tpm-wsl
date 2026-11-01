//! Private protocol buffering. Wipes owned allocations; caller buffers stay caller-owned.
use secrecy::zeroize::{Zeroize, Zeroizing};
use std::io::{self, BufRead, Read};

/// Fixed read storage, wiped as bytes are consumed and before the allocation is released.
pub(crate) struct WipingReader<R> {
    inner: R,
    bytes: Zeroizing<Vec<u8>>,
    position: usize,
    filled: usize,
}

impl<R: Read> WipingReader<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self::with_capacity(8192, inner)
    }

    fn with_capacity(capacity: usize, inner: R) -> Self {
        Self {
            inner,
            bytes: Zeroizing::new(vec![0; capacity]),
            position: 0,
            filled: 0,
        }
    }

    /// Clear live storage as well as its readable range, including after a failed read.
    pub(crate) fn clear(&mut self) {
        self.bytes.as_mut_slice().zeroize();
        self.position = 0;
        self.filled = 0;
    }
}

impl<R: Read> Read for WipingReader<R> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.position == self.filled && out.len() >= self.bytes.len() {
            self.clear();
            // This bypass transfers directly into caller-owned output, like BufReader.
            return self.inner.read(out);
        }
        let available = self.fill_buf()?;
        let count = out.len().min(available.len());
        out[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}

/// Grow a guarded vector by copying into a new guarded allocation. Swapping drops
/// the old allocation under its guard; Vec::reserve would free it without wiping.
fn append_bytes(destination: &mut Zeroizing<Vec<u8>>, bytes: &[u8]) {
    let needed = destination
        .len()
        .checked_add(bytes.len())
        .expect("buffer length overflow");
    if needed > destination.capacity() {
        let capacity = destination.capacity().saturating_mul(2).max(needed);
        let mut replacement = Zeroizing::new(Vec::with_capacity(capacity));
        replacement.extend_from_slice(destination);
        std::mem::swap(destination, &mut replacement);
    }
    destination.extend_from_slice(bytes);
}

/// Preserve the BufRead caller's existing String while wiping any allocation
/// replaced during growth. No allocation occurs in push_str after this reserve.
fn append_text(destination: &mut String, text: &str) {
    let needed = destination
        .len()
        .checked_add(text.len())
        .expect("buffer length overflow");
    if needed > destination.capacity() {
        let capacity = destination.capacity().saturating_mul(2).max(needed);
        let mut replacement = Zeroizing::new(String::with_capacity(capacity));
        replacement.push_str(destination);
        std::mem::swap(destination, &mut *replacement);
    }
    destination.push_str(text);
}

impl<R: Read> BufRead for WipingReader<R> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position == self.filled {
            self.clear();
            match self.inner.read(&mut self.bytes) {
                Ok(count) => self.filled = count,
                Err(error) => {
                    // Read implementations may write into the buffer before an error.
                    self.clear();
                    return Err(error);
                }
            }
        }
        Ok(&self.bytes[self.position..self.filled])
    }

    fn consume(&mut self, amount: usize) {
        let end = self.filled.min(self.position.saturating_add(amount));
        self.bytes[self.position..end].zeroize();
        self.position = end;
    }

    fn read_line(&mut self, destination: &mut String) -> io::Result<usize> {
        // Keeping raw bytes guarded also covers incomplete or invalid UTF-8.
        let mut line = Zeroizing::new(Vec::new());
        let read_result = loop {
            let available = match self.fill_buf() {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => break Err(error),
            };
            if available.is_empty() {
                break Ok(());
            }
            let newline = available.iter().position(|byte| *byte == b'\n');
            let count = newline.map_or(available.len(), |index| index + 1);
            append_bytes(&mut line, &available[..count]);
            self.consume(count);
            if newline.is_some() {
                break Ok(());
            }
        };
        match std::str::from_utf8(&line) {
            Ok(text) => {
                append_text(destination, text);
                read_result.map(|()| line.len())
            }
            // Like BufRead::read_line, preserve an underlying IO error when both
            // reading and UTF-8 validation fail. Invalid bytes never reach String.
            Err(_) => match read_result {
                Err(error) => Err(error),
                Ok(()) => Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "stream did not contain valid UTF-8",
                )),
            },
        }
    }
}

#[cfg(test)]
#[path = "buffer_tests.rs"]
mod tests;
