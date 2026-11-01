//! Private guard for owned HMAC pad blocks and digest-output temporaries.
use core::ops::{Deref, DerefMut};
use zeroize::Zeroize;

/// Keep a private byte-array owner guarded without adding public digest bounds.
/// Returned public outputs stay caller-owned; this type is for internal copies.
pub struct WipingBytes<T: AsMut<[u8]>>(T);

impl<T: AsMut<[u8]>> WipingBytes<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn clear(&mut self) {
        self.0.as_mut().zeroize();
    }
}

impl<T: AsMut<[u8]>> Deref for WipingBytes<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: AsMut<[u8]>> DerefMut for WipingBytes<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: AsMut<[u8]> + Clone> Clone for WipingBytes<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: AsMut<[u8]>> Drop for WipingBytes<T> {
    fn drop(&mut self) {
        self.clear();
    }
}

