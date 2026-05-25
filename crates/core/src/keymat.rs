//! `SecretBytes` — zeroizing, debug-redacted, optionally mlock'd buffers.
//!
//! ## mlock caveats (read this before relying on it)
//!
//! `SecretBytes::new` and `from_random` attempt to `mlock(2)` the underlying
//! buffer so it cannot be paged to swap. This is **best-effort only**:
//! - On Debian default, `RLIMIT_MEMLOCK` is small (~8 MiB). Our buffers
//!   (passphrase, 64-byte master keyfile, 32-byte KEK) easily fit. We log a
//!   `tracing::warn!` and proceed unlocked on EPERM/ENOMEM.
//! - Argon2's working memory (≥ 64 MiB) is allocated by the `argon2` crate
//!   internally and we cannot mlock it. KDF intermediates may therefore page
//!   out under memory pressure. This is an accepted limitation; mitigating it
//!   would require forking the argon2 crate or running the KDF in a separate
//!   process.

use std::fmt;

use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Error, Result};

#[derive(Clone)]
pub struct SecretBytes {
    bytes: Zeroizing<Vec<u8>>,
    /// True iff we successfully mlock'd the buffer. Tracked so we don't
    /// `munlock` something we never locked (which would EFAULT or no-op
    /// depending on platform).
    locked: bool,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        let mut s = Self {
            bytes: Zeroizing::new(bytes),
            locked: false,
        };
        s.try_mlock();
        s
    }

    pub fn from_random(len: usize) -> Result<Self> {
        let mut buf = vec![0u8; len];
        getrandom::getrandom(&mut buf).map_err(|e| Error::Rng(e.to_string()))?;
        Ok(Self::new(buf))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Best-effort mlock. Logs and continues on permission/limit errors.
    fn try_mlock(&mut self) {
        if self.bytes.is_empty() {
            return;
        }
        // SAFETY: `bytes` points to a valid contiguous allocation owned by
        // this struct for as long as `self` lives. mlock is fine to call on
        // any readable address range.
        let ptr = self.bytes.as_ptr();
        let len = self.bytes.len();
        let res = unsafe {
            let nn = match std::ptr::NonNull::new(ptr as *mut std::ffi::c_void) {
                Some(p) => p,
                None => return,
            };
            nix::sys::mman::mlock(nn, len)
        };
        match res {
            Ok(()) => self.locked = true,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    bytes = len,
                    "mlock failed; secret buffer remains unlocked (may page to swap)"
                );
            }
        }
    }

    fn try_munlock(&mut self) {
        if !self.locked || self.bytes.is_empty() {
            return;
        }
        let ptr = self.bytes.as_ptr();
        let len = self.bytes.len();
        let res = unsafe {
            let nn = match std::ptr::NonNull::new(ptr as *mut std::ffi::c_void) {
                Some(p) => p,
                None => return,
            };
            nix::sys::mman::munlock(nn, len)
        };
        if let Err(e) = res {
            tracing::warn!(error = %e, "munlock failed");
        }
        self.locked = false;
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        // Order: munlock first, then Zeroizing's drop scrubs memory.
        self.try_munlock();
    }
}

impl From<&str> for SecretBytes {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes().to_vec())
    }
}

impl From<String> for SecretBytes {
    fn from(mut s: String) -> Self {
        let v = s.as_bytes().to_vec();
        s.zeroize();
        Self::new(v)
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes redacted>)", self.bytes.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_contents() {
        let s = SecretBytes::from("hunter2");
        let dbg = format!("{:?}", s);
        assert!(!dbg.contains("hunter2"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn from_random_has_correct_len() {
        let s = SecretBytes::from_random(64).unwrap();
        assert_eq!(s.len(), 64);
        assert!(s.as_bytes().iter().any(|&b| b != 0));
    }

    #[test]
    fn empty_buffer_does_not_attempt_mlock() {
        // Zero-length mlock would be EINVAL on some kernels; constructor
        // must bail early.
        let s = SecretBytes::new(Vec::new());
        assert_eq!(s.len(), 0);
        assert!(!s.locked);
    }

    #[test]
    fn construction_succeeds_even_when_mlock_would_fail() {
        // We can't reliably force mlock to fail without breaking the test
        // environment. Instead, just exercise the construction path many
        // times to ensure we never panic and locked is set sensibly.
        for _ in 0..16 {
            let s = SecretBytes::from_random(64).unwrap();
            // Either locked or not; both are valid (depends on RLIMIT).
            assert_eq!(s.len(), 64);
            drop(s);
        }
    }
}
