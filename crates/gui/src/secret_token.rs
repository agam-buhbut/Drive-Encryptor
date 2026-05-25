//! Single-use, TTL-bounded token store for secret material.
//!
//! The webview never holds passphrase plaintext. The Rust shell shows a
//! native dialog, captures the answer as a `SecretBytes`, stashes it in a
//! `TokenStore` keyed by an opaque hex id, and returns the id to JS. JS later
//! invokes `start_encrypt` with that id; the shell takes the secret out of
//! the store (single-use), uses it, drops it.
//!
//! A background sweeper drops entries older than `TTL` so an abandoned
//! wizard doesn't leave key material in memory indefinitely.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use denc_core::SecretBytes;

pub const TTL: Duration = Duration::from_secs(60);

#[derive(Clone)]
pub struct TokenStore {
    inner: Arc<Mutex<HashMap<String, (SecretBytes, Instant)>>>,
}

impl Default for TokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TokenStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Insert `secret` under a freshly-generated token id and return the id.
    /// Caller passes the id back to JS as an opaque string.
    pub fn insert(&self, secret: SecretBytes) -> std::io::Result<String> {
        let mut buf = [0u8; 16];
        getrandom::getrandom(&mut buf).map_err(|e| std::io::Error::other(format!("rng: {}", e)))?;
        let id = hex::encode(buf);
        let mut g = self.inner.lock().unwrap();
        g.insert(id.clone(), (secret, Instant::now()));
        Ok(id)
    }

    /// Take and return the secret stored under `id`, removing it. Returns
    /// `None` if the id doesn't exist or has expired.
    pub fn take(&self, id: &str) -> Option<SecretBytes> {
        let mut g = self.inner.lock().unwrap();
        let (secret, t) = g.remove(id)?;
        if t.elapsed() >= TTL {
            return None;
        }
        Some(secret)
    }

    /// Drop all entries older than `TTL`. Called periodically by the sweeper.
    pub fn sweep(&self) {
        let mut g = self.inner.lock().unwrap();
        g.retain(|_, (_, t)| t.elapsed() < TTL);
    }

    /// Wipe everything. Used on app shutdown / `cancel`.
    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap();
        g.clear();
    }

    /// Spawn a Tokio task that calls `sweep` every 30 s. Returns nothing —
    /// the task lives for the duration of the runtime.
    pub fn spawn_sweeper(self) {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                self.sweep();
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn insert_then_take_returns_secret() {
        let s = TokenStore::new();
        let id = s.insert(SecretBytes::from("hello")).unwrap();
        let got = s.take(&id).unwrap();
        assert_eq!(got.as_bytes(), b"hello");
    }

    #[test]
    fn take_is_single_use() {
        let s = TokenStore::new();
        let id = s.insert(SecretBytes::from("x")).unwrap();
        assert!(s.take(&id).is_some());
        assert!(s.take(&id).is_none(), "second take should fail");
    }

    #[test]
    fn unknown_id_returns_none() {
        let s = TokenStore::new();
        assert!(s.take("deadbeef").is_none());
    }

    #[test]
    fn sweep_drops_expired_entries() {
        // We can't easily fast-forward time without `tokio::time::pause`, so
        // this test verifies sweep removes nothing fresh and that take()
        // honours expiry by manipulating Instant directly.
        let s = TokenStore::new();
        let id = s.insert(SecretBytes::from("a")).unwrap();
        // Manually back-date the entry past TTL.
        {
            let mut g = s.inner.lock().unwrap();
            let entry = g.get_mut(&id).unwrap();
            entry.1 = Instant::now() - TTL - Duration::from_secs(1);
        }
        s.sweep();
        // After sweep, the expired entry should be gone.
        assert!(s.inner.lock().unwrap().is_empty());
    }

    #[test]
    fn take_after_ttl_returns_none() {
        let s = TokenStore::new();
        let id = s.insert(SecretBytes::from("b")).unwrap();
        // Back-date.
        {
            let mut g = s.inner.lock().unwrap();
            let entry = g.get_mut(&id).unwrap();
            entry.1 = Instant::now() - TTL - Duration::from_millis(1);
        }
        assert!(s.take(&id).is_none());
    }

    #[test]
    fn ids_are_unique() {
        let s = TokenStore::new();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let id = s.insert(SecretBytes::from("x")).unwrap();
            assert!(seen.insert(id), "id collision");
        }
        // Also ensure they're 32 hex chars.
        for id in &seen {
            assert_eq!(id.len(), 32);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn store_is_cloneable_thread_safe() {
        let s = TokenStore::new();
        let s2 = s.clone();
        let handle = thread::spawn(move || s2.insert(SecretBytes::from("threaded")).unwrap());
        let id = handle.join().unwrap();
        let got = s.take(&id).unwrap();
        assert_eq!(got.as_bytes(), b"threaded");
    }
}
