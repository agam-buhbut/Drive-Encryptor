//! Typed progress events emitted by `operations::encrypt_format`.
//!
//! `ProgressEvent` is a public contract consumed by:
//! - the GUI (forwards each event to the webview as a Tauri event)
//! - a future CLI `--json` mode (writes one event per line to stdout)
//!
//! `tracing` remains the channel for diagnostic logging (errors, debug);
//! `ProgressEvent` is the structured progress channel — distinct concerns.
//!
//! Sinks expose `is_cancelled()` so a long-running phase (especially
//! `--shred` on a multi-TiB drive) can be cancelled by the user without
//! waiting for the whole operation to finish.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// A milestone reached during encryption. Variants are tagged for JSON
/// serde via `#[serde(tag = "kind")]`, e.g. `{"kind":"gpt_created"}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProgressEvent {
    /// Plan validated; user-facing warnings ready to display.
    PlanReady { warnings: Vec<String> },
    /// `--shred` is running. Emitted at most ~10 Hz.
    PreShredding { bytes_done: u64, bytes_total: u64 },
    /// New GPT written.
    GptCreated,
    /// P1 (FAT32 escrow partition) formatted.
    P1Formatted,
    /// `recovery.bin` written to P1.
    RecoveryWritten,
    /// VeraCrypt `--create` is running on P2. VeraCrypt does not expose a
    /// progress hook, so this is emitted as a single before/after pair with
    /// `bytes_total = 0` meaning "indeterminate." The GUI shows a spinner
    /// during this window.
    VolumeCreating { bytes_written: u64, bytes_total: u64 },
    /// All on-disk artifacts verified.
    Verified,
    /// Operation succeeded. `recovery_key_pdf` is `Some` only after the
    /// caller has explicitly asked for the PDF to be saved.
    Done { recovery_key_pdf: Option<PathBuf> },
    /// Operation aborted. Either `Cancelled` (user pressed cancel) or a
    /// concrete error from a downstream phase.
    Aborted { reason: String },
}

/// Where progress events go and where cancel requests come from.
///
/// Implementations:
/// - `NoopSink` — drop everything (used by tests).
/// - `TracingSink` — re-emit as `tracing::info!` (default for the CLI; keeps
///   existing log output unchanged).
/// - `GuiSink` (in the `gui` crate) — emit as Tauri events; honours an atomic
///   cancel flag wired to the GUI's "Cancel" button.
pub trait ProgressSink: Send + Sync {
    fn emit(&self, event: ProgressEvent);
    fn is_cancelled(&self) -> bool {
        false
    }
}

#[derive(Debug, Default)]
pub struct NoopSink;

impl ProgressSink for NoopSink {
    fn emit(&self, _event: ProgressEvent) {}
}

/// Default CLI sink: re-emits each event as a `tracing::info!` so the
/// existing log output is preserved (any tracing-subscriber consumes it).
#[derive(Debug, Default)]
pub struct TracingSink;

impl ProgressSink for TracingSink {
    fn emit(&self, event: ProgressEvent) {
        tracing::info!(event = ?event, "progress");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_round_trip_json() {
        let cases = vec![
            ProgressEvent::PlanReady {
                warnings: vec!["small drive".into()],
            },
            ProgressEvent::PreShredding {
                bytes_done: 100,
                bytes_total: 1000,
            },
            ProgressEvent::GptCreated,
            ProgressEvent::P1Formatted,
            ProgressEvent::RecoveryWritten,
            ProgressEvent::VolumeCreating {
                bytes_written: 0,
                bytes_total: 0,
            },
            ProgressEvent::Verified,
            ProgressEvent::Done {
                recovery_key_pdf: Some(PathBuf::from("/tmp/r.pdf")),
            },
            ProgressEvent::Aborted {
                reason: "cancelled".into(),
            },
        ];
        for ev in cases {
            let s = serde_json::to_string(&ev).unwrap();
            let back: ProgressEvent = serde_json::from_str(&s).unwrap();
            assert_eq!(back, ev, "round-trip: {}", s);
        }
    }

    #[test]
    fn pre_shredding_serializes_with_kind_tag() {
        let s = serde_json::to_string(&ProgressEvent::PreShredding {
            bytes_done: 5,
            bytes_total: 10,
        })
        .unwrap();
        assert!(s.contains("\"kind\":\"pre_shredding\""));
        assert!(s.contains("\"bytes_done\":5"));
        assert!(s.contains("\"bytes_total\":10"));
    }

    #[test]
    fn noop_sink_is_quiet() {
        let s = NoopSink;
        s.emit(ProgressEvent::Verified);
        assert!(!s.is_cancelled());
    }

    #[test]
    fn tracing_sink_does_not_panic() {
        let s = TracingSink;
        s.emit(ProgressEvent::P1Formatted);
        s.emit(ProgressEvent::PreShredding {
            bytes_done: 1,
            bytes_total: 2,
        });
        assert!(!s.is_cancelled());
    }
}
