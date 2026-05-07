//! `GuiSink` — the GUI's `ProgressSink` impl. Forwards each event to the
//! webview as a Tauri event named `progress`, and exposes a cancel flag the
//! "Cancel" button sets.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use denc_core::{ProgressEvent, ProgressSink};
use tauri::{AppHandle, Emitter};

#[derive(Clone)]
pub struct GuiSink {
    app: AppHandle,
    cancelled: Arc<AtomicBool>,
}

impl GuiSink {
    pub fn new(app: AppHandle, cancelled: Arc<AtomicBool>) -> Self {
        Self { app, cancelled }
    }
}

impl ProgressSink for GuiSink {
    fn emit(&self, event: ProgressEvent) {
        if let Err(e) = self.app.emit("progress", &event) {
            tracing::warn!(error = %e, "failed to emit progress event to webview");
        }
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}
