// encrypt-flow.js — timed playback of the ProgressEvent stream into the
// progress page. Real backend emits these via a ProgressSink (see
// crates/core/src/progress.rs); here we just read MOCK.makeEncryptScript().

window.EncryptFlow = (function () {
  let timers = [];
  let cancelled = false;

  // Human labels per ProgressEvent kind. Mirrors the milestones in
  // crates/core/src/progress.rs.
  const STAGE_LABELS = {
    plan_ready:       "Pre-flight checks complete",
    pre_shredding:    "Overwriting drive with random data…",
    gpt_created:      "Wrote new partition table",
    p1_formatted:     "Formatted FAT32 escrow partition (P1)",
    recovery_written: "Wrote recovery.bin to P1",
    volume_creating:  "Creating VeraCrypt volume (P2)…",
    verified:         "Verified all artifacts",
    done:             "Done — drive is encrypted",
    aborted:          "Aborted",
  };

  function clear() {
    timers.forEach(t => clearTimeout(t));
    timers = [];
  }

  function logLine(text, isErr) {
    const log = document.getElementById("log-pane");
    if (!log) return;
    const line = document.createElement("span");
    line.className = "log-line" + (isErr ? " log-line--err" : "");
    const ts = new Date().toLocaleTimeString("en-GB");
    line.textContent = `[${ts}] ${text}\n`;
    log.appendChild(line);
    log.scrollTop = log.scrollHeight;
  }

  function setStage(label, detail) {
    const s = document.getElementById("progress-stage");
    const d = document.getElementById("progress-detail");
    if (s) s.textContent = label;
    if (d) d.textContent = detail || "";
  }

  function setProgress(ratio, indeterminate) {
    const bar = document.getElementById("progress-bar");
    const fill = document.getElementById("progress-fill");
    if (!bar || !fill) return;
    bar.classList.toggle("progress--indeterminate", !!indeterminate);
    if (!indeterminate) {
      fill.style.width = `${Math.max(0, Math.min(1, ratio)) * 100}%`;
    }
  }

  function applyEvent(ev) {
    const label = STAGE_LABELS[ev.kind] || ev.kind;
    switch (ev.kind) {
      case "plan_ready":
        setStage(label, "");
        setProgress(0.02, false);
        logLine("Plan ready");
        break;
      case "pre_shredding": {
        const r = ev.bytes_total ? ev.bytes_done / ev.bytes_total : 0;
        const detail = `${MOCK.formatSize(ev.bytes_done)} of ${MOCK.formatSize(ev.bytes_total)}`;
        setStage(label, detail);
        // Pre-shred fills the first 30% of the overall bar.
        setProgress(0.05 + r * 0.30, false);
        logLine(`pre_shredding ${detail}`);
        break;
      }
      case "gpt_created":
        setStage(label, ""); setProgress(0.40, false); logLine("gpt_created"); break;
      case "p1_formatted":
        setStage(label, ""); setProgress(0.46, false); logLine("p1_formatted"); break;
      case "recovery_written":
        setStage(label, ""); setProgress(0.52, false); logLine("recovery_written"); break;
      case "volume_creating": {
        const indet = ev.bytes_total === 0;
        const detail = indet ? "(VeraCrypt does not expose progress)" : "";
        setStage(label, detail);
        if (indet) setProgress(0, true);
        else       setProgress(0.96, false);
        logLine(`volume_creating ${detail}`);
        break;
      }
      case "verified":
        setStage(label, ""); setProgress(0.98, false); logLine("verified"); break;
      case "done":
        setStage(label, ""); setProgress(1.0, false); logLine("done");
        // Auto-advance to the recovery-key reveal page.
        if (typeof Wizard !== "undefined") {
          // Allow the operator to perceive completion before transitioning.
          setTimeout(() => Wizard.go(6), 600);
        }
        break;
      case "aborted":
        setStage(label, ev.reason || "");
        logLine(`aborted: ${ev.reason || ""}`, true);
        break;
    }
  }

  function start(shred) {
    cancelled = false;
    clear();
    setProgress(0, false);
    const log = document.getElementById("log-pane");
    if (log) log.innerHTML = "";
    logLine(shred ? "Starting encrypt with --shred" : "Starting encrypt");

    const script = MOCK.makeEncryptScript(shred);
    for (const frame of script) {
      timers.push(setTimeout(() => {
        if (cancelled) return;
        applyEvent(frame.event);
      }, frame.at));
    }
  }

  function abort(reason) {
    cancelled = true;
    clear();
    applyEvent({ kind: "aborted", reason: reason || "User cancelled" });
  }

  return { start, abort };
})();
