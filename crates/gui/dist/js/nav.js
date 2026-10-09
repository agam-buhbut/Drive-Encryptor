// nav.js — wizard step show/hide and footer-button state.
//
// A wizard page has any number of <section class="wizard-step" data-step="N">
// nodes inside .wizard__body, plus four footer buttons (#btn-back, #btn-next,
// #btn-cancel, #btn-help). nav.js drives transitions; per-step validation is
// owned by the page (e.g. encrypt.html toggling a "ready" flag on the section
// when its precondition is met).

window.Wizard = (function () {
  let current = 1;
  let total = 1;
  let onFinish = null;

  function el(id) { return document.getElementById(id); }

  function steps() { return Array.from(document.querySelectorAll(".wizard-step")); }

  function show(n) {
    const all = steps();
    if (n < 1) n = 1;
    if (n > total) n = total;
    current = n;
    all.forEach(s => {
      s.classList.toggle("active", parseInt(s.dataset.step, 10) === n);
    });
    refreshButtons();
    // If the active section has a focus target, focus it.
    const active = all.find(s => s.classList.contains("active"));
    if (active) {
      const f = active.querySelector("[data-autofocus]");
      if (f && typeof f.focus === "function") setTimeout(() => f.focus(), 0);
    }
  }

  // A step is "ready" if it has no `data-requires-ready` attribute, or if
  // its dataset.ready === "true". The page sets ready=true once preconditions
  // are met (typed serial matches, all warnings checked, etc.).
  function activeStepReady() {
    const all = steps();
    const active = all.find(s => parseInt(s.dataset.step, 10) === current);
    if (!active) return true;
    if (!("requiresReady" in active.dataset)) return true;
    return active.dataset.ready === "true";
  }

  function refreshButtons() {
    const back = el("btn-back");
    const next = el("btn-next");
    const cancel = el("btn-cancel");
    // Steps marked data-no-back (encryption running or finished) can't go
    // back: re-advancing would start a second encrypt of the same drive.
    const active = steps().find(s => parseInt(s.dataset.step, 10) === current);
    if (back)   back.disabled   = current === 1 || (active && "noBack" in active.dataset);
    if (cancel) cancel.disabled = false;
    if (next) {
      const isLast = current === total;
      next.textContent = isLast ? "Finish" : "Next >";
      next.disabled = !activeStepReady();
    }
  }

  function init(opts) {
    total = opts.total || steps().length;
    onFinish = opts.onFinish || (() => { window.location.href = "index.html"; });

    const back = el("btn-back");
    const next = el("btn-next");
    const cancel = el("btn-cancel");
    if (back)   back.addEventListener("click",   () => show(current - 1));
    if (next)   next.addEventListener("click",   () => {
      if (!activeStepReady()) return;
      if (current === total) { onFinish(); return; }
      // Allow page to react before the transition (e.g. start the progress timer).
      if (typeof opts.onAdvance === "function") opts.onAdvance(current, current + 1);
      show(current + 1);
    });
    if (cancel) cancel.addEventListener("click", () => Modal.confirmCancel(opts.onCancel));

    // Page can call markReady(stepNum, true/false) when its conditions change.
    show(1);
  }

  function markReady(stepNum, ready) {
    const sec = document.querySelector(`.wizard-step[data-step="${stepNum}"]`);
    if (!sec) return;
    sec.dataset.ready = ready ? "true" : "false";
    if (parseInt(sec.dataset.step, 10) === current) refreshButtons();
  }

  function go(n) { show(n); }
  function currentStep() { return current; }

  return { init, markReady, go, currentStep };
})();

// Modal helper: shows the cancel-confirmation dialog and calls onConfirm
// if the user clicks Yes. Reused by both wizards.
window.Modal = (function () {
  function el(id) { return document.getElementById(id); }
  function open(id)  { el(id).classList.add("open"); }
  function close(id) { el(id).classList.remove("open"); }

  function confirmCancel(onConfirm) {
    const m = el("modal-cancel");
    if (!m) {
      // Fall back to plain confirm() if the page didn't include the dialog.
      if (window.confirm("Cancel and return to the drive list?")) {
        if (typeof onConfirm === "function") onConfirm();
        else window.location.href = "index.html";
      }
      return;
    }
    m.classList.add("open");
    const yes = m.querySelector("[data-modal-yes]");
    const no  = m.querySelector("[data-modal-no]");
    function handleYes() {
      cleanup();
      if (typeof onConfirm === "function") onConfirm();
      else window.location.href = "index.html";
    }
    function handleNo() { cleanup(); }
    function cleanup() {
      m.classList.remove("open");
      yes.removeEventListener("click", handleYes);
      no.removeEventListener("click", handleNo);
    }
    yes.addEventListener("click", handleYes);
    no.addEventListener("click", handleNo);
  }

  return { open, close, confirmCancel };
})();
