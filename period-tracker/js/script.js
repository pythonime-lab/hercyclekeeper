"use strict";

// Import modular utilities
import { toISO, fromISO, addDays, diffDays, today } from "./dateUtils.js";
import { deriveKey, encryptData, decryptData, hashPin } from "./crypto.js";
import {
  resetSessionTimer,
  startCountdown,
  hideBanner,
  setLockApp,
} from "./session.js";
import {
  normalizeFlowValue,
  getFlowValueFromLog,
  normalizePainValue,
  getPainValueFromLog,
  normalizeMoodValue,
  getMoodValueFromLog,
  sanitize,
  safeText,
} from "./validators.js";
import {
  getCycleInfo,
  calculatePredictions,
  getDayType,
  isPredictedFuturePeriod,
  setState as setCyclesState,
} from "./cycles.js";
import { initKeyboardNavigation, setNavigationState } from "./navigation.js";
import { t, tp, applyI18n, setLanguage, getLanguage, getSupportedLanguages } from "./i18n.js";
import {
  cleanupEmptyLogs,
  setState as setPeriodMarkingState,
} from "./periodMarking.js";

const STORE_KEY = "yourcyclekeeper_enc_v1"; // encrypted blob
const SALT_KEY = "yourcyclekeeper_salt_v1"; // random salt (not secret)
const PINHASH_KEY = "yourcyclekeeper_ph_v1"; // HMAC of PIN for fast wrong-PIN detection
const BACKUP_KEY = "yourcyclekeeper_lastbackup_v1"; // ISO date of last export
const SCHEMA_VERSION = 1; // bump when state shape changes

// The old deriveKey, encryptData, decryptData, hashPin functions are now imported from crypto.js

async function getOrCreateSalt() {
  try {
    let s = await getFromDB(SALT_KEY);
    if (s) return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const encoded = btoa(String.fromCharCode(...salt));
    await setInDB(SALT_KEY, encoded);
    return salt;
  } catch (error) {
    console.error("🚨 Error in getOrCreateSalt:", error);
    showModal({
      icon: "⚠️",
      title: t("storage_error_title"),
      msg: t("storage_error_msg"),
      confirmText: t("ok"),
    });
    throw error;
  }
}

let state = {
  lastPeriodStart: null,
  cycleLength: 28,
  periodDuration: 5,
  logs: {},
  cycleHistory: [],
};

// Initialize modular state references
setCyclesState(state);
setPeriodMarkingState(state);

let sessionPin = null; // PIN held only in JS memory (never persisted)
let viewMonth = new Date();
let selectedDate = null;
let currentTab = "calendar";

// Reset on any user interaction (deferred until DOM ready)
function setupEventListeners() {
  ["touchstart", "touchend", "click", "keydown", "mousemove", "scroll"].forEach(
    (ev) =>
      document.addEventListener(
        ev,
        () => {
          if (sessionPin) resetSessionTimer();
        },
        { passive: true }
      )
  );
  const bannerEl = document.getElementById("timeout-banner");
  if (bannerEl) {
    bannerEl.addEventListener("click", () => {
      hideBanner();
      resetSessionTimer();
    });
  }

  // Add explicit touch handlers for mobile nav buttons (fixes iOS/mobile touch issues)
  const navButtons = document.querySelectorAll(".bnav-item");
  navButtons.forEach((btn) => {
    btn.addEventListener(
      "touchend",
      (e) => {
        e.preventDefault();
        const tab = btn.id.replace("bnav-", "");
        if (["calendar", "insights", "settings", "about", "support"].includes(tab)) {
          switchTab(tab);
        }
      },
      { passive: false }
    );
  });
}

function showToast(msg, duration = 2500) {
  let toast = document.getElementById("toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.id = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = msg;
  toast.classList.add("visible");
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => toast.classList.remove("visible"), duration);
}

function showModal({
  icon = "⚠️",
  title = "",
  msg = "",
  confirmText = "Confirm",
  cancelText = "Cancel",
  onConfirm,
  onCancel,
} = {}) {
  document.getElementById("modal-icon").textContent = icon;
  document.getElementById("modal-title").textContent = title;
  document.getElementById("modal-msg").textContent = msg;
  const confirmBtn = document.getElementById("modal-confirm");
  const cancelBtn = document.getElementById("modal-cancel");
  confirmBtn.textContent = confirmText;
  cancelBtn.textContent = cancelText || "";
  cancelBtn.style.display = cancelText ? "" : "none";
  const overlay = document.getElementById("modal-overlay");
  overlay.classList.add("visible");
  confirmBtn.onclick = () => {
    overlay.classList.remove("visible");
    onConfirm && onConfirm();
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
    onCancel && onCancel();
  };

  // Move focus into modal immediately (accessibility standard)
  setTimeout(() => {
    const focusTarget = cancelText ? cancelBtn : confirmBtn;
    if (focusTarget) {
      focusTarget.focus();
    }
  }, 0);
}

let pinBuffer = "";
let pinAttempts = 0;
let pinLockUntil = 0; // timestamp: locked until this ms (brute-force delay)
const MAX_ATTEMPTS = 5;
const LOCKOUT_MS = 60000; // 60-second lockout after 5 failed attempts

function updatePinDots(buf, prefix = "d") {
  for (let i = 0; i < 4; i++) {
    const el = document.getElementById(prefix + i);
    if (!el) return;
    el.classList.toggle("filled", i < buf.length);
  }
}

async function pinInput(digit) {
  if (pinBuffer.length >= 4) return;
  pinBuffer += digit;
  updatePinDots(pinBuffer);
  if (pinBuffer.length === 4) await submitPin();
}

function pinDelete() {
  pinBuffer = pinBuffer.slice(0, -1);
  updatePinDots(pinBuffer);
  document.getElementById("lock-error").textContent = "";
}

async function submitPin() {
  const pin = pinBuffer;
  pinBuffer = "";
  updatePinDots("");

  // Brute-force time-delay: refuse entry while locked out
  if (pinLockUntil && Date.now() < pinLockUntil) {
    const secsLeft = Math.ceil((pinLockUntil - Date.now()) / 1000);
    document.getElementById(
      "lock-error"
    ).textContent = t("too_many_attempts", { secs: secsLeft });
    return;
  }

  try {
    const salt = await getOrCreateSalt();
    const storedHash = await getFromDB(PINHASH_KEY);
    const attemptHash = await hashPin(pin, salt);

    if (attemptHash !== storedHash) {
      pinAttempts++;
      const remaining = MAX_ATTEMPTS - pinAttempts;
      const dots = document.querySelectorAll("#pin-dots .pin-dot");
      dots.forEach((d) => {
        d.classList.add("error");
        setTimeout(() => d.classList.remove("error"), 500);
      });
      if (remaining <= 0) {
        pinLockUntil = Date.now() + LOCKOUT_MS;
        document.getElementById("lock-error").textContent =
          t("locked_out");
        setTimeout(() => {
          // After lockout period: reset and allow retry without erasing
          pinAttempts = 0;
          pinLockUntil = 0;
          document.getElementById("lock-error").textContent =
            t("lockout_ended");
        }, LOCKOUT_MS);
      } else {
        document.getElementById(
          "lock-error"
        ).textContent = tp("incorrect_pin", remaining, { remaining });
      }
      return;
    }

    // PIN correct — decrypt data
    const blob = await getFromDB(STORE_KEY);
    if (blob) {
      try {
        state = await decryptData(blob, pin, salt);
        // Re-initialize module state references after loading encrypted data
        setCyclesState(state);
        setPeriodMarkingState(state);
      } catch {
        document.getElementById("lock-error").textContent =
          t("decryption_failed");
        return;
      }
    }
    pinAttempts = 0;
    sessionPin = pin;
    document.getElementById("lock-screen").classList.add("hidden");
    document.getElementById("app").style.display = "block";
    document.getElementById("bottom-nav").style.display = "flex";
    resetSessionTimer();
    viewMonth = new Date();
    updateStatusCard();
    renderCalendar();
    switchTab("calendar");
    updateInsights(); // Populate insights for desktop view
  } catch (error) {
    console.error("🚨 PIN submission error:", error);
    document.getElementById("lock-error").textContent =
      t("error_try_again");
  }
}

function lockApp() {
  sessionPin = null;
  state = {
    lastPeriodStart: null,
    cycleLength: 28,
    periodDuration: 5,
    logs: {},
    cycleHistory: [],
  };
  hideBanner();
  document.getElementById("app").style.display = "none";
  document.getElementById("bottom-nav").style.display = "none";
  document.getElementById("lock-screen").classList.remove("hidden");
  const logModal = document.getElementById("log-modal-overlay");
  if (logModal) logModal.classList.remove("visible");
  pinBuffer = "";
  updatePinDots("");
  document.getElementById("lock-error").textContent = "";
}

// Initialize session module with lockApp function
setLockApp(lockApp);

async function forgotPinFlow() {
  showModal({
    icon: "⚠️",
    title: t("forgot_pin_title"),
    msg: t("forgot_pin_msg"),
    confirmText: t("forgot_pin_confirm"),
    cancelText: t("cancel"),
    onConfirm: () => {
      // Second confirmation step
      showModal({
        icon: "⚠️",
        title: t("forgot_pin_confirm2_title"),
        msg: t("forgot_pin_confirm2_msg"),
        confirmText: t("forgot_pin_confirm2_btn"),
        cancelText: t("cancel"),
        onConfirm: async () => {
          try {
            await _executeForgotPinReset();
          } catch (error) {
            console.error("🚨 Reset error:", error);
            showModal({
              icon: "⚠️",
              title: t("reset_failed_title"),
              msg: t("reset_failed_msg"),
              confirmText: t("ok"),
            });
          }
        },
      });
    },
  });
}

async function _executeForgotPinReset() {
  try {
    await clearDB();
    sessionStorage.clear();
    state = {
      lastPeriodStart: null,
      cycleLength: 28,
      periodDuration: 5,
      logs: {},
      cycleHistory: [],
    };
    // Re-initialize module state references after creating new state
    setCyclesState(state);
    setPeriodMarkingState(state);
    pinAttempts = 0;
    pinLockUntil = 0;
    sessionPin = null;
    document.getElementById("lock-screen").classList.add("hidden");
    document.getElementById("onboarding").classList.remove("hidden");
    document.getElementById("app").style.display = "none";
    document.getElementById("bottom-nav").style.display = "none";
    document.getElementById("lock-error").textContent = "";
    showModal({
      icon: "✅",
      title: t("reset_complete_title"),
      msg: t("reset_complete_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
  } catch (error) {
    console.error("🚨 Reset error:", error);
    showModal({
      icon: "⚠️",
      title: t("reset_failed_title"),
      msg: t("reset_failed_msg"),
      confirmText: t("ok"),
    });
  }
}

async function save() {
  if (!sessionPin) return;
  try {
    const salt = await getOrCreateSalt();
    const enc = await encryptData(state, sessionPin, salt);
    try {
      await setInDB(STORE_KEY, enc);
    } catch (e) {
      if (e.name === "QuotaExceededError" || e.name === "NS_ERROR_DOM_QUOTA_REACHED") {
        showModal({
          icon: "⚠️",
          title: t("storage_full_title"),
          msg: t("storage_full_msg"),
          confirmText: t("ok"),
        });
        return;
      }
      throw e;
    }
  } catch (error) {
    console.error("🚨 Save error:", error);
    showModal({
      icon: "⚠️",
      title: t("save_failed_title"),
      msg: t("save_failed_msg"),
      confirmText: t("ok"),
    });
  }
}

let setupPin = "";

function setupPinInput(digit) {
  if (setupPin.length >= 4) return;
  setupPin += digit;
  for (let i = 0; i < 4; i++) {
    const el = document.getElementById("sp" + i);
    if (el) el.classList.toggle("filled", i < setupPin.length);
  }
  if (setupPin.length === 4) {
    document.getElementById("onboard-start-btn").disabled = false;
  }
}

function setupPinDelete() {
  setupPin = setupPin.slice(0, -1);
  for (let i = 0; i < 4; i++) {
    const el = document.getElementById("sp" + i);
    if (el) el.classList.toggle("filled", i < setupPin.length);
  }
  document.getElementById("onboard-start-btn").disabled = true;
}

async function startApp() {
  const lp = document.getElementById("ob-last-period").value;
  const cl = parseInt(document.getElementById("ob-cycle-len").value);
  const pd = parseInt(document.getElementById("ob-period-dur").value);
  if (!lp) {
    showModal({
      icon: "📅",
      title: t("missing_date_title"),
      msg: t("missing_date_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
    return;
  }
  if (setupPin.length < 4) {
    showModal({
      icon: "🔢",
      title: t("set_pin_title"),
      msg: t("set_pin_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
    return;
  }

  try {
    state.lastPeriodStart = lp;
    state.cycleLength = cl || 28;
    state.periodDuration = pd || 5;
    state.cycleHistory = [{ start: lp, length: cl || 28 }];
    sessionPin = setupPin;

    const salt = await getOrCreateSalt();
    const pinHash = await hashPin(setupPin, salt);
    await setInDB(PINHASH_KEY, pinHash);
    await save();

    document.getElementById("onboarding").classList.add("hidden");
    document.getElementById("lock-screen").classList.add("hidden");
    document.getElementById("app").style.display = "block";
    document.getElementById("bottom-nav").style.display = "flex";
    resetSessionTimer();
    viewMonth = new Date();
    updateStatusCard();
    renderCalendar();
    updateInsights();
    switchTab("calendar");
  } catch (error) {
    console.error("🚨 App startup error:", error);
    showModal({
      icon: "⚠️",
      title: t("setup_error_title"),
      msg: t("setup_error_msg"),
      confirmText: t("ok"),
    });
  }
}

// Date utility functions are now imported from dateUtils.js

// Cycle functions are now imported from cycles.js
// They were: getCycleInfo, calculatePredictions, getDayType, isPredictedFuturePeriod

// Validator functions are now imported from validators.js
// They were: sanitize, safeText

function updateNoteCount() {
  const ta = document.getElementById("log-note");
  const el = document.getElementById("note-limit");
  if (ta && el) el.textContent = t("note_count", { count: ta.value.length });
}

let currentFlowValue = 1;
let currentFlowSet = false;
let currentMoodValue = 50;
let currentMoodSet = false;
let currentPainValue = 5;
let currentPainSet = false;

async function autoSaveSymptomSelection() {
  if (!selectedDate || !/^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) return;

  const noteEl = document.getElementById("log-note");
  const rawNote = noteEl ? noteEl.value : "";
  const log = {};

  if (currentFlowSet) {
    log.flow = normalizeFlowValue(currentFlowValue, 1);
    updateCycleHistory(selectedDate);
  }

  if (currentPainSet) {
    log.pain = normalizePainValue(currentPainValue, 5);
  }

  if (currentMoodSet) {
    log.mood = normalizeMoodValue(currentMoodValue, 50);
  }

  log.note = rawNote.slice(0, 500).replace(/[<>]/g, "");

  state.logs[selectedDate] = log;
  cleanupEmptyLogs();
  await save();
  renderCalendar();
  updateStatusCard();
  updateInsights();
}

// ── Autosave note debounce ──────────────────────────────────────────────
let _noteSaveTimer = null;
function scheduleAutoSaveNote() {
  // Show "saving…" feel
  const indicator = document.getElementById("autosave-indicator");
  if (indicator) {
    indicator.textContent = "Saving…";
    indicator.classList.add("visible");
  }
  clearTimeout(_noteSaveTimer);
  _noteSaveTimer = setTimeout(async () => {
    await autoSaveSymptomSelection();
    showAutosaveIndicator();
  }, 800);
}

function showAutosaveIndicator() {
  const indicator = document.getElementById("autosave-indicator");
  if (!indicator) return;
  indicator.textContent = "All changes saved \u2713";
  indicator.classList.add("visible");
  setTimeout(() => {
    indicator.classList.remove("visible");
  }, 2500);
}

async function resetLogWithConfirm() {
  // Two-tap confirmation: first click shows confirm state, second click resets
  const btn = document.getElementById("log-reset-btn");
  if (!btn) return;

  if (btn.dataset.confirming === "true") {
    // Second tap — actually reset
    btn.dataset.confirming = "false";
    btn.textContent = "\u21ba Reset day";
    btn.classList.remove("confirming");
    clearTimeout(btn._confirmTimer);
    await deleteLog();
    showAutosaveIndicator();
  } else {
    // First tap — ask for confirmation
    btn.dataset.confirming = "true";
    btn.textContent = "Tap again to reset";
    btn.classList.add("confirming");
    btn._confirmTimer = setTimeout(() => {
      btn.dataset.confirming = "false";
      btn.textContent = "\u21ba Reset day";
      btn.classList.remove("confirming");
    }, 3000);
  }
}

async function deleteLog() {
  if (!selectedDate || !/^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) return;

  // Remove the log entry
  delete state.logs[selectedDate];

  // Clear the UI
  currentFlowSet = false;
  currentPainSet = false;
  currentMoodSet = false;
  updateFlowButtonVisual(1, false);
  updatePainButtonVisual(5, false);
  updateMoodButtonVisual(50, false);

  const noteEl = document.getElementById("log-note");
  if (noteEl) noteEl.value = "";
  updateNoteCount();

  // Update cycle history if it was a flow entry
  updateCycleHistory(selectedDate);

  // Save and refresh
  await save();
  renderCalendar();
  updateStatusCard();
  updateInsights();
}

function flowIconFromValue(value) {
  const v = normalizeFlowValue(value, 1);
  if (v === 1) return "🩸";
  if (v === 2) return "🩸🩸";
  return "🩸🩸🩸";
}

function flowLabelFromValue(value) {
  const v = normalizeFlowValue(value, 1);
  if (v === 1) return "🩸";
  if (v === 2) return "🩸🩸";
  return "🩸🩸🩸";
}

function updateFlowButtonVisual(value, isSet = true) {
  const v = normalizeFlowValue(value, 1);
  currentFlowValue = v;
  currentFlowSet = isSet;

  const flowBtn = document.getElementById("log-flow");
  const flowIcon = document.getElementById("log-flow-icon");

  if (flowBtn) {
    if (isSet) {
      flowBtn.classList.add("active-flow");
      flowBtn.style.borderColor = "";
      flowBtn.style.background = "";
      flowBtn.style.color = "";
    } else {
      flowBtn.classList.remove("active-flow");
      flowBtn.style.borderColor = "";
      flowBtn.style.background = "";
      flowBtn.style.color = "";
    }
  }
  if (flowIcon) flowIcon.textContent = flowIconFromValue(v);
}

function flowWordLabelFromValue(value) {
  const v = normalizeFlowValue(value, 1);
  if (v === 1) return t("flow_light");
  if (v === 2) return t("flow_medium");
  return t("flow_heavy");
}

function updateFlowModalPreview(value) {
  const slider = document.getElementById("flow-modal-slider");
  const label = document.getElementById("flow-modal-value");
  const wordLabel = document.getElementById("flow-modal-word");
  if (!slider || !label) return;
  const v = normalizeFlowValue(value, 1);
  slider.style.accentColor = "#FF3D6B";
  label.textContent = flowLabelFromValue(v);
  label.style.color = "var(--rose)";
  label.style.whiteSpace = "nowrap";
  label.style.letterSpacing = "-0.22em";
  label.style.lineHeight = "1";
  if (wordLabel) wordLabel.textContent = flowWordLabelFromValue(v);
}

function showFlowModal() {
  const overlay = document.getElementById("modal-overlay");
  const iconEl = document.getElementById("modal-icon");
  const titleEl = document.getElementById("modal-title");
  const msgEl = document.getElementById("modal-msg");
  const confirmBtn = document.getElementById("modal-confirm");
  const cancelBtn = document.getElementById("modal-cancel");

  if (!overlay || !iconEl || !titleEl || !msgEl || !confirmBtn || !cancelBtn)
    return;

  iconEl.textContent = "🩸";
  titleEl.textContent = t("set_flow");
  msgEl.textContent = "";

  const wrap = document.createElement("div");
  wrap.className = "flow-modal-wrap";
  const valueEl = document.createElement("div");
  valueEl.id = "flow-modal-value";
  valueEl.className = "flow-modal-value";
  const wordEl = document.createElement("div");
  wordEl.id = "flow-modal-word";
  wordEl.style.cssText = "font-size:0.875rem;color:var(--text-muted);margin-top:0.25rem;text-align:center;";
  const slider = document.createElement("input");
  slider.type = "range";
  slider.min = "1";
  slider.max = "3";
  slider.step = "1";
  slider.value = String(currentFlowValue);
  slider.id = "flow-modal-slider";
  slider.className = "flow-modal-slider";
  slider.addEventListener("input", (e) =>
    updateFlowModalPreview(e.target.value)
  );
  wrap.appendChild(valueEl);
  wrap.appendChild(wordEl);
  wrap.appendChild(slider);
  msgEl.appendChild(wrap);

  confirmBtn.textContent = t("save");
  cancelBtn.textContent = t("cancel");
  cancelBtn.style.display = "";

  updateFlowModalPreview(currentFlowValue);

  confirmBtn.onclick = async () => {
    const v = normalizeFlowValue(slider.value, 1);
    updateFlowButtonVisual(v, true);
    overlay.classList.remove("visible");
    await autoSaveSymptomSelection();
    showAutosaveIndicator();
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
  };

  overlay.classList.add("visible");

  // Move focus to slider immediately
  setTimeout(() => {
    if (slider) {
      slider.focus();
    }
  }, 0);
}

function painColorFromValue(value) {
  const v = normalizePainValue(value, 5);
  const t = (v - 1) / 9;
  const low = { r: 255, g: 179, b: 71 }; // #FFB347 (light orange)
  const high = { r: 255, g: 140, b: 0 }; // #FF8C00 (dark orange)
  const r = Math.round(low.r + (high.r - low.r) * t);
  const g = Math.round(low.g + (high.g - low.g) * t);
  const b = Math.round(low.b + (high.b - low.b) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

function painLabelFromValue(value) {
  const v = normalizePainValue(value, 5);
  return t("pain_label", { value: v.toFixed(1) });
}

function updatePainButtonVisual(value, isSet = true) {
  const v = normalizePainValue(value, 5);
  currentPainValue = v;
  currentPainSet = isSet;

  const painBtn = document.getElementById("log-headache");
  const painIcon = document.getElementById("log-pain-icon");
  const col = painColorFromValue(v);

  if (painBtn) {
    if (isSet) {
      painBtn.classList.add("active-symptom");
      painBtn.style.borderColor = col;
      painBtn.style.background = "rgba(255, 255, 255, 0.06)";
      painBtn.style.color = col;
    } else {
      painBtn.classList.remove("active-symptom");
      painBtn.style.borderColor = "";
      painBtn.style.background = "";
      painBtn.style.color = "";
    }
  }
  if (painIcon) painIcon.textContent = "🤕";
  const painLabel = document.getElementById("log-pain-label");
  if (painLabel) painLabel.textContent = isSet ? `Pain: ${v.toFixed(1)}/10` : "Pain";
}

function updatePainModalPreview(value) {
  const slider = document.getElementById("pain-modal-slider");
  const label = document.getElementById("pain-modal-value");
  if (!slider || !label) return;
  const v = normalizePainValue(value, 5);
  const col = painColorFromValue(v);
  slider.style.accentColor = col;
  label.textContent = painLabelFromValue(v);
  label.style.color = col;
}

function showPainModal() {
  const overlay = document.getElementById("modal-overlay");
  const iconEl = document.getElementById("modal-icon");
  const titleEl = document.getElementById("modal-title");
  const msgEl = document.getElementById("modal-msg");
  const confirmBtn = document.getElementById("modal-confirm");
  const cancelBtn = document.getElementById("modal-cancel");

  if (!overlay || !iconEl || !titleEl || !msgEl || !confirmBtn || !cancelBtn)
    return;

  iconEl.textContent = "🤕";
  titleEl.textContent = t("set_pain");
  msgEl.textContent = "";

  const wrap = document.createElement("div");
  wrap.className = "pain-modal-wrap";
  const valueEl = document.createElement("div");
  valueEl.id = "pain-modal-value";
  valueEl.className = "pain-modal-value";
  const slider = document.createElement("input");
  slider.type = "range";
  slider.min = "1";
  slider.max = "10";
  slider.step = "0.5";
  slider.value = String(currentPainValue);
  slider.id = "pain-modal-slider";
  slider.className = "pain-modal-slider";
  slider.addEventListener("input", (e) =>
    updatePainModalPreview(e.target.value)
  );
  wrap.appendChild(valueEl);
  wrap.appendChild(slider);
  msgEl.appendChild(wrap);

  confirmBtn.textContent = t("save");
  cancelBtn.textContent = t("cancel");
  cancelBtn.style.display = "";

  updatePainModalPreview(currentPainValue);

  confirmBtn.onclick = async () => {
    const v = normalizePainValue(slider.value, 5);
    updatePainButtonVisual(v, true);
    overlay.classList.remove("visible");
    await autoSaveSymptomSelection();
    showAutosaveIndicator();
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
  };

  overlay.classList.add("visible");

  // Move focus to slider immediately
  setTimeout(() => {
    if (slider) {
      slider.focus();
    }
  }, 0);
}

function moodColorFromValue(value) {
  const v = normalizeMoodValue(value, 50);
  const t = v / 100;
  const low = { r: 139, g: 127, b: 232 }; // #8B7FE8
  const high = { r: 46, g: 204, b: 113 }; // #2ECC71
  const r = Math.round(low.r + (high.r - low.r) * t);
  const g = Math.round(low.g + (high.g - low.g) * t);
  const b = Math.round(low.b + (high.b - low.b) * t);
  return `rgb(${r}, ${g}, ${b})`;
}

function moodLabelFromValue(value) {
  const v = normalizeMoodValue(value, 50);
  if (v < 35) return t("mood_low");
  if (v > 65) return t("mood_happy");
  return t("mood_neutral");
}

function moodIconFromValue(value) {
  const v = normalizeMoodValue(value, 50);
  if (v < 35) return "😔";
  if (v > 65) return "😊";
  return "😐";
}

function updateMoodButtonVisual(value, isSet = true) {
  const v = normalizeMoodValue(value, 50);
  currentMoodValue = v;
  currentMoodSet = isSet;

  const moodBtn = document.getElementById("log-mood");
  const moodIcon = document.getElementById("log-mood-icon");
  const col = moodColorFromValue(v);

  if (moodBtn) {
    if (isSet) {
      moodBtn.classList.add("active-mood");
      moodBtn.style.borderColor = col;
      moodBtn.style.background = "rgba(255, 255, 255, 0.06)";
      moodBtn.style.color = col;
    } else {
      moodBtn.classList.remove("active-mood");
      moodBtn.style.borderColor = "";
      moodBtn.style.background = "";
      moodBtn.style.color = "";
    }
  }
  if (moodIcon) moodIcon.textContent = moodIconFromValue(v);
}

function updateMoodModalPreview(value) {
  const slider = document.getElementById("mood-modal-slider");
  const label = document.getElementById("mood-modal-value");
  if (!slider || !label) return;
  const v = normalizeMoodValue(value, 50);
  const col = moodColorFromValue(v);
  slider.style.accentColor = col;
  label.textContent = moodLabelFromValue(v);
  label.style.color = col;
}

function showMoodModal() {
  const overlay = document.getElementById("modal-overlay");
  const iconEl = document.getElementById("modal-icon");
  const titleEl = document.getElementById("modal-title");
  const msgEl = document.getElementById("modal-msg");
  const confirmBtn = document.getElementById("modal-confirm");
  const cancelBtn = document.getElementById("modal-cancel");

  if (!overlay || !iconEl || !titleEl || !msgEl || !confirmBtn || !cancelBtn)
    return;

  iconEl.textContent = "🎚️";
  titleEl.textContent = t("set_mood");
  msgEl.textContent = "";

  const wrap = document.createElement("div");
  wrap.className = "mood-modal-wrap";
  const valueEl = document.createElement("div");
  valueEl.id = "mood-modal-value";
  valueEl.className = "mood-modal-value";
  const slider = document.createElement("input");
  slider.type = "range";
  slider.min = "0";
  slider.max = "100";
  slider.step = "50";
  slider.value = String(currentMoodValue);
  slider.id = "mood-modal-slider";
  slider.className = "mood-modal-slider";
  slider.addEventListener("input", (e) =>
    updateMoodModalPreview(e.target.value)
  );

  const tickLabels = document.createElement("div");
  tickLabels.style.display = "flex";
  tickLabels.style.justifyContent = "space-between";
  tickLabels.style.fontSize = "1.25rem";
  tickLabels.style.marginTop = "0.5rem";
  tickLabels.style.padding = "0 0.5rem";
  tickLabels.style.cursor = "pointer";
  ["😔", "😐", "😊"].forEach((emoji, idx) => {
    const span = document.createElement("span");
    span.textContent = emoji;
    // allow clicking emoji to change slider
    span.onclick = () => {
      slider.value = idx * 50;
      updateMoodModalPreview(slider.value);
    };
    tickLabels.appendChild(span);
  });

  wrap.appendChild(valueEl);
  wrap.appendChild(slider);
  wrap.appendChild(tickLabels);
  msgEl.appendChild(wrap);

  confirmBtn.textContent = t("save");
  cancelBtn.textContent = t("cancel");
  cancelBtn.style.display = "";

  updateMoodModalPreview(currentMoodValue);

  confirmBtn.onclick = async () => {
    const v = normalizeMoodValue(slider.value, 50);
    updateMoodButtonVisual(v, true);
    overlay.classList.remove("visible");
    await autoSaveSymptomSelection();
    showAutosaveIndicator();
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
  };

  overlay.classList.add("visible");

  // Move focus to slider immediately
  setTimeout(() => {
    if (slider) {
      slider.focus();
    }
  }, 0);
}

function updateStatusCard() {
  const info = getCycleInfo();
  const emptyHint = document.getElementById("status-empty-hint");
  if (!info) {
    if (emptyHint) {
      emptyHint.textContent = t("status_no_data_hint");
      emptyHint.classList.remove("hidden");
    }
    return;
  }
  if (emptyHint) emptyHint.classList.add("hidden");
  const phaseTagKey = {
    Menstruation: "period_short",
    Follicular: "follicular",
    "Fertile Window": "fertile",
    Ovulation: "ovulation_short",
    Luteal: "luteal",
  }[info.phase] || "period_short";
  const phaseEl = document.getElementById("status-phase");
  if (phaseEl) phaseEl.style.color = info.phaseColor;

  safeText("status-phase-text", t(phaseTagKey).toUpperCase());
  safeText("status-title", getPhaseMessage(info));

  // Hide subtitle if the reminder chip captures the same 'Next period in X days' info
  const showReminder = info.daysUntilNext > 0 && info.daysUntilNext <= 3;
  safeText("status-subtitle", showReminder ? "" : getPhaseSubtitle(info));

  safeText("cycle-day", info.cycleDay);
  safeText(
    "days-until-next",
    info.daysUntilNext > 0 ? info.daysUntilNext : t("now")
  );
  safeText("cycle-len-disp", info.cl);
  updateCycleBar(info);
  updateReminderBanner(info);
}

function updateReminderBanner(info) {
  const banner = document.getElementById("reminder-banner");
  const text = document.getElementById("reminder-text");
  if (!banner || !text || !info) return;

  // Show banner if period is coming within 3 days
  if (info.daysUntilNext > 0 && info.daysUntilNext <= 3) {
    text.textContent = tp("period_expected_in", info.daysUntilNext);
    banner.style.display = "flex";
  } else {
    banner.style.display = "none";
  }
}

function getPhaseMessage(info) {
  if (info.phase === "Menstruation") return t("phase_menstruation");
  if (info.phase === "Follicular") return t("phase_follicular");
  if (info.phase === "Fertile Window") return t("phase_fertile");
  if (info.phase === "Ovulation Day") return t("phase_ovulation");
  return t("phase_luteal");
}
function getPhaseSubtitle(info) {
  if (info.phase === "Menstruation")
    return t("subtitle_menstruation", { day: info.cycleDay });
  if (info.phase === "Fertile Window")
    return t("subtitle_fertile", { start: info.fertileStart, end: info.fertileEnd });
  if (info.phase === "Ovulation Day") return t("subtitle_ovulation");
  return t("subtitle_other", { n: info.daysUntilNext });
}

function updateCycleBar(info) {
  const bar = document.getElementById("cycle-bar");
  safeText("bar-cycle-end", t("bar_day", { n: info.cl }));
  const segs = [
    { c: "linear-gradient(90deg,#FF3D6B,#FF6B4A)", w: info.pd },
    {
      c: "linear-gradient(90deg,#FF6B4A,#FFB347)",
      w: info.fertileStart - info.pd - 1,
    },
    {
      c: "linear-gradient(90deg,#34D399,#2DD4BF)",
      w: info.fertileEnd - info.fertileStart + 1,
    },
    { c: "#F59E0B", w: 1 },
    {
      c: "linear-gradient(90deg,#A78BFA,#7C3AED)",
      w: info.cl - info.fertileEnd - 1,
    },
  ];
  bar.innerHTML = "";
  let left = 0;
  segs.forEach((s) => {
    if (s.w <= 0) {
      left += s.w;
      return;
    }
    const seg = document.createElement("div");
    seg.style.cssText = `position:absolute;top:0;height:100%;border-radius:999px;left:${(
      (left / info.cl) *
      100
    ).toFixed(2)}%;width:${((s.w / info.cl) * 100).toFixed(2)}%;background:${
      s.c
    };`;
    bar.appendChild(seg);
    left += s.w;
  });
  const todayPct = ((getCycleInfo().cycleDay - 1) / info.cl) * 100;
  if (todayPct >= 0 && todayPct <= 100) {
    const m = document.createElement("div");
    m.className = "today-marker";
    m.style.left = todayPct.toFixed(2) + "%";
    bar.appendChild(m);
  }
}

function updateInsights() {
  const info = getCycleInfo();
  if (!info) return;
  safeText("avg-cycle", info.cl + "d");
  safeText("avg-period", info.pd + "d");
  safeText("tracked-cycles", state.cycleHistory.length || 1);
  safeText("fertile-window", info.fertileEnd - info.fertileStart + 1);

  const hist = document.getElementById("cycle-history");
  const histCount = document.getElementById("history-count");
  if (!state.cycleHistory || state.cycleHistory.length === 0) {
    hist.innerHTML = "";
    const p = document.createElement("p");
    p.style.cssText = "color:var(--text-muted);font-size:0.875rem";
    p.textContent = t("no_cycle_history");
    hist.appendChild(p);
    if (histCount) histCount.textContent = "";
    return;
  }
  hist.innerHTML = "";
  const total = state.cycleHistory.length;
  const shown = Math.min(6, total);
  [...state.cycleHistory]
    .slice(-6)
    .reverse()
    .forEach((c) => {
      const row = document.createElement("div");
      row.className = "history-row";
      const dateSpan = document.createElement("span");
      dateSpan.textContent = c.start; // sanitized via textContent
      const lenSpan = document.createElement("span");
      lenSpan.className = "history-len";
      const col =
        c.length < 26 ? "#34D399" : c.length > 32 ? "#FF6B4A" : "#A78BFA";
      lenSpan.style.cssText = `background:${col}22;color:${col}`;
      lenSpan.textContent = tp("history_days", parseInt(c.length)); // parseInt guards injections
      row.appendChild(dateSpan);
      row.appendChild(lenSpan);
      hist.appendChild(row);
    });
  if (histCount) {
    histCount.textContent = total > 6 ? t("history_showing", { shown, total }) : "";
  }

  // Ensure chart controls are initialized
  const yearSelect = document.getElementById("pain-view-year");
  if (yearSelect && yearSelect.options.length === 0) {
    initializePainChartControls();
  }
  renderPainChart();
}

function initializePainChartControls() {
  const monthSelect = document.getElementById("pain-view-month");
  const yearSelect = document.getElementById("pain-view-year");
  const now = new Date();
  const currentYear = now.getFullYear();
  const currentMonth = now.getMonth();

  // Set to 'All Months' by default to show full year
  if (monthSelect) monthSelect.value = "";

  // Populate year dropdown with last 5 years
  if (yearSelect) {
    for (let i = 0; i < 5; i++) {
      const year = currentYear - i;
      const option = document.createElement("option");
      option.value = String(year);
      option.textContent = String(year);
      option.style.cssText = "background: #1a1a2e; color: white;";
      yearSelect.appendChild(option);
    }
    yearSelect.value = String(currentYear);
  }
}

let activeChartFilter = "all";

function setChartFilter(filter) {
  if (activeChartFilter === filter) {
    activeChartFilter = "all";
  } else {
    activeChartFilter = filter;
  }
  updateChartLegendUI();
  updatePainChart();
}

function updateChartLegendUI() {
  const items = ["period", "ovulation", "flow", "pain", "mood"];
  items.forEach((item) => {
    const el = document.getElementById("legend-" + item);
    if (!el) return;
    if (activeChartFilter === "all") {
      el.style.opacity = "1";
      el.style.backgroundColor = "transparent";
      el.setAttribute("aria-pressed", "true");
    } else if (activeChartFilter === item) {
      el.style.opacity = "1";
      el.style.backgroundColor = "rgba(255, 255, 255, 0.1)";
      el.setAttribute("aria-pressed", "true");
    } else {
      el.style.opacity = "0.3";
      el.style.backgroundColor = "transparent";
      el.setAttribute("aria-pressed", "false");
    }
  });
}

function updatePainChart() {
  renderPainChart();
}

function renderPainChart() {
  const canvas = document.getElementById("pain-chart");
  if (!canvas) return;

  const ctx = canvas.getContext("2d");
  const container = canvas.parentElement;
  const rect = container.getBoundingClientRect();

  // If canvas is hidden or no width, skip rendering
  if (rect.width === 0) {
    setTimeout(() => renderPainChart(), 100);
    return;
  }

  const dpr = window.devicePixelRatio || 1;
  const width = rect.width;
  const height = 300;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  canvas.style.height = height + "px";
  ctx.scale(dpr, dpr);

  const padding = { top: 25, right: 0, bottom: 40, left: 0 };
  const chartWidth = width; // Fill container fully
  const chartHeight = height - padding.top - padding.bottom;

  // Clear canvas
  ctx.clearRect(0, 0, width, height);

  // Get selected month and year
  const monthSelect = document.getElementById("pain-view-month");
  const yearSelect = document.getElementById("pain-view-year");
  const selectedMonthValue = monthSelect ? monthSelect.value : "";
  const selectedYear = yearSelect
    ? parseInt(yearSelect.value)
    : new Date().getFullYear();

  // Get data for selected period
  const isYearView = selectedMonthValue === "";
  const data = isYearView
    ? getPainDataYear(selectedYear)
    : getPainDataMonth(selectedYear, parseInt(selectedMonthValue));



  // Draw grid lines
  ctx.strokeStyle = "rgba(255, 255, 255, 0.1)";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padding.top + (chartHeight / 4) * i;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(padding.left + chartWidth, y);
    ctx.stroke();
  }

  // Draw axes
  ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
  ctx.lineWidth = 2;
  ctx.beginPath();
  ctx.moveTo(padding.left, padding.top);
  ctx.lineTo(padding.left, padding.top + chartHeight);
  ctx.lineTo(padding.left + chartWidth, padding.top + chartHeight);
  ctx.stroke();

  // Draw bars and markers
  const barWidth = chartWidth / data.length;

  data.forEach((point, i) => {
    const x = padding.left + i * barWidth + barWidth / 2;
    const baseY = padding.top + chartHeight;

    // Draw period background (only in month view, not year view)
    if (
      point.isPeriod &&
      !isYearView &&
      (activeChartFilter === "all" || activeChartFilter === "period")
    ) {
      ctx.fillStyle = "rgba(255, 61, 107, 0.15)";
      ctx.fillRect(
        padding.left + i * barWidth,
        padding.top,
        barWidth,
        chartHeight
      );
    }

    // Draw ovulation marker (only in month view, not year view)
    if (
      point.isOvulation &&
      !isYearView &&
      (activeChartFilter === "all" || activeChartFilter === "ovulation")
    ) {
      ctx.fillStyle = "rgba(255, 215, 0, 0.3)";
      ctx.fillRect(
        padding.left + i * barWidth,
        padding.top,
        barWidth,
        chartHeight
      );
    }

    // Draw symptom bars
    const symptoms = [];
    if (
      point.hasFlow &&
      (activeChartFilter === "all" || activeChartFilter === "flow")
    )
      symptoms.push({
        color: "#FF3D6B",
        intensity: point.flowIntensity || 1,
      });
    if (
      point.hasPain &&
      (activeChartFilter === "all" || activeChartFilter === "pain")
    )
      symptoms.push({
        color: "#FF6B4A",
        intensity: point.painIntensity || 1,
      });
    if (
      point.hasMood &&
      (activeChartFilter === "all" || activeChartFilter === "mood")
    )
      symptoms.push({
        isGradient: true,
        gradientColors: ["#8B7FE8", "#2ECC71"], // Purple (bottom) to Green (top)
        intensity: point.moodIntensity,
      });

    if (symptoms.length > 0) {
      // Fix segment width to always be 1/3 of the allocated day width
      const segmentWidth = (barWidth * 0.7) / 3;
      // Center the group of actual symptoms within the day's barWidth
      const groupWidth = symptoms.length * segmentWidth;
      const startX = padding.left + i * barWidth + (barWidth - groupWidth) / 2;

      symptoms.forEach((symptom, idx) => {
        const barHeight = chartHeight * 0.8 * symptom.intensity;

        if (symptom.isGradient) {
          // Determine gradient scale based on the total possible height
          const grad = ctx.createLinearGradient(
            0,
            baseY,
            0,
            baseY - chartHeight * 0.8
          );
          grad.addColorStop(0, symptom.gradientColors[0]);
          grad.addColorStop(1, symptom.gradientColors[1]);
          ctx.fillStyle = grad;
        } else {
          ctx.fillStyle = symptom.color;
        }

        ctx.fillRect(
          startX + idx * segmentWidth,
          baseY - barHeight,
          segmentWidth * 0.9,
          barHeight
        );
      });
    }
  });

  // Draw labels
  ctx.fillStyle = "#999";
  ctx.font =
    data.length > 20 && chartWidth < 350 ? "9px sans-serif" : "11px sans-serif";
  ctx.textAlign = "center";

  data.forEach((point, i) => {
    const x = padding.left + i * barWidth + barWidth / 2;
    ctx.fillText(point.label, x, padding.top + chartHeight + 20);
  });
}

function getPainDataMonth(year, month) {
  const data = [];
  if (year === undefined || month === undefined) {
    const now = new Date();
    year = now.getFullYear();
    month = now.getMonth();
  }
  const daysInMonth = new Date(year, month + 1, 0).getDate();

  const info = getCycleInfo();

  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${String(month + 1).padStart(2, "0")}-${String(
      d
    ).padStart(2, "0")}`;
    const dayType = getDayType(dateStr);
    const log = state.logs[dateStr] || {};
    const flowValue = getFlowValueFromLog(log);
    const painValue = getPainValueFromLog(log);
    const moodValue = getMoodValueFromLog(log);

    data.push({
      label: String(d),
      hasFlow: flowValue !== null,
      flowIntensity: flowValue === null ? 0 : flowValue / 3,
      hasPain: painValue !== null,
      painIntensity: painValue === null ? 0 : painValue / 10,
      hasMood: moodValue !== null,
      moodValue,
      moodIntensity: moodValue === null ? 0 : Math.max(0.1, moodValue / 100),
      isPeriod: dayType.includes("period"),
      isOvulation: dayType === "ovulation",
    });
  }

  return data;
}

function getPainDataYear(year) {
  const data = [];
  if (year === undefined) {
    const now = new Date();
    year = now.getFullYear();
  }

  for (let m = 0; m < 12; m++) {
    const monthStart = new Date(year, m, 1);
    const monthEnd = new Date(year, m + 1, 0);

    let flowSum = 0;
    let flowCount = 0;
    let painSum = 0;
    let painCount = 0;
    let moodSum = 0;
    let moodCount = 0;
    let periodDays = 0;
    let totalDays = monthEnd.getDate();

    for (let d = 1; d <= totalDays; d++) {
      const dateStr = `${year}-${String(m + 1).padStart(2, "0")}-${String(
        d
      ).padStart(2, "0")}`;
      const log = state.logs[dateStr] || {};
      const dayType = getDayType(dateStr);
      const flowValue = getFlowValueFromLog(log);
      const painValue = getPainValueFromLog(log);
      const moodValue = getMoodValueFromLog(log);

      if (flowValue !== null) {
        flowSum += flowValue;
        flowCount++;
      }
      if (painValue !== null) {
        painSum += painValue;
        painCount++;
      }
      if (moodValue !== null) {
        moodSum += moodValue;
        moodCount++;
      }
      if (dayType.includes("period")) periodDays++;
    }

    const avgFlow = flowCount > 0 ? flowSum / flowCount : null;
    const avgPain = painCount > 0 ? painSum / painCount : null;
    const avgMood = moodCount > 0 ? moodSum / moodCount : null;

    data.push({
      label: monthStart.toLocaleString(getLanguage(), { month: "short" }),
      hasFlow: flowCount > 0,
      hasPain: painCount > 0,
      hasMood: moodCount > 0,
      flowValue: avgFlow,
      painValue: avgPain,
      moodValue: avgMood,
      flowIntensity: avgFlow === null ? 0 : avgFlow / 3,
      painIntensity: avgPain === null ? 0 : avgPain / 10,
      moodIntensity: avgMood === null ? 0 : Math.max(0.1, avgMood / 100),
      isPeriod: periodDays > 0,
      isOvulation: false,
    });
  }

  return data;
}

function downloadChart() {
  const originalCanvas = document.getElementById("pain-chart");
  if (!originalCanvas) return;

  try {
    const monthSelect = document.getElementById("pain-view-month");
    const yearSelect = document.getElementById("pain-view-year");
    const selectedMonth = monthSelect?.value || "";
    const selectedYear = yearSelect?.value || new Date().getFullYear();

    // Create month/year label
    let periodLabel;
    if (selectedMonth === "") {
      periodLabel = t("chart_full_year", { year: selectedYear });
    } else {
      const monthName = new Date(
        selectedYear,
        parseInt(selectedMonth)
      ).toLocaleString(getLanguage(), { month: "long" });
      periodLabel = t("chart_month_year", { month: monthName, year: selectedYear });
    }

    // Create a new canvas with header and footer
    const headerHeight = 100;
    const footerHeight = 40;
    const exportCanvas = document.createElement("canvas");
    const dpr = window.devicePixelRatio || 1;

    exportCanvas.width = originalCanvas.width;
    exportCanvas.height =
      originalCanvas.height + (headerHeight + footerHeight) * dpr;

    const ctx = exportCanvas.getContext("2d");

    // Fill background
    ctx.fillStyle = "#1a1a1a";
    ctx.fillRect(0, 0, exportCanvas.width, exportCanvas.height);

    // Load and draw logo
    const logo = new Image();
    logo.src = "icons/favicon-128x128.png";
    logo.onload = () => {
      // Draw logo (centered at top)
      const logoSize = 32 * dpr;
      const centerX = exportCanvas.width / 2;
      ctx.drawImage(logo, centerX - logoSize / 2, 20 * dpr, logoSize, logoSize);

      // Draw "Your Cycle Keeper" text below logo
      ctx.fillStyle = "#A78BFA";
      ctx.font = `${16 * dpr}px sans-serif`;
      ctx.textAlign = "center";
      ctx.fillText("Your Cycle Keeper", centerX, 70 * dpr);

      // Draw period label (subtle, top right)
      ctx.font = `${13 * dpr}px sans-serif`;
      ctx.fillStyle = "#666";
      ctx.textAlign = "right";
      ctx.fillText(periodLabel, exportCanvas.width - 20 * dpr, 30 * dpr);

      // Draw original chart
      ctx.drawImage(originalCanvas, 0, headerHeight * dpr);

      // Draw footer
      ctx.fillStyle = "#333";
      ctx.fillRect(
        0,
        headerHeight * dpr + originalCanvas.height,
        exportCanvas.width,
        footerHeight * dpr
      );
      ctx.fillStyle = "#666";
      ctx.font = `${11 * dpr}px sans-serif`;
      ctx.textAlign = "center";
      ctx.fillText(
        "yourcyclekeeper.web.app",
        centerX,
        headerHeight * dpr + originalCanvas.height + 25 * dpr
      );

      // Convert to blob and download
      exportCanvas.toBlob((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const monthName =
          selectedMonth === ""
            ? "full-year"
            : new Date(selectedYear, parseInt(selectedMonth)).toLocaleString(
                "default",
                { month: "short" }
              );
        a.download = `cycle-tracking_${monthName}-${selectedYear}.png`;
        a.click();
        URL.revokeObjectURL(url);
      }, "image/png");
    };

    // Fallback if logo fails to load
    logo.onerror = () => {
      const centerX = exportCanvas.width / 2;

      // Draw "Your Cycle Keeper" text
      ctx.fillStyle = "#A78BFA";
      ctx.font = `${16 * dpr}px sans-serif`;
      ctx.textAlign = "center";
      ctx.fillText("Your Cycle Keeper", centerX, 40 * dpr);

      // Draw period label
      ctx.font = `${13 * dpr}px sans-serif`;
      ctx.fillStyle = "#666";
      ctx.textAlign = "right";
      ctx.fillText(periodLabel, exportCanvas.width - 20 * dpr, 30 * dpr);

      // Draw original chart
      ctx.drawImage(originalCanvas, 0, headerHeight * dpr);

      // Draw footer
      ctx.fillStyle = "#333";
      ctx.fillRect(
        0,
        headerHeight * dpr + originalCanvas.height,
        exportCanvas.width,
        footerHeight * dpr
      );
      ctx.fillStyle = "#666";
      ctx.font = `${11 * dpr}px sans-serif`;
      ctx.textAlign = "center";
      ctx.fillText(
        "Private & Encrypted • yourcyclekeeper.web.app",
        centerX,
        headerHeight * dpr + originalCanvas.height + 25 * dpr
      );

      // Convert to blob and download
      exportCanvas.toBlob((blob) => {
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        const monthName =
          selectedMonth === ""
            ? "full-year"
            : new Date(selectedYear, parseInt(selectedMonth)).toLocaleString(
                "default",
                { month: "short" }
              );
        a.download = `cycle-tracking_${monthName}-${selectedYear}.png`;
        a.click();
        URL.revokeObjectURL(url);
      }, "image/png");
    };
  } catch (error) {
    console.error("🚨 Chart download error:", error);
    showModal({
      icon: "⚠️",
      title: t("download_failed_title"),
      msg: t("download_failed_msg"),
      confirmText: t("ok"),
    });
  }
}

function renderCalendar() {
  const grid = document.getElementById("cal-grid");
  const year = viewMonth.getFullYear();
  const month = viewMonth.getMonth();
  const todayStr = today();

  // Safe month label using Intl — no user input
  document.getElementById("cal-month-label").textContent = new Date(
    year,
    month,
    1
  ).toLocaleString(getLanguage(), { month: "long", year: "numeric" });

  // Generate localized weekday headers
  const weekdaysEl = document.getElementById("cal-weekdays");
  if (weekdaysEl) {
    weekdaysEl.innerHTML = "";
    const formatter = new Intl.DateTimeFormat(getLanguage(), { weekday: "short" });
    for (let i = 0; i < 7; i++) {
      const d = new Date(2023, 0, i + 1); // Jan 1 2023 is Sunday
      const el = document.createElement("div");
      el.className = "cal-weekday";
      el.textContent = formatter.format(d);
      weekdaysEl.appendChild(el);
    }
  }

  grid.innerHTML = "";
  const firstDay = new Date(year, month, 1).getDay();
  const daysInMonth = new Date(year, month + 1, 0).getDate();

  for (let i = 0; i < firstDay; i++) {
    const el = document.createElement("div");
    el.className = "cal-day empty";
    grid.appendChild(el);
  }

  for (let d = 1; d <= daysInMonth; d++) {
    const dateStr = `${year}-${String(month + 1).padStart(2, "0")}-${String(
      d
    ).padStart(2, "0")}`;
    const cell = document.createElement("div");
    const dayType = getDayType(dateStr);
    let cls = "cal-day";
    if (dayType === "period") cls += " period";
    else if (dayType === "ovulation") cls += " ovulation";
    else if (dayType === "fertile") cls += " fertile";
    else if (isPredictedFuturePeriod(dateStr)) cls += " predicted-period";
    if (dateStr === todayStr) cls += " today";
    if (dateStr === selectedDate) cls += " selected-log";
    if (state.logs[dateStr]) cls += " has-log";
    cell.className = cls;
    cell.textContent = d; // safe: numeric only
    cell.dataset.date = dateStr; // used internally only
    cell.tabIndex = 0; // Make focusable
    cell.setAttribute("role", "button");
    cell.setAttribute(
      "aria-label",
      `${d}, ${
        dayType === "period"
          ? t("calendar_day_period")
          : dayType === "ovulation"
          ? t("calendar_day_ovulation")
          : dayType === "fertile"
          ? t("calendar_day_fertile")
          : t("calendar_day_regular")
      }`
    );
    cell.addEventListener("click", () => selectDay(dateStr));
    cell.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        selectDay(dateStr);
      }
    });
    grid.appendChild(cell);
  }
}

function changeMonth(dir) {
  // Don't allow calendar navigation if a modal is open
  const logPanel = document.getElementById("log-panel");
  if (logPanel && logPanel.classList.contains("visible")) {
    return;
  }

  viewMonth = new Date(viewMonth.getFullYear(), viewMonth.getMonth() + dir, 1);
  renderCalendar();
}

function closeLogPanel() {
  const logModal = document.getElementById("log-modal-overlay");
  if (logModal) {
    logModal.classList.remove("visible");
  }

  // Re-enable calendar nav buttons
  const prevBtn = document.getElementById("cal-prev");
  const nextBtn = document.getElementById("cal-next");
  if (prevBtn) prevBtn.classList.remove("nav-disabled");
  if (nextBtn) nextBtn.classList.remove("nav-disabled");

  // Return focus to the calendar date that was selected (accessibility standard)
  const previousDate = selectedDate;
  selectedDate = null;
  renderCalendar();

  if (previousDate) {
    // Use setTimeout to ensure calendar has rendered
    setTimeout(() => {
      const dateCell = document.querySelector(
        `.cal-day[data-date="${previousDate}"]`
      );
      if (dateCell) {
        dateCell.focus();
      }
    }, 0);
  }
}

function selectDay(dateStr) {
  // Validate dateStr format before using
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
  selectedDate = dateStr;
  renderCalendar();
  const modal = document.getElementById("log-modal-overlay");
  modal.classList.add("visible");

  // Disable calendar nav buttons while log panel is open
  const prevBtn = document.getElementById("cal-prev");
  const nextBtn = document.getElementById("cal-next");
  if (prevBtn) prevBtn.classList.add("nav-disabled");
  if (nextBtn) nextBtn.classList.add("nav-disabled");
  const d = fromISO(dateStr);
  document.getElementById("log-panel-date").textContent = d.toLocaleDateString(
    "default",
    {
      weekday: "long",
      month: "long",
      day: "numeric",
    }
  );

  const log = state.logs[dateStr] || {};
  const flowValue = getFlowValueFromLog(log);
  updateFlowButtonVisual(
    flowValue === null ? 1 : flowValue,
    flowValue !== null
  );

  const painValue = getPainValueFromLog(log);
  updatePainButtonVisual(
    painValue === null ? 5 : painValue,
    painValue !== null
  );

  const moodValue = getMoodValueFromLog(log);
  updateMoodButtonVisual(
    moodValue === null ? 50 : moodValue,
    moodValue !== null
  );

  // Safe value — textContent for note
  const noteEl = document.getElementById("log-note");
  noteEl.value = (log.note || "").slice(0, 500);
  updateNoteCount();

  // Move focus into modal immediately (accessibility standard for modal dialogs)
  setTimeout(() => {
    const firstButton = document.getElementById("log-flow");
    if (firstButton) {
      firstButton.focus();
    }
  }, 0);
}

async function saveLog() {
  if (!selectedDate || !/^\d{4}-\d{2}-\d{2}$/.test(selectedDate)) return;
  const log = {};
  if (currentFlowSet) {
    log.flow = normalizeFlowValue(currentFlowValue, 1);
  }

  if (currentPainSet) {
    log.pain = normalizePainValue(currentPainValue, 5);
  }

  if (currentMoodSet) {
    log.mood = normalizeMoodValue(currentMoodValue, 50);
  }

  const rawNote = document.getElementById("log-note").value;
  log.note = rawNote.slice(0, 500).replace(/[<>]/g, ""); // strip < > as extra guard

  state.logs[selectedDate] = log;
  if (log.flow) updateCycleHistory(selectedDate);
  cleanupEmptyLogs();
  await save();

  renderCalendar();
  updateStatusCard();
  updateInsights();
  if (navigator.vibrate) navigator.vibrate(40);
}

function updateCycleHistory(dateStr) {
  if (!state.cycleHistory) state.cycleHistory = [];
  const hist = state.cycleHistory;
  if (hist.length > 0) {
    const last = hist[hist.length - 1];
    if (last.start === dateStr) return;
    const len = diffDays(fromISO(last.start), fromISO(dateStr));
    if (len > 14 && len < 60) {
      hist[hist.length - 1].length = len;
      hist.push({ start: dateStr, length: state.cycleLength });
      const lens = hist.filter((c) => c.length > 14).map((c) => c.length);
      if (lens.length >= 2) {
        state.cycleLength = Math.round(
          lens.reduce((a, b) => a + b, 0) / lens.length
        );
        state.lastPeriodStart = dateStr;
      }
    }
  } else {
    hist.push({ start: dateStr, length: state.cycleLength });
    state.lastPeriodStart = dateStr;
  }
}

async function applySettings() {
  const lp = document.getElementById("s-last-period").value;
  const cl = parseInt(document.getElementById("s-cycle-len").value);
  const pd = parseInt(document.getElementById("s-period-dur").value);
  if (!lp || !/^\d{4}-\d{2}-\d{2}$/.test(lp)) {
    showModal({
      icon: "📅",
      title: t("invalid_date_title"),
      msg: t("invalid_date_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
    return;
  }
  if (cl < 20 || cl > 45) {
    showModal({
      icon: "⚠️",
      title: t("invalid_cycle_title"),
      msg: t("invalid_cycle_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
    return;
  }
  if (pd < 1 || pd > 10) {
    showModal({
      icon: "⚠️",
      title: t("invalid_duration_title"),
      msg: t("invalid_duration_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
    return;
  }

  // Show confirmation modal before applying changes
  showModal({
    icon: "⚠️",
    title: t("update_predictions_title"),
    msg: t("update_predictions_msg"),
    confirmText: t("update_predictions_confirm"),
    cancelText: t("cancel"),
    onConfirm: async () => {
      state.lastPeriodStart = lp;
      state.cycleLength = cl;
      state.periodDuration = pd;
      await save();
      updateStatusCard();
      renderCalendar();
      updateInsights();
      switchTab("calendar");
      showToast(t("settings_saved_toast"));
    },
  });
}

async function updateBackupStatus() {
  const el = document.getElementById("backup-status");
  if (!el) return;
  const lastBackup = await getFromDB(BACKUP_KEY);
  if (!lastBackup) {
    el.textContent = t("backup_never");
    el.className = "backup-status backup-status--warn";
    return;
  }
  const days = Math.floor((new Date() - fromISO(lastBackup)) / 86400000);
  if (days === 0) {
    el.textContent = t("backup_today");
    el.className = "backup-status backup-status--ok";
  } else if (days === 1) {
    el.textContent = t("backup_yesterday");
    el.className = "backup-status backup-status--ok";
  } else if (days <= 30) {
    el.textContent = tp("backup_days_ago", days);
    el.className = "backup-status backup-status--ok";
  } else {
    el.textContent = tp("backup_overdue", days);
    el.className = "backup-status backup-status--warn";
  }
}

function loadSettingsFields() {
  document.getElementById("s-last-period").value = state.lastPeriodStart || "";
  document.getElementById("s-cycle-len").value = state.cycleLength;
  document.getElementById("s-period-dur").value = state.periodDuration;

  // Calculate and display storage usage
  calculateStorageUsage();
  updateBackupStatus();
}

async function exportData() {
  if (!sessionPin) return;
  showModal({
    icon: "📦",
    title: t("export_backup_title"),
    msg: t("export_backup_msg"),
    confirmText: t("export"),
    cancelText: t("cancel"),
    onConfirm: async () => {
      try {
        const salt = await getOrCreateSalt();
        const enc = await encryptData(state, sessionPin, salt);
        const saltB64 = btoa(String.fromCharCode(...salt));
        const bundle = JSON.stringify({ enc, salt: saltB64, v: 1 });
        const blob = new Blob([bundle], {
          type: "application/octet-stream",
        });
        const a = document.createElement("a");
        a.href = URL.createObjectURL(blob);
        a.download = `yourcyclekeeper_backup_${today()}.bin`;
        a.click();
        URL.revokeObjectURL(a.href);
        await setInDB(BACKUP_KEY, today());
        backupReminderShownThisSession = true;
        updateBackupStatus();
      } catch (error) {
        console.error("🚨 Export error:", error);
        showModal({
          icon: "⚠️",
          title: t("export_failed_title"),
          msg: t("export_failed_msg"),
          confirmText: t("ok"),
        });
      }
    },
  });
}

let _importPinBuffer = "";

function _showImportPinModal(bundle, backupSalt) {
  _importPinBuffer = "";
  const overlay = document.getElementById("modal-overlay");
  const box = overlay.querySelector(".modal-box");

  const iconEl = document.createElement("div");
  iconEl.className = "modal-icon";
  iconEl.textContent = "🔑";

  const titleEl = document.createElement("div");
  titleEl.className = "modal-title";
  titleEl.textContent = t("enter_backup_pin_title");

  const msgEl = document.createElement("div");
  msgEl.className = "modal-msg";
  msgEl.id = "ipin-msg";
  msgEl.textContent = t("enter_backup_pin_msg");

  const dotsWrap = document.createElement("div");
  dotsWrap.style.cssText =
    "display:flex;gap:0.75rem;justify-content:center;margin:1rem 0";
  for (let i = 0; i < 4; i++) {
    const dot = document.createElement("div");
    dot.className = "pin-dot";
    dot.id = "ipd" + i;
    dotsWrap.appendChild(dot);
  }

  const padWrap = document.createElement("div");
  padWrap.style.cssText =
    "display:grid;grid-template-columns:repeat(3,4.25rem);gap:0.625rem;justify-content:center;margin-bottom:0.875rem";
  ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "⌫"].forEach((k) => {
    if (k === "") {
      padWrap.appendChild(document.createElement("div"));
      return;
    }
    const btn = document.createElement("div");
    btn.className = "num-btn";
    btn.style.cssText = "width:4.25rem;height:4.25rem";
    btn.textContent = k;
    btn.addEventListener("click", () =>
      _importPinInput(k, bundle, backupSalt)
    );
    padWrap.appendChild(btn);
  });

  const btnsDiv = document.createElement("div");
  btnsDiv.className = "modal-btns";
  const cancelBtn = document.createElement("button");
  cancelBtn.className = "modal-btn secondary";
  cancelBtn.textContent = t("cancel");
  cancelBtn.addEventListener("click", () =>
    overlay.classList.remove("visible")
  );
  btnsDiv.appendChild(cancelBtn);

  box.replaceChildren(iconEl, titleEl, msgEl, dotsWrap, padWrap, btnsDiv);
  overlay.classList.add("visible");
}

function _importPinInput(key, bundle, backupSalt) {
  if (key === "⌫") {
    _importPinBuffer = _importPinBuffer.slice(0, -1);
    for (let i = 0; i < 4; i++) {
      const el = document.getElementById("ipd" + i);
      if (el) el.classList.toggle("filled", i < _importPinBuffer.length);
    }
    return;
  }
  if (_importPinBuffer.length >= 4) return;
  _importPinBuffer += key;
  for (let i = 0; i < 4; i++) {
    const el = document.getElementById("ipd" + i);
    if (el) el.classList.toggle("filled", i < _importPinBuffer.length);
  }
  if (_importPinBuffer.length === 4) {
    setTimeout(() => _submitImportPin(bundle, backupSalt), 150);
  }
}

async function _submitImportPin(bundle, backupSalt) {
  const enteredPin = _importPinBuffer;
  try {
    const restored = await decryptData(bundle.enc, enteredPin, backupSalt);
    if (!restored) {
      const msgEl = document.getElementById("ipin-msg");
      if (msgEl) {
        msgEl.textContent = t("incorrect_pin_simple");
        msgEl.style.color = "var(--danger, #f87171)";
      }
      _importPinBuffer = "";
      for (let i = 0; i < 4; i++) {
        const el = document.getElementById("ipd" + i);
        if (el) el.classList.remove("filled");
      }
      return;
    }
    // Decryption succeeded — restore data, keep current session PIN and salt
    state = restored;
    setCyclesState(state);
    setPeriodMarkingState(state);
    await save(); // re-encrypts with current sessionPin + current salt
    document.getElementById("modal-overlay").classList.remove("visible");
    renderCalendar();
    updateStatusCard();
    updateInsights();
    showModal({
      icon: "✅",
      title: t("restored_title"),
      msg: t("restored_msg"),
      cancelText: "",
      confirmText: t("ok"),
    });
  } catch {
    const msgEl = document.getElementById("ipin-msg");
    if (msgEl) {
      msgEl.textContent = t("incorrect_pin_simple");
      msgEl.style.color = "var(--danger, #f87171)";
    }
    _importPinBuffer = "";
    for (let i = 0; i < 4; i++) {
      const el = document.getElementById("ipd" + i);
      if (el) el.classList.remove("filled");
    }
  }
}

async function importData() {
  const input = document.createElement("input");
  input.type = "file";
  input.accept = ".bin";
  input.addEventListener("change", async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const bundle = JSON.parse(text);
      const backupSalt = Uint8Array.from(atob(bundle.salt), (c) =>
        c.charCodeAt(0)
      );

      // Validate backup version
      if (bundle.v !== 1) {
        showModal({
          icon: "❌",
          title: t("invalid_backup_title"),
          msg: t("invalid_backup_msg"),
          cancelText: "",
          confirmText: t("ok"),
        });
        return;
      }

      _showImportPinModal(bundle, backupSalt);
    } catch (err) {
      showModal({
        icon: "❌",
        title: t("import_failed_title"),
        msg: t("import_failed_msg"),
        cancelText: "",
        confirmText: t("ok"),
      });
    }
  });
  input.click();
}

async function calculateStorageUsage() {
  try {
    const bytes = await calculateDBStorageUsage();
    const sizeKB = (bytes / 1024).toFixed(2);
    const usageSpan = document.getElementById("storage-usage");
    if (usageSpan) {
      usageSpan.textContent = t("storage_used", { sizeKB });
    }
  } catch (error) {
    console.warn("⚠️ Could not calculate storage:", error);
    const usageSpan = document.getElementById("storage-usage");
    if (usageSpan) {
      usageSpan.textContent = t("storage_unknown");
    }
  }
}

function confirmClear() {
  showModal({
    icon: "🗑️",
    title: t("erase_title"),
    msg: t("erase_msg"),
    confirmText: t("erase_confirm"),
    cancelText: t("cancel"),
    onConfirm: async () => {
      try {
        await clearDB();
        location.reload();
      } catch (error) {
        console.error("🚨 Clear error:", error);
        showModal({
          icon: "⚠️",
          title: t("erase_failed_title"),
          msg: t("erase_failed_msg"),
          confirmText: t("ok"),
        });
      }
    },
  });
}

let changePinStage = "new"; // 'new' | 'confirm'
let changePinFirst = "";
let changePinBuffer = "";

function showChangePinModal() {
  changePinStage = "new";
  changePinFirst = "";
  changePinBuffer = "";
  _renderChangePinModal();
}

function _renderChangePinModal() {
  const isConfirm = changePinStage === "confirm";
  const overlay = document.getElementById("modal-overlay");
  const box = overlay.querySelector(".modal-box");

  // Safe DOM construction — no user data in innerHTML, only static UI
  const iconEl = document.createElement("div");
  iconEl.className = "modal-icon";
  iconEl.textContent = "🔑";
  const titleEl = document.createElement("div");
  titleEl.className = "modal-title";
  titleEl.textContent = isConfirm ? t("confirm_new_pin") : t("enter_new_pin");
  const msgEl = document.createElement("div");
  msgEl.className = "modal-msg";
  msgEl.id = "cpin-msg";
  msgEl.textContent = isConfirm
    ? t("reenter_pin_msg")
    : t("choose_pin_msg");

  const dotsWrap = document.createElement("div");
  dotsWrap.id = "cpin-dots";
  dotsWrap.style.cssText =
    "display:flex;gap:0.75rem;justify-content:center;margin:1rem 0";
  for (let i = 0; i < 4; i++) {
    const dot = document.createElement("div");
    dot.className = "pin-dot";
    dot.id = "cpd" + i;
    dotsWrap.appendChild(dot);
  }

  const padWrap = document.createElement("div");
  padWrap.style.cssText =
    "display:grid;grid-template-columns:repeat(3,4.25rem);gap:0.625rem;justify-content:center;margin-bottom:0.875rem";
  ["1", "2", "3", "4", "5", "6", "7", "8", "9", "", "0", "⌫"].forEach((k) => {
    if (k === "") {
      padWrap.appendChild(document.createElement("div"));
      return;
    }
    const btn = document.createElement("div");
    btn.className = "num-btn";
    btn.style.cssText = "width:4.25rem;height:4.25rem";
    btn.textContent = k;
    btn.addEventListener("click", () => changePinInput(k));
    padWrap.appendChild(btn);
  });

  const btnsDiv = document.createElement("div");
  btnsDiv.className = "modal-btns";
  const cancelBtn = document.createElement("button");
  cancelBtn.className = "modal-btn secondary";
  cancelBtn.textContent = t("cancel");
  cancelBtn.addEventListener("click", () =>
    document.getElementById("modal-overlay").classList.remove("visible")
  );
  btnsDiv.appendChild(cancelBtn);

  box.replaceChildren(iconEl, titleEl, msgEl, dotsWrap, padWrap, btnsDiv);
  overlay.classList.add("visible");
}

function changePinInput(key) {
  if (key === "⌫") {
    changePinBuffer = changePinBuffer.slice(0, -1);
    for (let i = 0; i < 4; i++) {
      const el = document.getElementById("cpd" + i);
      if (el) el.classList.toggle("filled", i < changePinBuffer.length);
    }
    return;
  }
  if (changePinBuffer.length >= 4) return;
  changePinBuffer += key;
  for (let i = 0; i < 4; i++) {
    const el = document.getElementById("cpd" + i);
    if (el) el.classList.toggle("filled", i < changePinBuffer.length);
  }
  if (changePinBuffer.length === 4) {
    setTimeout(() => _submitChangePinStep(), 150);
  }
}

async function _submitChangePinStep() {
  if (changePinStage === "new") {
    changePinFirst = changePinBuffer;
    changePinBuffer = "";
    changePinStage = "confirm";
    _renderChangePinModal();
  } else {
    if (changePinBuffer !== changePinFirst) {
      const msgEl = document.getElementById("cpin-msg");
      if (msgEl) {
        msgEl.textContent = t("pins_no_match");
        msgEl.style.color = "var(--danger)";
      }
      changePinBuffer = "";
      changePinFirst = "";
      changePinStage = "new";
      setTimeout(() => _renderChangePinModal(), 900);
      return;
    }
    // PINs match — re-derive key, re-encrypt, update HMAC
    const newPin = changePinBuffer;
    try {
      const salt = await getOrCreateSalt();
      const newHash = await hashPin(newPin, salt);
      await setInDB(PINHASH_KEY, newHash);
      sessionPin = newPin;
      await save(); // re-encrypts all data with new PIN
      document.getElementById("modal-overlay").classList.remove("visible");
      showModal({
        icon: "✅",
        title: t("pin_changed_title"),
        msg: t("pin_changed_msg"),
        cancelText: "",
        confirmText: t("ok"),
      });
    } catch (error) {
      console.error("🚨 PIN change error:", error);
      showModal({
        icon: "⚠️",
        title: t("pin_change_failed_title"),
        msg: t("pin_change_failed_msg"),
        cancelText: "",
        confirmText: t("ok"),
      });
    }
  }
}

function switchTab(tab) {
  const allowed = ["calendar", "insights", "settings", "about", "support"];
  if (!allowed.includes(tab)) return;
  currentTab = tab;

  // Sync navigation state
  setNavigationState(tab === "support" ? "about" : tab, viewMonth);

  // Remove active from bottom nav items
  [
    "bnav-calendar",
    "bnav-insights",
    "bnav-settings",
    "bnav-about",
    "bnav-support",
  ].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.remove("active");
  });

  // Show/hide view panels
  const calView = document.getElementById("view-calendar");
  const insView = document.getElementById("view-insights");
  const setView = document.getElementById("view-settings");
  const aboutView = document.getElementById("view-about");
  const isAboutMode = tab === "about" || tab === "support";
  if (calView) calView.style.display = tab === "calendar" ? "block" : "none";
  if (insView) insView.style.display = tab === "insights" ? "block" : "none";
  if (setView) setView.style.display = tab === "settings" ? "block" : "none";
  if (aboutView) aboutView.style.display = isAboutMode ? "block" : "none";
  if (insView)
    insView.className =
      "insights-wrap" + (tab === "insights" ? " visible" : "");
  if (setView)
    setView.className =
      "settings-wrap" + (tab === "settings" ? " visible" : "");
  if (aboutView) {
    aboutView.className = "settings-wrap" + (isAboutMode ? " visible" : "");
    aboutView.classList.toggle("support-mode", tab === "support");
    // Add official version notice if not already present
    if (isAboutMode && !document.getElementById("official-version-notice")) {
      const notice = document.createElement("div");
      notice.id = "official-version-notice";
      notice.style.cssText = "margin:1.5rem 0 0 0;padding:0.75rem 1.25rem;background:#221a33;color:#A78BFA;border-radius:8px;font-size:1rem;text-align:center;opacity:0.92;";
      notice.textContent = "Official version: yourcyclekeeper.web.app";
      aboutView.appendChild(notice);
    }
  }

  // Add active to current tab button
  if (tab === "calendar") {
    const bnav = document.getElementById("bnav-calendar");
    if (bnav) bnav.classList.add("active");
  }
  if (tab === "insights") {
    const bnav = document.getElementById("bnav-insights");
    if (bnav) bnav.classList.add("active");
    updateInsights();
  }
  if (tab === "settings") {
    const bnav = document.getElementById("bnav-settings");
    if (bnav) bnav.classList.add("active");
    loadSettingsFields();
  }
  if (tab === "about") {
    const bnav = document.getElementById("bnav-about");
    if (bnav) bnav.classList.add("active");
  }
  if (tab === "support") {
    const bnav = document.getElementById("bnav-support");
    if (bnav) bnav.classList.add("active");
  }
  // Hide log panel when switching tabs
  const logModal = document.getElementById("log-modal-overlay");
  if (logModal) logModal.classList.remove("visible");
}

async function init() {
  try {
    // Initialize IndexedDB
    await initIndexedDB();

    // Setup event listeners now that DOM exists
    setupEventListeners();

    // Initialize keyboard navigation
    initKeyboardNavigation({
      pinInput,
      pinDelete,
      setupPinInput,
      setupPinDelete,
      changePinInput,
      closeLogPanel,
      renderCalendar,
    });

    const hasData = !!(await getFromDB(STORE_KEY));
    const hasSalt = !!(await getFromDB(SALT_KEY));
    const hasPinHash = !!(await getFromDB(PINHASH_KEY));

    // Register Service Worker (only on http/https, not file://)
    if (
      "serviceWorker" in navigator &&
      (location.protocol === "http:" || location.protocol === "https:")
    ) {
      const swUrl = `/period-tracker/service-worker.js`;
      navigator.serviceWorker
        .register(swUrl)
        .then((reg) => {
          console.log("Service Worker registered:", reg);
        })
        .catch((err) => {
          console.warn("Service Worker registration failed:", err);
        });

      // When a new SW takes over (skipWaiting + clients.claim), reload so
      // the page runs the latest JS instead of the old in-memory version.
      navigator.serviceWorker.addEventListener("controllerchange", () => {
        window.location.reload();
      });
    } else if (!("serviceWorker" in navigator)) {
      console.log("Service Worker not supported in this browser");
    } else {
      console.log(
        "Service Worker skipped (running on file:// protocol - use http:// or https:// for production)"
      );
    }

    // Set sensible default date in onboarding
    document.getElementById("ob-last-period").value = toISO(
      addDays(new Date(), -14)
    );

    if (hasData && hasSalt && hasPinHash) {
      // Returning user: show lock screen
      document.getElementById("lock-screen").classList.remove("hidden");
      document.getElementById("lock-sub").textContent =
        t("unlock_subtitle");
    } else {
      // First time: show onboarding
      document.getElementById("lock-screen").classList.add("hidden");
      document.getElementById("onboarding").classList.remove("hidden");
    }
  } catch (error) {
    console.error("🚨 Initialization error:", error);
    showModal({
      icon: "⚠️",
      title: t("db_error_title"),
      msg: t("db_error_msg"),
      confirmText: t("refresh"),
      onConfirm: () => location.reload(),
    });
    return;
  }

  updateFlowButtonVisual(1, false);
  updatePainButtonVisual(5, false);
  updateMoodButtonVisual(50, false);
  initializePainChartControls();
  applyI18n();
  _initLangSwitcher();
  _updateMonthDropdown();
}

function _initLangSwitcher() {
  const sel = document.getElementById("lang-switcher");
  if (!sel) return;
  sel.value = getLanguage();
  sel.addEventListener("change", () => {
    setLanguage(sel.value);
    applyI18n();
    _updateMonthDropdown();
    // Re-render dynamic content with new language
    updateStatusCard();
    renderCalendar();
    updateInsights();
    updateNoteCount();
    if (document.getElementById("lock-sub")) {
      document.getElementById("lock-sub").textContent = t("unlock_subtitle");
    }
  });
}

function _updateMonthDropdown() {
  const sel = document.getElementById("pain-view-month");
  if (!sel) return;
  const lang = getLanguage();
  const currentValue = sel.value;
  // Update all month options (index 1–12, value 0–11)
  for (let i = 0; i < 12; i++) {
    const option = sel.options[i + 1]; // skip "All Months" at index 0
    if (!option) continue;
    option.textContent = new Date(2000, i, 1).toLocaleString(lang, { month: "long" });
  }
  sel.value = currentValue;
}

// Wait for DOM to be ready before initializing
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", () => {
    init().catch((err) => {
      console.error("🚨 Fatal initialization error:", err);
    });
  });
} else {
  // DOM is already loaded
  init().catch((err) => {
    console.error("🚨 Fatal initialization error:", err);
  });
}

function switchInsightTab(tabId) {
  const tabs = ['chart', 'how', 'history'];
  
  tabs.forEach(tab => {
    const btn = document.getElementById('tab-btn-' + tab);
    const content = document.getElementById('insight-tab-' + tab);
    if (!btn || !content) return;
    
    if (tab === tabId) {
      btn.classList.add('active');
      content.style.display = 'block';
    } else {
      btn.classList.remove('active');
      content.style.display = 'none';
    }
  });
}

function switchSettingsTab(tabId) {
  const tabs = ['cycle', 'security'];
  tabs.forEach(tab => {
    const btn = document.getElementById('tab-btn-settings-' + tab);
    const content = document.getElementById('settings-tab-' + tab);
    if (!btn || !content) return;
    
    if (tab === tabId) {
      btn.classList.add('active');
      content.classList.add('active');
    } else {
      btn.classList.remove('active');
      content.classList.remove('active');
    }
  });
}

function switchAboutTab(tabId) {
  const tabs = ['developer', 'privacy', 'disclaimer'];
  tabs.forEach(tab => {
    const btn = document.getElementById(`tab-btn-about-${tab}`);
    const content = document.getElementById(`about-tab-${tab}`);
    if (!btn || !content) return;
    if (tab === tabId) {
      btn.classList.add('active');
      content.classList.add('active');
    } else {
      btn.classList.remove('active');
      content.classList.remove('active');
    }
  });
}

// Expose functions to window for HTML onclick handlers
window.switchInsightTab = switchInsightTab;
window.switchSettingsTab = switchSettingsTab;
window.switchAboutTab = switchAboutTab;
window.pinInput = pinInput;
window.pinDelete = pinDelete;
window.forgotPinFlow = forgotPinFlow;
window.setupPinInput = setupPinInput;
window.setupPinDelete = setupPinDelete;
window.startApp = startApp;
window.changeMonth = changeMonth;
window.closeLogPanel = closeLogPanel;
window.showFlowModal = showFlowModal;
window.showPainModal = showPainModal;
window.showMoodModal = showMoodModal;
window.saveLog = saveLog;
window.deleteLog = deleteLog;
window.resetLogWithConfirm = resetLogWithConfirm;
window.scheduleAutoSaveNote = scheduleAutoSaveNote;
window.downloadChart = downloadChart;
window.setChartFilter = setChartFilter;
window.updatePainChart = updatePainChart;
window.updateNoteCount = updateNoteCount;
window.applySettings = applySettings;
window.showChangePinModal = showChangePinModal;
window.exportData = exportData;
window.importData = importData;
window.confirmClear = confirmClear;
window.switchTab = switchTab;
window.changeLanguage = (lang) => {
  setLanguage(lang);
  applyI18n();
  updateStatusCard();
  renderCalendar();
  updateInsights();
  const lockSub = document.getElementById("lock-sub");
  if (lockSub) lockSub.textContent = t("unlock_subtitle");
};
