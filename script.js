"use strict";

const STORE_KEY = "luna_enc_v1"; // encrypted blob
const SALT_KEY = "luna_salt_v1"; // random salt (not secret)
const PINHASH_KEY = "luna_ph_v1"; // HMAC of PIN for fast wrong-PIN detection
const SCHEMA_VERSION = 1; // bump when state shape changes

async function deriveKey(pin, salt) {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 250000, hash: "SHA-256" }, // ← 250k
    keyMat,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptData(data, pin, salt) {
  const key = await deriveKey(pin, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  // Schema envelope: version + payload. Allows future migrations.
  const envelope = JSON.stringify({ v: SCHEMA_VERSION, payload: data });
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    enc.encode(envelope)
  );
  const combined = new Uint8Array(iv.byteLength + ct.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ct), iv.byteLength);
  return btoa(String.fromCharCode(...combined));
}

async function decryptData(b64, pin, salt) {
  const key = await deriveKey(pin, salt);
  const combined = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = combined.slice(0, 12);
  const ct = combined.slice(12);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  const parsed = JSON.parse(new TextDecoder().decode(pt));
  // Schema version gate — future-proof for data shape changes
  if (parsed.v === undefined) {
    // Legacy blob (pre-schema): treat entire object as payload
    return parsed;
  }
  if (parsed.v !== SCHEMA_VERSION) {
    throw new Error(
      `Unsupported data schema version: ${parsed.v}. Please update the app.`
    );
  }
  return parsed.payload;
}

async function hashPin(pin, salt) {
  const enc = new TextEncoder();
  const keyMat = await crypto.subtle.importKey(
    "raw",
    enc.encode(pin),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", keyMat, salt);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

function getOrCreateSalt() {
  let s = localStorage.getItem(SALT_KEY);
  if (s) return Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  localStorage.setItem(SALT_KEY, btoa(String.fromCharCode(...salt)));
  return salt;
}

let state = {
  lastPeriodStart: null,
  cycleLength: 28,
  periodDuration: 5,
  logs: {},
  cycleHistory: [],
};

let sessionPin = null; // PIN held only in JS memory (never persisted)
let viewMonth = new Date();
let selectedDate = null;
let currentTab = "calendar";

const SESSION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const WARN_AT_MS = SESSION_TIMEOUT_MS - 60000; // warn at 4 min
let sessionTimer = null;
let warnTimer = null;
let lastActivity = Date.now();

function resetSessionTimer() {
  lastActivity = Date.now();
  clearTimeout(sessionTimer);
  clearTimeout(warnTimer);
  hideBanner();
  warnTimer = setTimeout(() => {
    document.getElementById("timeout-banner").classList.add("visible");
    startCountdown(60);
  }, WARN_AT_MS);
  sessionTimer = setTimeout(() => {
    lockApp();
  }, SESSION_TIMEOUT_MS);
}

let countdownInterval = null;
function startCountdown(seconds) {
  clearInterval(countdownInterval);
  let s = seconds;
  document.getElementById("timeout-count").textContent = s;
  countdownInterval = setInterval(() => {
    s--;
    document.getElementById("timeout-count").textContent = s;
    if (s <= 0) clearInterval(countdownInterval);
  }, 1000);
}

function hideBanner() {
  document.getElementById("timeout-banner").classList.remove("visible");
  clearInterval(countdownInterval);
}

// Reset on any user interaction
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
document.getElementById("timeout-banner").addEventListener("click", () => {
  hideBanner();
  resetSessionTimer();
});

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

function pinInput(digit) {
  if (pinBuffer.length >= 4) return;
  pinBuffer += digit;
  updatePinDots(pinBuffer);
  if (pinBuffer.length === 4) submitPin();
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
    ).textContent = `Too many attempts. Try again in ${secsLeft}s.`;
    return;
  }

  const salt = getOrCreateSalt();
  const storedHash = localStorage.getItem(PINHASH_KEY);
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
        "🚫 Too many attempts. Locked for 60 seconds.";
      setTimeout(() => {
        // After lockout period: reset and allow retry without erasing
        pinAttempts = 0;
        pinLockUntil = 0;
        document.getElementById("lock-error").textContent =
          "Lockout ended. Try again.";
      }, LOCKOUT_MS);
    } else {
      document.getElementById(
        "lock-error"
      ).textContent = `Incorrect PIN. ${remaining} attempt${
        remaining === 1 ? "" : "s"
      } remaining.`;
    }
    return;
  }

  // PIN correct — decrypt data
  const blob = localStorage.getItem(STORE_KEY);
  if (blob) {
    try {
      state = await decryptData(blob, pin, salt);
    } catch {
      document.getElementById("lock-error").textContent =
        "Decryption failed. Data may be corrupted.";
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
  clearTimeout(sessionTimer);
  clearTimeout(warnTimer);
  clearInterval(countdownInterval);
  hideBanner();
  document.getElementById("app").style.display = "none";
  document.getElementById("bottom-nav").style.display = "none";
  document.getElementById("lock-screen").classList.remove("hidden");
  document.getElementById("log-panel").classList.remove("visible");
  pinBuffer = "";
  updatePinDots("");
  document.getElementById("lock-error").textContent = "";
}

function forgotPinFlow() {
  showModal({
    icon: "⚠️",
    title: "Forgot PIN?",
    msg: "This will permanently erase all your cycle data and reset Luna. This cannot be undone. Are you sure?",
    confirmText: "Yes, erase and reset",
    cancelText: "Cancel",
    onConfirm: () => {
      localStorage.clear();
      sessionStorage.clear();
      state = {
        lastPeriodStart: null,
        cycleLength: 28,
        periodDuration: 5,
        logs: {},
        cycleHistory: [],
      };
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
        title: "Reset Complete",
        msg: "Luna has been reset. Please set a new PIN to get started.",
        cancelText: "",
        confirmText: "OK",
      });
    },
  });
}

async function save() {
  if (!sessionPin) return;
  const salt = getOrCreateSalt();
  const enc = await encryptData(state, sessionPin, salt);
  localStorage.setItem(STORE_KEY, enc);
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
      title: "Missing Date",
      msg: "Please enter the first day of your last period.",
      cancelText: "",
      confirmText: "OK",
    });
    return;
  }
  if (setupPin.length < 4) {
    showModal({
      icon: "🔢",
      title: "Set a PIN",
      msg: "Enter a 4-digit PIN to protect your data.",
      cancelText: "",
      confirmText: "OK",
    });
    return;
  }

  state.lastPeriodStart = lp;
  state.cycleLength = cl || 28;
  state.periodDuration = pd || 5;
  state.cycleHistory = [{ start: lp, length: cl || 28 }];
  sessionPin = setupPin;

  const salt = getOrCreateSalt();
  const pinHash = await hashPin(setupPin, salt);
  localStorage.setItem(PINHASH_KEY, pinHash);
  await save();

  document.getElementById("onboarding").classList.add("hidden");
  document.getElementById("lock-screen").classList.add("hidden");
  document.getElementById("app").style.display = "block";
  document.getElementById("bottom-nav").style.display = "flex";
  resetSessionTimer();
  viewMonth = new Date();
  updateStatusCard();
  renderCalendar();
  switchTab("calendar");
}

function toISO(date) {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(
    2,
    "0"
  )}-${String(date.getDate()).padStart(2, "0")}`;
}
function fromISO(s) {
  const [y, m, d] = s.split("-").map(Number);
  return new Date(y, m - 1, d);
}
function addDays(date, n) {
  const d = new Date(date);
  d.setDate(d.getDate() + n);
  return d;
}
function diffDays(a, b) {
  return Math.round((b - a) / 86400000);
}
function today() {
  return toISO(new Date());
}

function getCycleInfo() {
  if (!state.lastPeriodStart) return null;
  const startDate = fromISO(state.lastPeriodStart);
  const cl = state.cycleLength;
  const pd = state.periodDuration;
  const todayDate = new Date();
  todayDate.setHours(0, 0, 0, 0);

  let cycleStart = new Date(startDate);
  while (addDays(cycleStart, cl) <= todayDate)
    cycleStart = addDays(cycleStart, cl);

  const cycleDay = diffDays(cycleStart, todayDate) + 1;
  const nextPeriod = addDays(cycleStart, cl);
  const daysUntilNext = diffDays(todayDate, nextPeriod);

  // Standard Days Method: fertile days 8-19 (adjusted to cycle length)
  const fertileStart = Math.max(8, cl - 18);
  const fertileEnd = cl - 11;
  const ovulationDay = cl - 14;

  let phase = "Luteal";
  let phaseColor = "var(--lavender)";
  if (cycleDay >= 1 && cycleDay <= pd) {
    phase = "Menstruation";
    phaseColor = "var(--rose)";
  } else if (cycleDay < fertileStart) {
    phase = "Follicular";
    phaseColor = "var(--amber)";
  } else if (cycleDay === ovulationDay) {
    phase = "Ovulation Day";
    phaseColor = "var(--ovulation)";
  } else if (cycleDay >= fertileStart && cycleDay <= fertileEnd) {
    phase = "Fertile Window";
    phaseColor = "var(--fertile-green)";
  }

  return {
    cycleStart,
    cycleDay,
    nextPeriod,
    daysUntilNext,
    cl,
    pd,
    fertileStart,
    fertileEnd,
    ovulationDay,
    phase,
    phaseColor,
  };
}

/* Build 6 predicted cycle windows starting from lastPeriodStart */
function calculatePredictions() {
  if (!state.lastPeriodStart) return [];
  const cl = state.cycleLength;
  const pd = state.periodDuration;
  const ovOffset = cl - 14;
  const fertStartOff = Math.max(8, cl - 18);
  const fertEndOff = cl - 11;
  const base = fromISO(state.lastPeriodStart);
  const predictions = [];

  for (let i = 0; i < 6; i++) {
    const periodStart = addDays(base, cl * i);
    const periodEnd = addDays(periodStart, pd - 1);
    const ovulation = addDays(periodStart, ovOffset);
    const fertileStart = addDays(periodStart, fertStartOff);
    const fertileEnd = addDays(periodStart, fertEndOff);
    predictions.push({
      periodStart,
      periodEnd,
      ovulation,
      fertileStart,
      fertileEnd,
    });
  }
  return predictions;
}

/* Classify a date string across all 6 predicted windows */
function getDayType(dateStr) {
  if (!state.lastPeriodStart) return "normal";
  const d = fromISO(dateStr);
  const preds = calculatePredictions();

  for (const p of preds) {
    if (d >= p.periodStart && d <= p.periodEnd) return "period";
    if (toISO(d) === toISO(p.ovulation)) return "ovulation";
    if (d >= p.fertileStart && d <= p.fertileEnd) return "fertile";
  }
  return "normal";
}

function isPredictedFuturePeriod(dateStr) {
  const d = fromISO(dateStr);
  const todayD = fromISO(today());
  if (d <= todayD) return false;
  return getDayType(dateStr) === "period";
}

function sanitize(str) {
  if (typeof str !== "string") return "";
  const div = document.createElement("div");
  div.textContent = str.slice(0, 500); // hard cap
  return div.innerHTML;
}

// Safe DOM text setter — uses textContent, never innerHTML for user data
function safeText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}

function updateNoteCount() {
  const ta = document.getElementById("log-note");
  const el = document.getElementById("note-limit");
  if (ta && el) el.textContent = `${ta.value.length} / 500`;
}

let currentFlowValue = 1;
let currentFlowSet = false;
let currentMoodValue = 50;
let currentMoodSet = false;
let currentPainValue = 5;
let currentPainSet = false;

function normalizeFlowValue(value, fallback = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.min(3, Math.round(n)));
}

function getFlowValueFromLog(log) {
  if (!log) return null;
  if (typeof log.flow === "number" && Number.isFinite(log.flow)) {
    return normalizeFlowValue(log.flow, 1);
  }
  if (log.flow === true) return 1;
  return null;
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

function updateFlowModalPreview(value) {
  const slider = document.getElementById("flow-modal-slider");
  const label = document.getElementById("flow-modal-value");
  if (!slider || !label) return;
  const v = normalizeFlowValue(value, 1);
  slider.style.accentColor = "#FF3D6B";
  label.textContent = flowLabelFromValue(v);
  label.style.color = "var(--rose)";
  label.style.whiteSpace = "nowrap";
  label.style.letterSpacing = "-0.22em";
  label.style.lineHeight = "1";
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
  titleEl.textContent = "Set Flow";
  msgEl.textContent = "";

  const wrap = document.createElement("div");
  wrap.className = "flow-modal-wrap";
  const valueEl = document.createElement("div");
  valueEl.id = "flow-modal-value";
  valueEl.className = "flow-modal-value";
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
  wrap.appendChild(slider);
  msgEl.appendChild(wrap);

  confirmBtn.textContent = "Save";
  cancelBtn.textContent = "Cancel";
  cancelBtn.style.display = "";

  updateFlowModalPreview(currentFlowValue);

  confirmBtn.onclick = () => {
    const v = normalizeFlowValue(slider.value, 1);
    updateFlowButtonVisual(v, true);
    overlay.classList.remove("visible");
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
  };

  overlay.classList.add("visible");
}

function normalizePainValue(value, fallback = 5) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const clamped = Math.max(1, Math.min(10, n));
  return Math.round(clamped * 2) / 2;
}

function getPainValueFromLog(log) {
  if (!log) return null;
  if (typeof log.pain === "number" && Number.isFinite(log.pain)) {
    return normalizePainValue(log.pain, 5);
  }
  if (typeof log.headache === "number" && Number.isFinite(log.headache)) {
    return normalizePainValue(log.headache, 5);
  }
  if (log.headache === true) return 5;
  return null;
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
  return `Pain ${v.toFixed(1)} / 10`;
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
  titleEl.textContent = "Set Pain";
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

  confirmBtn.textContent = "Save";
  cancelBtn.textContent = "Cancel";
  cancelBtn.style.display = "";

  updatePainModalPreview(currentPainValue);

  confirmBtn.onclick = () => {
    const v = normalizePainValue(slider.value, 5);
    updatePainButtonVisual(v, true);
    overlay.classList.remove("visible");
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
  };

  overlay.classList.add("visible");
}

function normalizeMoodValue(value, fallback = 50) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(100, n));
}

function getMoodValueFromLog(log) {
  if (!log) return null;
  if (typeof log.mood === "number" && Number.isFinite(log.mood)) {
    return Math.max(0, Math.min(100, log.mood));
  }
  if (log["mood-happy"] && !log["mood-low"]) return 100;
  if (log["mood-low"] && !log["mood-happy"]) return 0;
  if (log["mood-happy"] && log["mood-low"]) return 50;
  return null;
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
  if (v < 35) return "Low Mood";
  if (v > 65) return "Happy";
  return "Neutral";
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
  if (moodIcon) moodIcon.textContent = "😐";
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
  titleEl.textContent = "Set Mood";
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
  slider.value = String(currentMoodValue);
  slider.id = "mood-modal-slider";
  slider.className = "mood-modal-slider";
  slider.addEventListener("input", (e) =>
    updateMoodModalPreview(e.target.value)
  );
  wrap.appendChild(valueEl);
  wrap.appendChild(slider);
  msgEl.appendChild(wrap);

  confirmBtn.textContent = "Save";
  cancelBtn.textContent = "Cancel";
  cancelBtn.style.display = "";

  updateMoodModalPreview(currentMoodValue);

  confirmBtn.onclick = () => {
    const v = normalizeMoodValue(slider.value, 50);
    updateMoodButtonVisual(v, true);
    overlay.classList.remove("visible");
  };
  cancelBtn.onclick = () => {
    overlay.classList.remove("visible");
  };

  overlay.classList.add("visible");
}

function updateStatusCard() {
  const info = getCycleInfo();
  if (!info) return;
  safeText("status-phase", "● " + info.phase.toUpperCase());
  safeText("status-title", getPhaseMessage(info));
  safeText("status-subtitle", getPhaseSubtitle(info));
  safeText("cycle-day", info.cycleDay);
  safeText(
    "days-until-next",
    info.daysUntilNext > 0 ? info.daysUntilNext : "Now"
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
    const dayText = info.daysUntilNext === 1 ? "day" : "days";
    text.textContent = `Your period is expected in ${info.daysUntilNext} ${dayText}`;
    banner.style.display = "block";
  } else {
    banner.style.display = "none";
  }
}

function getPhaseMessage(info) {
  if (info.phase === "Menstruation") return "Your period 🩸";
  if (info.phase === "Follicular") return "Building up ✨";
  if (info.phase === "Fertile Window") return "Fertile days 🌿";
  if (info.phase === "Ovulation Day") return "Ovulation day 🌟";
  return "Luteal phase 🌙";
}
function getPhaseSubtitle(info) {
  if (info.phase === "Menstruation")
    return `Day ${info.cycleDay} of your period`;
  if (info.phase === "Fertile Window")
    return `Days ${info.fertileStart}–${info.fertileEnd} are fertile`;
  if (info.phase === "Ovulation Day") return "Peak fertility today";
  return `Next period in ${info.daysUntilNext} days`;
}

function updateCycleBar(info) {
  const bar = document.getElementById("cycle-bar");
  safeText("bar-cycle-end", `Day ${info.cl}`);
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
  if (!state.cycleHistory || state.cycleHistory.length === 0) {
    hist.innerHTML = "";
    const p = document.createElement("p");
    p.style.cssText = "color:var(--text-muted);font-size:0.875rem";
    p.textContent = "Log at least 2 period start dates to see cycle history.";
    hist.appendChild(p);
    return;
  }
  hist.innerHTML = "";
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
      lenSpan.textContent = `${parseInt(c.length)} days`; // parseInt guards injections
      row.appendChild(dateSpan);
      row.appendChild(lenSpan);
      hist.appendChild(row);
    });

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
  canvas.style.width = width + "px";
  canvas.style.height = height + "px";
  ctx.scale(dpr, dpr);

  const padding = { top: 20, right: 20, bottom: 40, left: 40 };
  const chartWidth = width - padding.left - padding.right;
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

  if (data.length === 0) {
    ctx.fillStyle = "#666";
    ctx.font = "14px sans-serif";
    ctx.textAlign = "center";
    ctx.fillText("No tracking data logged yet", width / 2, height / 2);
    return;
  }

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
    if (point.isPeriod && !isYearView) {
      ctx.fillStyle = "rgba(255, 61, 107, 0.15)";
      ctx.fillRect(
        padding.left + i * barWidth,
        padding.top,
        barWidth,
        chartHeight
      );
    }

    // Draw ovulation marker (only in month view, not year view)
    if (point.isOvulation && !isYearView) {
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
    if (point.hasFlow)
      symptoms.push({
        color: "#FF3D6B",
        intensity: point.flowIntensity || 1,
      });
    if (point.hasPain)
      symptoms.push({
        color: "#FF6B4A",
        intensity: point.painIntensity || 1,
      });
    if (point.hasMood)
      symptoms.push({
        color: moodColorFromValue(point.moodValue),
        intensity: point.moodIntensity,
      });

    if (symptoms.length > 0) {
      const segmentWidth = (barWidth * 0.7) / symptoms.length;
      const startX = padding.left + i * barWidth + barWidth * 0.15;

      symptoms.forEach((symptom, idx) => {
        ctx.fillStyle = symptom.color;
        const barHeight = chartHeight * 0.8 * symptom.intensity;
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
  ctx.font = "11px sans-serif";
  ctx.textAlign = "center";

  const labelStep = isYearView ? 1 : 5;
  data.forEach((point, i) => {
    if (i % labelStep === 0 || i === data.length - 1) {
      const x = padding.left + i * barWidth + barWidth / 2;
      ctx.fillText(point.label, x, padding.top + chartHeight + 20);
    }
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
      moodIntensity:
        moodValue === null ? 0 : 0.4 + (Math.abs(moodValue - 50) / 50) * 0.6,
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
      label: monthStart.toLocaleString("default", { month: "short" }),
      hasFlow: flowCount > 0,
      hasPain: painCount > 0,
      hasMood: moodCount > 0,
      flowValue: avgFlow,
      painValue: avgPain,
      moodValue: avgMood,
      flowIntensity: avgFlow === null ? 0 : avgFlow / 3,
      painIntensity: avgPain === null ? 0 : avgPain / 10,
      moodIntensity:
        avgMood === null ? 0 : 0.4 + (Math.abs(avgMood - 50) / 50) * 0.6,
      isPeriod: periodDays > 0,
      isOvulation: false,
    });
  }

  return data;
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
  ).toLocaleString("default", { month: "long", year: "numeric" });

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
    cell.addEventListener("click", () => selectDay(dateStr));
    grid.appendChild(cell);
  }
}

function changeMonth(dir) {
  viewMonth = new Date(viewMonth.getFullYear(), viewMonth.getMonth() + dir, 1);
  renderCalendar();
}

function selectDay(dateStr) {
  // Validate dateStr format before using
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return;
  selectedDate = dateStr;
  renderCalendar();
  const panel = document.getElementById("log-panel");
  panel.classList.add("visible");
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
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
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
  await save();

  renderCalendar();
  document.getElementById("log-panel").classList.remove("visible");
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
      title: "Invalid Date",
      msg: "Please enter a valid last period date.",
      cancelText: "",
      confirmText: "OK",
    });
    return;
  }
  if (cl < 20 || cl > 45) {
    showModal({
      icon: "⚠️",
      title: "Invalid Cycle Length",
      msg: "Cycle length must be between 20 and 45 days.",
      cancelText: "",
      confirmText: "OK",
    });
    return;
  }
  if (pd < 1 || pd > 10) {
    showModal({
      icon: "⚠️",
      title: "Invalid Duration",
      msg: "Period duration must be between 1 and 10 days.",
      cancelText: "",
      confirmText: "OK",
    });
    return;
  }
  state.lastPeriodStart = lp;
  state.cycleLength = cl;
  state.periodDuration = pd;
  await save();
  updateStatusCard();
  renderCalendar();
  updateInsights();
  switchTab("calendar");
}

function loadSettingsFields() {
  document.getElementById("s-last-period").value = state.lastPeriodStart || "";
  document.getElementById("s-cycle-len").value = state.cycleLength;
  document.getElementById("s-period-dur").value = state.periodDuration;

  // Calculate and display storage usage
  calculateStorageUsage();
}

function installApp() {
  console.log("installApp() clicked. deferredPrompt exists:", !!deferredPrompt);
  if (deferredPrompt) {
    deferredPrompt.prompt();
    deferredPrompt.userChoice.then((choiceResult) => {
      console.log("Install choice:", choiceResult.outcome);
      if (choiceResult.outcome === "accepted") {
        console.log("User accepted the install prompt");
        localStorage.setItem("luna_app_installed", "true");
        const btn = document.getElementById("install-btn");
        if (btn) btn.style.display = "none";
      } else {
        console.log("User dismissed the install prompt");
      }
      deferredPrompt = null;
    });
  } else {
    console.warn("No deferredPrompt available");
    // App might already be installed, or check if it's installed
    if (
      window.navigator.standalone === true ||
      window.matchMedia("(display-mode: standalone)").matches
    ) {
      // Already running as installed app
      showModal({
        icon: "✅",
        title: "Already Installed",
        msg: "Luna is already installed on your device! You can see it in your app drawer.",
        cancelText: "",
        confirmText: "OK",
      });
    } else {
      // Show manual install instructions
      showModal({
        icon: "📱",
        title: "Install Luna as App",
        msg: "To install:\n\n1. Tap the menu (⋮) in your browser\n2. Look for 'Install app' or 'Add to Home screen'\n3. Confirm installation",
        cancelText: "",
        confirmText: "OK",
      });
    }
  }
}

async function exportData() {
  if (!sessionPin) return;
  showModal({
    icon: "📦",
    title: "Export Backup",
    msg: "Your backup will be exported as an encrypted file. It can only be decrypted with your PIN. Keep it private.",
    confirmText: "Export",
    cancelText: "Cancel",
    onConfirm: async () => {
      const salt = getOrCreateSalt();
      const enc = await encryptData(state, sessionPin, salt);
      const saltB64 = btoa(String.fromCharCode(...salt));
      const bundle = JSON.stringify({ enc, salt: saltB64, v: 1 });
      const blob = new Blob([bundle], {
        type: "application/octet-stream",
      });
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = `luna_backup_${today()}.bin`;
      a.click();
      URL.revokeObjectURL(a.href);
    },
  });
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
      const salt = Uint8Array.from(atob(bundle.salt), (c) => c.charCodeAt(0));

      // Validate backup version
      if (bundle.v !== 1) {
        showModal({
          icon: "❌",
          title: "Invalid Backup",
          msg: "This backup format is not supported.",
          cancelText: "",
          confirmText: "OK",
        });
        return;
      }

      showModal({
        icon: "🔑",
        title: "Restore Backup",
        msg: "Enter your PIN to decrypt and restore the backup.",
        confirmText: "Restore",
        cancelText: "Cancel",
        onConfirm: async () => {
          try {
            const testDecrypted = await decryptData(
              bundle.enc,
              sessionPin,
              salt
            );
            if (testDecrypted) {
              state = testDecrypted;
              localStorage.setItem(STORE_KEY, bundle.enc);
              localStorage.setItem(SALT_KEY, bundle.salt);
              await save();
              renderCalendar();
              updateStatusCard();
              updateInsights();
              showModal({
                icon: "✅",
                title: "Restored",
                msg: "Your backup has been restored successfully.",
                cancelText: "",
                confirmText: "OK",
              });
            } else {
              showModal({
                icon: "❌",
                title: "Decryption Failed",
                msg: "The PIN is incorrect or the backup is corrupted.",
                cancelText: "",
                confirmText: "OK",
              });
            }
          } catch (err) {
            showModal({
              icon: "❌",
              title: "Restore Error",
              msg: "Could not restore backup: " + err.message,
              cancelText: "",
              confirmText: "OK",
            });
          }
        },
      });
    } catch (err) {
      showModal({
        icon: "❌",
        title: "Import Failed",
        msg: "Could not read backup file. Ensure it's valid.",
        cancelText: "",
        confirmText: "OK",
      });
    }
  });
  input.click();
}

function calculateStorageUsage() {
  let totalSize = 0;
  for (let key in localStorage) {
    if (localStorage.hasOwnProperty(key)) {
      totalSize += localStorage[key].length + key.length;
    }
  }
  // Convert to KB
  const sizeKB = (totalSize / 1024).toFixed(2);
  const usageSpan = document.getElementById("storage-usage");
  if (usageSpan) {
    usageSpan.textContent = `${sizeKB} KB`;
  }
}

function confirmClear() {
  showModal({
    icon: "🗑️",
    title: "Erase All Data",
    msg: "This will permanently delete all your cycle data and cannot be undone. Are you absolutely sure?",
    confirmText: "Yes, erase everything",
    cancelText: "Cancel",
    onConfirm: () => {
      localStorage.clear();
      location.reload();
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
  titleEl.textContent = isConfirm ? "Confirm New PIN" : "Enter New PIN";
  const msgEl = document.createElement("div");
  msgEl.className = "modal-msg";
  msgEl.id = "cpin-msg";
  msgEl.textContent = isConfirm
    ? "Re-enter your new PIN to confirm."
    : "Choose a 4-digit PIN.";

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
  cancelBtn.textContent = "Cancel";
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
        msgEl.textContent = "PINs don't match. Try again.";
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
    const salt = getOrCreateSalt();
    const newHash = await hashPin(newPin, salt);
    localStorage.setItem(PINHASH_KEY, newHash);
    sessionPin = newPin;
    await save(); // re-encrypts all data with new PIN
    document.getElementById("modal-overlay").classList.remove("visible");
    showModal({
      icon: "✅",
      title: "PIN Changed",
      msg: "Your PIN has been updated and all data re-encrypted.",
      cancelText: "",
      confirmText: "OK",
    });
  }
}

function switchTab(tab) {
  const allowed = ["calendar", "insights", "settings"];
  if (!allowed.includes(tab)) return;
  currentTab = tab;
  // Remove active from bottom nav items
  ["bnav-calendar", "bnav-insights", "bnav-settings"].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.remove("active");
  });

  // Show/hide view panels
  const calView = document.getElementById("view-calendar");
  const insView = document.getElementById("view-insights");
  const setView = document.getElementById("view-settings");
  if (calView) calView.style.display = tab === "calendar" ? "block" : "none";
  if (insView) insView.style.display = tab === "insights" ? "block" : "none";
  if (setView) setView.style.display = tab === "settings" ? "block" : "none";
  if (insView)
    insView.className =
      "insights-wrap" + (tab === "insights" ? " visible" : "");
  if (setView)
    setView.className =
      "settings-wrap" + (tab === "settings" ? " visible" : "");

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
  // Hide log panel when switching tabs
  const logPanel = document.getElementById("log-panel");
  if (logPanel) logPanel.classList.remove("visible");
}

function init() {
  const hasData = !!localStorage.getItem(STORE_KEY);
  const hasSalt = !!localStorage.getItem(SALT_KEY);
  const hasPinHash = !!localStorage.getItem(PINHASH_KEY);

  // Register Service Worker (only on http/https, not file://)
  if (
    "serviceWorker" in navigator &&
    (location.protocol === "http:" || location.protocol === "https:")
  ) {
    navigator.serviceWorker
      .register("/luna-cycle/service-worker.js")
      .then((reg) => {
        console.log("Service Worker registered:", reg);
      })
      .catch((err) => {
        console.warn("Service Worker registration failed:", err);
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
      "Enter your PIN to unlock your private health data";
  } else {
    // First time: show onboarding
    document.getElementById("lock-screen").classList.add("hidden");
    document.getElementById("onboarding").classList.remove("hidden");
  }

  updateFlowButtonVisual(1, false);
  updatePainButtonVisual(5, false);
  updateMoodButtonVisual(50, false);
  initializePainChartControls();
}

init();
