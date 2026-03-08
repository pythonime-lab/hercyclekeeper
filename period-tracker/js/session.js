// Session management and timeout logic
const SESSION_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes
const WARN_AT_MS = SESSION_TIMEOUT_MS - 60000; // 1 minute before timeout

let sessionTimer = null;
let warnTimer = null;
let countdownInterval = null;
let lastActivity = Date.now();

export function getSessionTimer() {
  return { sessionTimer, warnTimer, lastActivity };
}

export function setSessionTimers(session, warn, lastAct) {
  sessionTimer = session;
  warnTimer = warn;
  lastActivity = lastAct;
}

export function resetSessionTimer() {
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

export function startCountdown(seconds) {
  clearInterval(countdownInterval);
  let s = seconds;
  const countEl = document.getElementById("timeout-count");
  if (!countEl) return;
  countEl.textContent = s;
  countdownInterval = setInterval(() => {
    s--;
    if (countEl) countEl.textContent = s;
    if (s <= 0) clearInterval(countdownInterval);
  }, 1000);
}

export function hideBanner() {
  const bannerEl = document.getElementById("timeout-banner");
  if (bannerEl) bannerEl.classList.remove("visible");
  clearInterval(countdownInterval);
}

// lockApp will be imported from main app module
export let lockApp = null;
export function setLockApp(fn) {
  lockApp = fn;
}
