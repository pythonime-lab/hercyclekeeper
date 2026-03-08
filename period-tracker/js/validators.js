// Data normalization and validation functions
export function normalizeFlowValue(value, fallback = 1) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(1, Math.min(3, Math.round(n)));
}

export function getFlowValueFromLog(log) {
  if (!log) return null;
  if (typeof log.flow === "number" && Number.isFinite(log.flow)) {
    return normalizeFlowValue(log.flow, 1);
  }
  if (log.flow === true) return 1;
  return null;
}

export function normalizePainValue(value, fallback = 5) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  const clamped = Math.max(1, Math.min(10, n));
  return Math.round(clamped * 2) / 2;
}

export function getPainValueFromLog(log) {
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

export function normalizeMoodValue(value, fallback = 50) {
  const n = Number(value);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(0, Math.min(100, n));
}

export function getMoodValueFromLog(log) {
  if (!log) return null;
  if (typeof log.mood === "number" && Number.isFinite(log.mood)) {
    return Math.max(0, Math.min(100, log.mood));
  }
  if (log["mood-happy"] && !log["mood-low"]) return 100;
  if (log["mood-low"] && !log["mood-happy"]) return 0;
  if (log["mood-happy"] && log["mood-low"]) return 50;
  return null;
}

export function sanitize(str) {
  if (typeof str !== "string") return "";
  const div = document.createElement("div");
  div.textContent = str.slice(0, 500);
  return div.innerHTML;
}

export function safeText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = String(value);
}
