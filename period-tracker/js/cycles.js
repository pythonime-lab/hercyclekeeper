// Cycle prediction and period type determination
import { addDays, diffDays, fromISO, toISO, today } from "./dateUtils.js";

// These will be set by the main app to reference the global state
let state = null;
export function setState(stateObj) {
  state = stateObj;
}

export function getCycleInfo() {
  if (!state || !state.lastPeriodStart) return null;
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

export function calculatePredictions() {
  if (!state || !state.lastPeriodStart) return [];
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

export function getManualPeriodRange(dateStr) {
  if (!state) return null;

  const d = fromISO(dateStr);
  let currentStart = null;
  let currentStartD = null;

  const allDates = Object.keys(state.logs).sort();

  for (const date of allDates) {
    const dateD = fromISO(date);
    const log = state.logs[date];

    if (log.periodStart) {
      currentStart = date;
      currentStartD = dateD;
    }

    if (log.periodEnd && currentStart) {
      if (d >= currentStartD && d <= dateD) {
        return { start: currentStart, end: date };
      }
      currentStart = null;
      currentStartD = null;
    }
  }

  if (currentStart && currentStartD) {
    if (d >= currentStartD) {
      const maxEndD = addDays(currentStartD, state.periodDuration - 1);
      if (d <= maxEndD) {
        return { start: currentStart, end: null };
      }
    }
  }

  return null;
}

export function getDayType(dateStr) {
  if (!state) return "normal";

  const log = state.logs[dateStr];
  if (log && (log.periodStart || log.periodEnd)) {
    return "period";
  }

  const manualPeriod = getManualPeriodRange(dateStr);
  if (manualPeriod) {
    return "period";
  }

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

export function isPredictedFuturePeriod(dateStr) {
  const d = fromISO(dateStr);
  const todayD = fromISO(today());
  if (d <= todayD) return false;
  return getDayType(dateStr) === "period";
}
