// Period marking and cycle recalculation logic
import { addDays, fromISO } from "./dateUtils.js";

let state = null;
export function setState(stateObj) {
  state = stateObj;
}

export function cleanupConsecutiveMarkers() {
  if (!state) return;

  const allDates = Object.keys(state.logs).sort();
  let lastStartDate = null;
  let lastEndDate = null;

  for (const dateStr of allDates) {
    const log = state.logs[dateStr];

    if (log.periodStart) {
      if (lastStartDate) {
        const prevLog = state.logs[lastStartDate];
        if (prevLog && prevLog.periodStart) {
          delete prevLog.periodStart;
        }
      }
      lastStartDate = dateStr;
    }

    if (log.periodEnd) {
      if (lastEndDate && lastEndDate !== lastStartDate) {
        const prevLog = state.logs[lastEndDate];
        if (prevLog && prevLog.periodEnd) {
          delete prevLog.periodEnd;
        }
      }
      lastEndDate = dateStr;
    }

    if (log.periodStart) {
      lastEndDate = null;
    }
  }

  cleanupEmptyLogs();
}

export function cleanupEmptyLogs() {
  if (!state) return;

  for (const dateStr in state.logs) {
    const log = state.logs[dateStr];
    const hasFlow = !!log.flow;
    const hasPain = !!log.pain;
    const hasMood = log.mood !== undefined && log.mood !== null;
    const hasNote = !!(log.note && log.note.trim());
    const hasPeriodStart = !!log.periodStart;
    const hasPeriodEnd = !!log.periodEnd;

    if (
      !hasFlow &&
      !hasPain &&
      !hasMood &&
      !hasNote &&
      !hasPeriodStart &&
      !hasPeriodEnd
    ) {
      delete state.logs[dateStr];
    }
  }
}

export function recalculateCycleFromMarkers() {
  if (!state) return;

  const periodStarts = [];
  const periodRanges = [];

  for (const dateStr in state.logs) {
    const log = state.logs[dateStr];
    if (log.periodStart) {
      periodStarts.push(dateStr);
    }
  }

  if (periodStarts.length === 0) return;

  periodStarts.sort();

  for (let i = 0; i < periodStarts.length; i++) {
    const startDate = periodStarts[i];
    let endDate = null;
    let duration = state.periodDuration;

    const startD = fromISO(startDate);
    for (const dateStr in state.logs) {
      const log = state.logs[dateStr];
      if (log.periodEnd) {
        const endD = fromISO(dateStr);
        const diff = diffDays(startD, endD);
        if (diff >= 0 && diff <= 10 && (!endDate || dateStr < endDate)) {
          endDate = dateStr;
          duration = diff + 1;
        }
      }
    }

    periodRanges.push({ start: startDate, duration });
  }

  const newHistory = [];
  for (let i = 0; i < periodStarts.length; i++) {
    const startDate = periodStarts[i];
    const nextStart = periodStarts[i + 1];

    let cycleLength = state.cycleLength;
    if (nextStart) {
      cycleLength = diffDays(fromISO(startDate), fromISO(nextStart));
    }

    newHistory.push({
      start: startDate,
      length: cycleLength,
    });
  }

  if (newHistory.length > 0) {
    state.cycleHistory = newHistory;
    state.lastPeriodStart = periodStarts[periodStarts.length - 1];

    if (newHistory.length >= 2) {
      const completedCycles = newHistory.slice(0, -1);
      if (completedCycles.length > 0) {
        const avgLength = Math.round(
          completedCycles.reduce((sum, c) => sum + c.length, 0) /
            completedCycles.length
        );
        if (avgLength >= 20 && avgLength <= 45) {
          state.cycleLength = avgLength;
        }
      }
    }

    const markedDurations = periodRanges
      .filter((r) => r.duration > 0 && r.duration <= 10)
      .map((r) => r.duration);

    if (markedDurations.length > 0) {
      const avgDuration = Math.round(
        markedDurations.reduce((sum, d) => sum + d, 0) / markedDurations.length
      );
      if (avgDuration >= 1 && avgDuration <= 10) {
        state.periodDuration = avgDuration;
      }
    }
  }
}

function diffDays(a, b) {
  return Math.round((b - a) / 86400000);
}
