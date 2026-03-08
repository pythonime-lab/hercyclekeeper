// Keyboard navigation and accessibility module
import { addDays, fromISO, toISO } from "./dateUtils.js";

let currentTab = "calendar";
let viewMonth = new Date();

export function setNavigationState(tab, month) {
  currentTab = tab;
  viewMonth = month;
}

export function getNavigationState() {
  return { currentTab, viewMonth };
}

export function initKeyboardNavigation(callbacks) {
  const {
    pinInput,
    pinDelete,
    setupPinInput,
    setupPinDelete,
    changePinInput,
    closeLogPanel,
    renderCalendar,
  } = callbacks;

  document.addEventListener("keydown", (e) => {
    // Don't interfere with native input/select/textarea keyboard behavior
    const focused = document.activeElement;
    const isFormElement =
      focused &&
      (focused.tagName === "INPUT" ||
        focused.tagName === "SELECT" ||
        focused.tagName === "TEXTAREA");

    // Focus trap for ALL modals (prevent tabbing out to background content)
    if (e.key === "Tab") {
      // Check for log panel modal
      const logModal = document.getElementById("log-modal-overlay");
      const isLogModalOpen = logModal && logModal.classList.contains("visible");

      // Check for generic modal
      const genericModal = document.getElementById("modal-overlay");
      const isGenericModalOpen =
        genericModal && genericModal.classList.contains("visible");

      if (isLogModalOpen) {
        const logPanel = document.getElementById("log-panel");
        if (logPanel) {
          const focusableElements = logPanel.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          );
          const firstElement = focusableElements[0];
          const lastElement = focusableElements[focusableElements.length - 1];

          if (e.shiftKey) {
            if (document.activeElement === firstElement) {
              e.preventDefault();
              lastElement.focus();
            }
          } else {
            if (document.activeElement === lastElement) {
              e.preventDefault();
              firstElement.focus();
            }
          }
        }
      } else if (isGenericModalOpen) {
        const modalBox = genericModal.querySelector(".modal-box");
        if (modalBox) {
          const focusableElements = modalBox.querySelectorAll(
            'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
          );
          const firstElement = focusableElements[0];
          const lastElement = focusableElements[focusableElements.length - 1];

          if (e.shiftKey) {
            if (document.activeElement === firstElement) {
              e.preventDefault();
              lastElement.focus();
            }
          } else {
            if (document.activeElement === lastElement) {
              e.preventDefault();
              firstElement.focus();
            }
          }
        }
      }
    }

    // Close modal on Escape key (but not if typing in a form field)
    if (e.key === "Escape" && !isFormElement) {
      const logModal = document.getElementById("log-modal-overlay");
      if (logModal && logModal.classList.contains("visible")) {
        closeLogPanel();
        return;
      }

      const genericModal = document.getElementById("modal-overlay");
      if (genericModal && genericModal.classList.contains("visible")) {
        genericModal.classList.remove("visible");
        return;
      }
    }

    // Don't handle keys if user is interacting with a select dropdown
    if (
      isFormElement &&
      focused.tagName === "SELECT" &&
      (e.key === "ArrowUp" ||
        e.key === "ArrowDown" ||
        e.key === "Enter" ||
        e.key === " ")
    ) {
      // Let native select behavior work
      return;
    }

    // Handle keyboard PIN entry on lock screen
    const lockScreen = document.getElementById("lock-screen");
    if (lockScreen && !lockScreen.classList.contains("hidden")) {
      if (e.key >= "0" && e.key <= "9") {
        e.preventDefault();
        pinInput(e.key);
      } else if (e.key === "Backspace") {
        e.preventDefault();
        pinDelete();
      }
      return;
    }

    // Handle keyboard PIN entry on onboarding screen
    const onboarding = document.getElementById("onboarding");
    if (onboarding && !onboarding.classList.contains("hidden")) {
      if (e.key >= "0" && e.key <= "9") {
        e.preventDefault();
        setupPinInput(e.key);
      } else if (e.key === "Backspace") {
        e.preventDefault();
        setupPinDelete();
      } else if (e.key === "Enter") {
        e.preventDefault();
        const startBtn = document.getElementById("onboard-start-btn");
        if (startBtn && !startBtn.disabled) {
          startBtn.click();
        }
      }
      return;
    }

    // Handle keyboard PIN entry in change PIN modal
    const modalOverlay = document.getElementById("modal-overlay");
    if (modalOverlay && modalOverlay.classList.contains("visible")) {
      const modalBox = modalOverlay.querySelector(".modal-box");
      const pinDots = modalBox?.querySelector("#cpin-dots");
      if (pinDots) {
        if (e.key >= "0" && e.key <= "9") {
          e.preventDefault();
          changePinInput(e.key);
        } else if (e.key === "Backspace") {
          e.preventDefault();
          changePinInput("⌫");
        }
      }
      return;
    }

    // Arrow key navigation for calendar grid (complex component)
    if (currentTab === "calendar") {
      const logModal = document.getElementById("log-modal-overlay");
      const isLogOpen = logModal && logModal.classList.contains("visible");

      // Calendar date navigation with arrow keys (only when modal is closed)
      if (
        !isLogOpen &&
        (e.key === "ArrowLeft" ||
          e.key === "ArrowRight" ||
          e.key === "ArrowUp" ||
          e.key === "ArrowDown")
      ) {
        const focused = document.activeElement;
        if (
          focused &&
          focused.classList.contains("cal-day") &&
          focused.dataset.date
        ) {
          e.preventDefault();
          const currentDate = fromISO(focused.dataset.date);
          let newDate;

          if (e.key === "ArrowLeft") {
            newDate = addDays(currentDate, -1);
          } else if (e.key === "ArrowRight") {
            newDate = addDays(currentDate, 1);
          } else if (e.key === "ArrowUp") {
            newDate = addDays(currentDate, -7);
          } else if (e.key === "ArrowDown") {
            newDate = addDays(currentDate, 7);
          }

          if (newDate) {
            const newDateStr = toISO(newDate);
            const newCell = document.querySelector(
              `.cal-day[data-date="${newDateStr}"]`
            );
            if (newCell) {
              newCell.focus();
            } else {
              // Date is in a different month - navigate to that month
              viewMonth = new Date(
                newDate.getFullYear(),
                newDate.getMonth(),
                1
              );
              renderCalendar();
              setTimeout(() => {
                const targetCell = document.querySelector(
                  `.cal-day[data-date="${newDateStr}"]`
                );
                if (targetCell) targetCell.focus();
              }, 0);
            }
          }
        }
      }
    }
  });
}
