# Your Cycle Keeper — Private Period & Cycle Tracker

> **⚠️ Beta Version 1.0.0** — Currently in active development. Features may change and bugs may occur.

> **AES-256-GCM encrypted. Zero data collection. Forever free.**

[![Support via PayPal](https://img.shields.io/badge/Support-PayPal-0070ba?style=for-the-badge&logo=paypal&logoColor=white)](https://paypal.me/pythonime)

Your Cycle Keeper is a privacy-first period and cycle tracking PWA (Progressive Web App). All data is encrypted locally on your device using AES-256-GCM. **Nothing is sent to any server. No accounts. No analytics. No tracking.**

## Features

- 🔒 **End-to-End Encrypted** — AES-256-GCM encryption with your personal PIN
- 📱 **Progressive Web App** — Install like a native app on any device
- 🩸 **Flow Tracking** — Log flow intensity (light, medium, heavy)
- 🤕 **Pain Tracking** — Rate pain levels from 1-10 in 0.5 increments
- 😊 **Mood Tracking** — Track mood (low, neutral, happy)
- 📅 **Period Markers** — Manually mark period start/end dates
- 📝 **Daily Notes** — Add custom notes (up to 500 characters)
- 📊 **Cycle Predictions** — Estimates fertile window, ovulation, and next period
- ⏰ **In-App Reminders** — Banner notification when your period is approaching
- 📈 **Symptom Charts** — Visual charts with month/year views and data export (PNG)
- 🎨 **Interactive Charts** — Filter by period, ovulation, flow, pain, or mood
- 📊 **Cycle Statistics** — View your cycle history and patterns
- ♿ **Fully Accessible** — WCAG 2.0 compliant with keyboard navigation
- 🚫 **Completely Offline** — Works without internet connection
- 💾 **Encrypted Backup** — Export and restore your data with your PIN

## How It Works

Cycle Keeper uses the **Calendar Rhythm Method** and **Standard Days Method** to estimate:

- **Fertile Window** — Days 8 through (cycle length − 11)
- **Ovulation Day** — Approximately (cycle length − 14) days from period start
- **Next Period** — Predicted based on your cycle length

**⚠️ Important:** Cycle Keeper is an educational tool only. It is **not** medical advice and must not be used as a contraceptive or fertility guarantee. Always consult a healthcare professional for medical decisions.

## Privacy & Security

- **Zero Data Collection** — All data stays on your device
- **No Servers** — No cloud storage, no accounts, no syncing across devices
- **No Analytics** — No tracking, no telemetry, no third-party code
- **Encrypted Storage** — Data encrypted with your PIN before being stored
- **Open Source** — Auditable code for complete transparency

## Installation

### Web App (Recommended)

Visit: https://yourcyclekeeper.web.app

Then:

1. Click the menu button (⋮) in your browser
2. Select "Install app" or "Add to Home Screen"
3. Cycle Keeper will work like a native app on your device

### Local Development

```bash
# Clone the repository
git clone https://github.com/pythonime-lab/yourcyclekeeper.git
cd yourcyclekeeper

# Open in browser (requires HTTP/HTTPS for Service Worker)
# Use a local dev server:
python -m http.server 8000
# or
npx http-server

# Visit: http://localhost:8000
```

## Technical Details

- **Version:** 1.0.0-beta (in active development)
- **Framework:** Vanilla JavaScript ES6 modules (zero dependencies)
- **Architecture:** Modular design with separated concerns (crypto, cycles, validation, storage)
- **Storage:** IndexedDB (persistent, survives cache clearing)
- **Encryption:** Web Crypto API (AES-256-GCM)
- **Key Derivation:** PBKDF2 (250,000 iterations, SHA-256)
- **Session Security:** 5-minute auto-lock with countdown warning
- **Offline Support:** Service Worker v3.1.0 + Cache-first strategy
- **Accessibility:** WCAG 2.0 compliant (keyboard navigation, screen reader support, focus management)
- **Browser Support:** All modern browsers with Web Crypto API (Chrome, Firefox, Safari, Edge)

## Data Structure

Cycle Keeper stores in IndexedDB:

- Last period start date
- Cycle length and period duration
- Daily logs with:
  - Flow intensity (1-3: light, medium, heavy)
  - Pain level (1-10 in 0.5 increments)
  - Mood (0-100: low, neutral, happy)
  - Custom notes (up to 500 characters)
  - Period start/end markers
- Cycle history (tracks pattern changes over time)
- PIN-derived encryption keys (PBKDF2 with random salt)

All encrypted locally with your PIN. Never transmitted. No cloud storage.


## Official Releases

Official releases are published only by the original author. Any other distributions, builds, or app store listings are unofficial and not supported.

## License

GPL v3 — See [LICENSE.txt](LICENSE.txt)

## Medical Disclaimer

**This app provides cycle estimations based on average biological patterns. It is NOT medical advice.**

Cycle Keeper estimates your cycle using pattern tracking. Actual timing varies due to:

- Stress
- Illness
- Medications
- Hormonal changes
- Individual biology

**Do NOT use as a contraceptive or fertility guarantee.** Always consult a qualified healthcare professional.

## Accessibility

Your Cycle Keeper follows **WCAG 2.0 accessibility standards**:

- **Keyboard Navigation:**
  - Tab/Shift+Tab: Navigate forward/backward through interactive elements
  - Arrow Keys: Navigate calendar dates (complex grid component)
  - Enter/Space: Activate buttons and links
  - Escape: Close modals and return focus
  - Digits 0-9 + Backspace: PIN entry on all screens
- **Screen Readers:** Semantic HTML with proper ARIA labels and roles
- **Focus Management:** Visible focus indicators, logical tab order
- **Form Controls:** Native keyboard support for inputs, selects, and textareas

Standards based on [Salesforce Accessibility Guidelines](https://trailhead.salesforce.com/content/learn/modules/coding-for-web-accessibility/understand-accessible-navigation).

## Contributing

Found a bug? Have a feature idea? Open an issue on GitHub.

---

Made with ❤️ for privacy.
