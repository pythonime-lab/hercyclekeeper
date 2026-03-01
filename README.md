# Luna — Private Period & Cycle Tracker

> **AES-256-GCM encrypted. Zero data collection. Forever free.**

Luna is a privacy-first period and cycle tracking PWA (Progressive Web App). All data is encrypted locally on your device using AES-256-GCM. **Nothing is sent to any server. No accounts. No analytics. No tracking.**

## Features

- 🔒 **End-to-End Encrypted** — AES-256-GCM encryption with your personal PIN
- 📱 **Progressive Web App** — Install like a native app on any device
- 🔴 **Period Tracking** — Log flow, symptoms, mood, and notes
- 📊 **Cycle Predictions** — Estimates fertile window, ovulation, and next period
- ⏰ **Notifications** — Get reminders before your period starts
- 📈 **Cycle Statistics** — View your cycle history and patterns
- 🚫 **Completely Offline** — Works without internet connection
- 💾 **Encrypted Backup** — Export and restore your data with your PIN

## How It Works

Luna uses the **Calendar Rhythm Method** and **Standard Days Method** to estimate:

- **Fertile Window** — Days 8 through (cycle length − 11)
- **Ovulation Day** — Approximately (cycle length − 14) days from period start
- **Next Period** — Predicted based on your cycle length

**⚠️ Important:** Luna is an educational tool only. It is **not** medical advice and must not be used as a contraceptive or fertility guarantee. Always consult a healthcare professional for medical decisions.

## Privacy & Security

- **Zero Data Collection** — All data stays on your device
- **No Servers** — No cloud storage, no accounts, no syncing across devices
- **No Analytics** — No tracking, no telemetry, no third-party code
- **Encrypted Storage** — Data encrypted with your PIN before being stored
- **Open Source** — Auditable code for complete transparency

## Installation

### Web App (Recommended)

Visit: https://pythonime-lab.github.io/luna-cycle/

Then:

1. Click the menu button (⋮) in your browser
2. Select "Install app" or "Add to Home Screen"
3. Luna will work like a native app on your device

### Local Development

```bash
# Clone the repository
git clone https://github.com/pythonime-lab/luna-cycle.git
cd luna-cycle

# Open in browser (requires HTTP/HTTPS for Service Worker)
# Use a local dev server:
python -m http.server 8000
# or
npx http-server

# Visit: http://localhost:8000/luna-cycle/
```

## Technical Details

- **Framework:** Vanilla JavaScript (no dependencies)
- **Encryption:** Web Crypto API (AES-GCM)
- **Key Derivation:** PBKDF2 (250,000 iterations)
- **Offline Support:** Service Worker + Cache-first strategy
- **Browser Support:** All modern browsers (Chrome, Firefox, Safari, Edge)

## Data Structure

Luna stores:

- Last period start date
- Cycle length and period duration
- Daily logs (flow, symptoms, mood, notes)
- Cycle history
- Notification preferences

All encrypted locally. Never transmitted.

## License

MIT License — See [LICENSE.txt](LICENSE.txt)

## Medical Disclaimer

**This app provides cycle estimations based on average biological patterns. It is NOT medical advice.**

Luna estimates your cycle using pattern tracking. Actual timing varies due to:

- Stress
- Illness
- Medications
- Hormonal changes
- Individual biology

**Do NOT use as a contraceptive or fertility guarantee.** Always consult a qualified healthcare professional.

## Contributing

Found a bug? Have a feature idea? Open an issue on GitHub.

---

Made with ❤️ for privacy.
