# 🔍 SecretScan AI — Secrets Detection Engine

> A dual-engine (Regex + Machine Learning) web-based tool that scans source code and configuration files for exposed secrets, credentials, API keys, and sensitive data — before they reach production.

---

## 📌 Overview

SecretScan AI is a lightweight, self-hosted security tool built with **Python** and **Flask**. It combines two detection strategies to find secrets hiding in your codebase:

- **Regex Engine** — 19 handcrafted patterns targeting known secret formats (AWS keys, GitHub tokens, Stripe keys, JWTs, database URLs, and more)
- **ML Anomaly Engine** — A `GradientBoostingClassifier` trained on entropy, character distribution, and structural features to catch secrets that don't match known patterns

Upload any source file through the browser UI and get an instant, severity-ranked report with redacted values, risk scoring, and category breakdowns — all without sending your code to any third-party service.

---

## 🎯 Why This Exists

Secrets leaked in source code are one of the most common causes of security breaches. Developers accidentally commit:

- API keys hardcoded during development
- Database passwords in config files
- Private keys and JWT secrets in `.env` files checked into git
- Cloud credentials embedded in scripts

Tools like GitHub's secret scanning only catch secrets **after** they've been pushed. SecretScan AI lets you scan files **locally, before committing** — acting as your last line of defence.

---

## ✨ Features

| Feature | Details |
|---|---|
| 🔎 Dual Detection | Regex patterns + ML model running in parallel |
| 🎨 Dark Terminal UI | Cybersecurity-themed interface with drag-and-drop upload |
| 📊 Risk Scoring | 0–100 risk score computed from severity-weighted findings |
| 🏷️ Severity Levels | Critical / High / Medium / Low per finding |
| 🗂️ Category Grouping | Cloud Credentials, Auth Tokens, PII, Cryptographic Keys, etc. |
| 🔒 Redaction | Secrets are masked before display — raw values never shown |
| 🧬 Fingerprinting | MD5 fingerprint per finding for deduplication |
| 📈 Confidence Score | ML findings show model confidence percentage |
| ⚡ File Cleanup | Uploaded files are deleted from server immediately after scan |
| 🚦 Rate Limiting | 5-second cooldown between scans per IP |
| 📁 File Validation | Extension allowlist + 10MB size cap |

---

## 🧠 How Detection Works

### 1. Regex Engine
Scans every line of the uploaded file against 19 compiled regex patterns. Each pattern targets a specific secret format:

| Pattern | Example Match |
|---|---|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| GitHub Token | `ghp_[A-Za-z0-9]{36}` |
| Stripe Secret Key | `sk_live_...` |
| Google API Key | `AIza[0-9A-Za-z-_]{35}` |
| Slack Token | `xoxb-...` / `xoxp-...` |
| JWT Token | `eyJ...header.payload.signature` |
| Database URL | `postgresql://user:pass@host/db` |
| Private Key Block | `-----BEGIN RSA PRIVATE KEY-----` |
| SSH Key | `-----BEGIN OPENSSH PRIVATE KEY-----` |
| SendGrid Key | `SG.xxxx.xxxx` |
| Twilio API Key | `SK[0-9a-fA-F]{32}` |
| Heroku API Key | `heroku[a-zA-Z0-9]{32}` |
| Bearer Token | `Bearer <token>` |
| Password in Config | `password = ...` / `passwd: ...` |
| Generic Secret | `api_key = ...` / `secret = ...` |
| Email Address | `user@domain.com` |
| IPv4 Address | `192.168.x.x` |
| AWS Secret Key | `aws_secret_access_key = ...` |
| GitHub OAuth Token | `gho_[A-Za-z0-9]{36}` |

### 2. ML Anomaly Engine
For every token in the file, the model extracts 16 features and predicts whether it looks like a secret:

- **Shannon Entropy** — high-entropy strings (random-looking) score higher
- **Character Ratios** — digit / uppercase / lowercase / special char ratios
- **Length Features** — long tokens (20+, 40+ chars) are more suspicious
- **Prefix Detection** — known secret prefixes (`AKIA`, `ghp_`, `eyJ`, etc.)
- **Uniqueness Ratio** — how many unique characters relative to length
- **Common Word Filter** — skips `hello`, `true`, `false`, `null`, etc.

The model uses a **65% confidence threshold** — only findings above this are reported, reducing false positives.

### 3. Risk Score
Each finding contributes to a 0–100 risk score:

```
Critical finding  → +40 points
High finding      → +20 points
Medium finding    → +10 points
Low finding       →  +2 points
```

The score determines the overall risk badge: `CLEAN` → `LOW` → `MEDIUM` → `HIGH` → `CRITICAL`

---

## 🗂️ Project Structure

```
secret_scanner_ai/
├── app.py                  # Flask web server + /scan JSON API
├── scanner.py              # Core scan logic, Finding dataclass, redaction
├── ai_model.py             # ML model training + prediction functions
├── patterns.json           # 19 regex patterns for known secret formats
├── requirements.txt        # Python dependencies
├── demo_secrets.py         # Demo test file with fake credentials
├── .gitignore
├── README.md
└── templates/
    └── index.html          # Full frontend UI (dark terminal theme)
```

---

## 🖥️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+, Flask 3.x |
| ML Model | scikit-learn — GradientBoostingClassifier |
| Feature Engineering | NumPy, Shannon Entropy, Regex |
| Frontend | Vanilla HTML / CSS / JavaScript |
| Fonts | IBM Plex Mono + DM Sans (Google Fonts) |
| File Handling | Werkzeug secure_filename |

---

## 📸 UI Highlights

- **Drag-and-drop upload** with file-type icons per extension
- **Animated progress bar** with real-time scan stage labels
- **5 stat cards** — Total, Critical, High, Medium, Low findings
- **Risk meter bar** that animates to your score on results load
- **Filterable findings table** — filter by severity with one click
- **Expandable rows** — click any finding to see fingerprint, detection method, and category
- **Category chips** — summarizes what types of secrets were found
- **Clean state** — friendly message when no secrets are detected

---

## 🧪 Testing with Demo File

A `demo_secrets.py` file is included with ~80 lines of realistic-looking fake credentials covering every detection category. Upload it via the UI to see the full scanner in action.

Expected results: **20–30+ findings** across all severity levels including AWS keys, GitHub tokens, Stripe keys, database URLs, JWT tokens, SSH keys, hardcoded passwords, emails, and IPs.

> ⚠️ All credentials in `demo_secrets.py` are completely fake and follow real formats only for testing purposes.

---

## 🔐 Security Design Decisions

- Uploaded files are **deleted immediately** after scanning — nothing is stored
- Secrets are **redacted** before rendering in the UI (only first few + last 2 chars shown)
- Each finding gets a **MD5 fingerprint** for deduplication
- **Rate limiting** prevents abuse (5s per IP)
- **Extension allowlist** rejects executables, archives, and non-code files
- **10MB file size cap** prevents memory exhaustion
- The app runs on `debug=False` in production mode

---

## ⚙️ Supported File Types

`.py` `.js` `.ts` `.env` `.json` `.yaml` `.yml` `.sh` `.bash` `.conf` `.cfg` `.ini` `.toml` `.rb` `.php` `.go` `.rs` `.java` `.cs` `.cpp` `.c` `.tf` `.hcl` `.xml` `.properties` `.dockerfile`

---

## 🚀 Installation & Local Setup

### Prerequisites

Make sure you have the following installed:
- **Python 3.10 or higher** — [Download](https://www.python.org/downloads/)
- **pip** — comes bundled with Python
- **Git** — [Download](https://git-scm.com/)

---

### Step 1 — Clone the Repository

```bash
git clone https://github.com/jaigudesahil/secret-scanner-ai.git
cd secret-scanner-ai
```

---

### Step 2 — Create a Virtual Environment (Recommended)

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

You should see `(venv)` appear in your terminal prompt.

---

### Step 3 — Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- `flask` — web framework
- `scikit-learn` — ML model
- `numpy` — feature array processing
- `werkzeug` — secure file handling

---

### Step 4 — Run the App

```bash
python app.py
```

You should see:
```
* Running on http://0.0.0.0:5000
```

---

### Step 5 — Open in Browser

```
http://localhost:5000
```

Upload any source file or use the included `demo_secrets.py` to test.

---

### Step 6 — Stop the Server

Press `Ctrl + C` in the terminal to stop Flask.

---

## 🛠️ Troubleshooting

| Problem | Fix |
|---|---|
| `ModuleNotFoundError: flask` | Run `pip install -r requirements.txt` |
| `ModuleNotFoundError: sklearn` | Run `pip install scikit-learn` |
| Port 5000 already in use | Change port in `app.py`: `app.run(port=8080)` |
| `TemplateNotFound: index.html` | Make sure you run `python app.py` from inside the project root folder, not a subfolder |
| Upload returns 404 | Make sure you're using the new `app.py` — the old version didn't have the `/scan` route |
| File type not supported | Only source code and config file extensions are accepted — see supported types above |

---

## 🤝 Contributing

Pull requests are welcome. To contribute:

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m "feat: add your feature"`
4. Push to the branch: `git push origin feat/your-feature`
5. Open a Pull Request

Ideas for contributions:
- Add more regex patterns to `patterns.json`
- Improve ML training data in `ai_model.py`
- Add multi-file / zip archive scanning
- Add a CLI mode (`python scanner.py <file>`)
- Export findings as JSON or PDF report

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

## 👨‍💻 Author

**Sahil Jaigude**
- GitHub: [@jaigudesahil](https://github.com/jaigudesahil)

---

> Built as a cybersecurity learning project. Not intended to replace enterprise-grade secret scanning tools like GitGuardian, Trufflehog, or Gitleaks — but great for understanding how they work under the hood.