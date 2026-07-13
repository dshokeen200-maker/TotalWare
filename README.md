# 🛡️ TotalWare — Universal Malware Analysis Platform

TotalWare is a self-hosted malware analysis platform that scans **APK, EXE, PDF, Office, ZIP, and PCAP** files, combining deep static analysis, a live Android dynamic sandbox, and aggregated threat intelligence into a single, explainable risk verdict.

Built with **Python + Flask**. Think of it as a unified analysis orchestrator: it brings together VirusTotal, MalwareBazaar, URLhaus, AbuseIPDB, Shodan, and AlienVault OTX, adds its own deep static/dynamic analysis, and presents one clear verdict with human-readable reasons and MITRE ATT&CK mapping.

---

## ✨ Features

- **Multi-format scanning** — APK, EXE/DLL, PDF, Office (macro analysis), ZIP/RAR/7z, PCAP, and scripts.
- **Deep APK analysis** — permissions, components, certificate forensics, repackaging/tampering detection, suspicious API detection, app-name-vs-package identity checks, and embedded-secret scanning (via androguard).
- **Dynamic sandbox** — detonates APKs in a local Android emulator with **Frida anti-detection** to reveal live C2 traffic; non-APK files use the VirusTotal cloud sandbox.
- **Aggregated threat intelligence** — VirusTotal, MalwareBazaar, URLhaus, AbuseIPDB, Shodan, AlienVault OTX.
- **Explainable risk engine** — a single weighted score (CLEAN → MALICIOUS) with the exact reasons, plus **MITRE ATT&CK** technique mapping.
- **Detection engines** — YARA rules, entropy analysis, fuzzy hashing (ssdeep-style variant detection), and suspicious-string extraction.
- **Visualization** — IP geolocation world map, file↔IOC relationship graph, and scan-to-scan diff.
- **AI summary** — a plain-English conclusion for each scan (Groq / Llama).
- **Full platform** — user accounts (optional login), scan history, a **REST API with keys** (rate-limited), a community threat feed with voting, and team/organization dashboards.
- **Tested** — an automated `pytest` suite covering the risk engine and the database layer.

---

## 🧰 Tech Stack

| Layer | Tools |
|---|---|
| Backend | Python, Flask, Flask-Login |
| Database | SQLAlchemy (SQLite locally, Postgres-ready) |
| Static analysis | androguard, yara-python, pefile, oletools, scapy, ppdeep |
| Dynamic sandbox | Android emulator + Frida |
| Threat intel | VirusTotal, MalwareBazaar, URLhaus, AbuseIPDB, Shodan, OTX |
| AI | Groq (Llama) |
| Frontend | HTML, CSS, JavaScript (Leaflet, vis-network) |

---

## 🚀 Getting Started

### 1. Clone and install

```bash
git clone https://github.com/YOUR_USERNAME/TotalWare.git
cd TotalWare
pip install -r requirements.txt
```

### 2. Configure API keys

Copy the example environment file and fill in your own (free) API keys:

```bash
cp .env.example .env
```

Then edit `.env` with your keys (VirusTotal, AbuseIPDB, Shodan, OTX, abuse.ch, Groq).

### 3. Run

```bash
python app.py
```

Open **http://127.0.0.1:5000** in your browser.

> **Note:** The local Android dynamic sandbox requires an Android emulator + `frida-server`. Without it, APK behaviour falls back to the VirusTotal cloud sandbox — all other features work normally.

---

## 🔌 API Usage

Generate an API key from the **API Keys** page, then scan files programmatically:

```bash
curl -X POST http://127.0.0.1:5000/api/v1/scan \
  -H "Authorization: Bearer tw_live_your_key_here" \
  -F "file=@sample.apk"
```

```json
{
  "filename": "sample.apk",
  "verdict": "MALICIOUS",
  "score": 100,
  "sha256": "…",
  "reasons": ["VirusTotal: 23/75 engines flag this as malicious", "Contacts known-malicious IP(s): …"],
  "scan_id": 42
}
```

Full API documentation is available in-app at `/docs`.

---

## 🧪 Testing

```bash
pip install pytest
pytest -v
```

Covers false-positive regression tests (legitimate apps stay CLEAN, real malware stays MALICIOUS) and the full database layer (users, scans, votes, API keys, organizations).

---

## 📁 Project Structure

```
TotalWare/
├── app.py                 # Flask app, routes, scan pipeline
├── modules/               # analysis modules
│   ├── risk_engine.py     # weighted, explainable scoring
│   ├── apk_analyzer.py    # androguard-based APK static analysis
│   ├── dynamic_sandbox.py # Frida-based Android detonation
│   ├── database.py        # SQLAlchemy models + queries
│   └── …                  # PE, PDF, Office, PCAP, threat intel, etc.
├── templates/             # web UI
├── yara_rules/            # YARA detection rules
├── sandbox/               # Frida anti-detect script
├── test_*.py              # pytest suite
└── requirements.txt
```

---

## ⚠️ Limitations

- Detection relies on third-party engines (VirusTotal, MalwareBazaar, etc.); it is an aggregator, not an independent AV engine.
- The local dynamic sandbox is x86-based — ARM-only-packed samples won't run, and it cannot run on typical cloud hosts (non-APK behaviour uses the VT cloud sandbox instead).
- The heuristic risk engine is hand-tuned; it can occasionally misfire on unusual-but-legitimate files.
- Built as a portfolio/learning project — dev-grade in places (single process, in-memory rate limiting, default secret key). Not hardened for enterprise/production use.

---

## 📝 License

This project is for educational and portfolio purposes.
