# TotalWare — Project Roadmap & Status

_Last updated: 24 June 2026_

TotalWare ek Universal Malware Analysis Platform hai (Flask). Yeh file track karti hai ki kya ban chuka hai aur kya baaki hai.

---

## 📍 CONTINUE FROM HERE (next session ke liye — Fable/koi bhi model)

**Status:** Phase A (analyzers), Phase B (Dynamic Sandbox), Phase C (Visualization) — **sab DONE**.

**Kaise chalao:** `python app.py` → `http://127.0.0.1:5000`. Emulator command se: `C:\Users\dshok\AppData\Local\Android\Sdk\emulator\emulator.exe -avd Pixel6 -no-snapshot -gpu swiftshader_indirect -tcpdump C:\Users\dshok\Downloads\capture.pcap`. frida-server: `adb root; adb shell /data/local/tmp/frida-server`.

**Naye modules bane:** `sandbox/anti_detect.js` (Frida anti-detect v2), `modules/dynamic_sandbox.py` (orchestrator), `modules/vt_behavior.py` (VT cloud sandbox), `modules/sandbox_router.py` (APK→local, baaki→VT + APK ke liye VT-merge), `modules/geolocation.py`, `modules/relationship_graph.py`, `modules/diff_analysis.py`. Endpoints: `/run_dynamic`, `/diff`.

**✅ DONE (2 July 2026) — False-positive tuning:**
- `risk_engine.py`: VT ab risk mein wired hai (`virustotal=` param; `app.py` mein `upload_and_scan` risk se PEHLE chalta hai). VT 0/40+ clean consensus → score cap 15 (CLEAN), PAR `hard_evidence` (MalwareBazaar/malicious IP/fuzzy variant/URLhaus) ho toh cap skip. VT malicious ≥10 engines → +40.
- Whitelists (`LEGIT_PKG_PREFIXES`, `KNOWN_GOOD_HOSTS`, `GOOGLE_IP_PREFIXES`): pairip/flutter/google repackaging-obfuscation-URL scoring se bahar; Google IPs IP-reputation se bahar; APK ke liye wget/curl/chmod keywords skip.
- `malware.yar`: Android_Malware_Indicators CRITICAL→MEDIUM (2→4 strings), Suspicious_Network_Activity HIGH→LOW, Base64 HIGH→MEDIUM. YARA total cap 35, YARA ≠ hard_evidence.
- `secrets_scanner.py`: AIza key ab `public_keys` (info-only), real secrets alag. UI updated.
- `urlhaus.py`: known-good hosts API check se skip. `sandbox_router.py`: +64.233./8.8.x/GCP prefixes + firebase hosts. `geolocation.py`: Google IPs map se skip.
- Tested (logic-level): Awaaz 15 CLEAN, rtochallan 100 MALICIOUS, VT-clean-but-bad-IP malware 80 MALICIOUS, clean PDF 15 CLEAN.

**✅ DONE (3 July 2026) — Phase D:** Report full update (AI analysis, VT engines, all perms, sandbox C2 merged keys `merged_candidate_c2_ips`, MITRE) + dynamic sandbox auto-run flow (button removed, download button dynamic ke baad visible). Details Phase D section mein.

**⏭️ IMMEDIATE NEXT:** Phase E — Platform (user accounts + login → scan history DB → public API). Suggestion: pehle scan history (SQLite, simple), fir accounts, fir API.

---

## ✅ DONE (ban chuka hai)

### Core file analyzers
- [x] **APK analyzer** (androguard) — package info, permissions, components, network
- [x] **PE analyzer** (.exe / .dll / .sys / .drv)
- [x] **PDF analyzer** (wired in `app.py`)
- [x] **Archive analyzer** (.zip / .7z / .rar, password support)

### Detection engines
- [x] **YARA scanning** (rules `yara_rules/malware.yar`) — file + archive ke andar
- [x] **Entropy analysis** (APK ke liye skip — kyunki compressed)
- [x] **Suspicious strings & keywords** extraction (URLs, IPs, emails)

### APK deep analysis (aaj banaye — bonus, roadmap se aage)
- [x] **Certificate forensics** — self-signed, fake signer name, weak hash, validity
- [x] **Repackaging / tampering detector** — foreign packages + library allowlist
- [x] **Suspicious API detection** — SMS, IMEI, DexClassLoader, reflection, etc.
- [x] **App name vs package mismatch** detector
- [x] **MITRE ATT&CK mapping** — behaviours → technique IDs (clickable)
- [x] **Secrets & credential scanner** — AWS/Google/JWT/private keys (regex + entropy)

### Threat intelligence
- [x] **VirusTotal** API (hash check + upload)
- [x] **AbuseIPDB** (IP reputation)
- [x] **Shodan** (host/port info)
- [x] **AlienVault OTX** (pulse reputation)

### Intelligence & output
- [x] **AI explanation** — Groq (Llama 3.1), graceful error handling
  - _Note: roadmap mein "Claude API" likha tha; humne Groq use kiya (free + reliable). Chaaho toh baad mein Claude pe switch ho sakta hai._
- [x] **Risk engine** — weighted, explainable scoring + verdict
- [x] **False-positive tuning** — clean app 90→20, malware 100 (negative testing)
- [x] **Proper UI** — premium dark theme, custom logo, all-permissions + app-info sections

---

## ⏳ PENDING (abhi karna hai)

### Phase A — Baaki analyzers ✅ DONE
- [x] **Office analyzer** — VBA macro analysis (oletools/olevba): AutoExec, Suspicious calls, IOCs + risk + UI
- [x] **PCAP analyzer** — scapy: dest IPs, DNS queries, HTTP hosts, suspicious ports; IPs fed into threat intel + risk + UI
- [x] **Fuzzy hashing (ssdeep)** — ppdeep: fuzzy hash + similarity match vs known_hashes.json (variant detection) + risk + UI
- [x] **BONUS: IP reputation → risk** — file contacting a known-malicious IP now raises score (+40)

### Phase B — Aur threat intel
- [x] **MalwareBazaar** API integration (`modules/malwarebazaar.py`, wired in `app.py`, +45 risk on confirmed match)
- [x] **URLhaus** integration (malicious URL feed) (`modules/urlhaus.py`, host check, +40 risk on malicious host)
- [x] **Dynamic Sandbox** — ✅ DONE. Universal multi-engine sandbox:
  - **APK → local Android emulator + Frida anti-detect** (`sandbox/anti_detect.js` v2): Build/props/ABI-spoof/telephony/files/anti-debug/monkey/FGS-bypass + C2-reveal (DNS/socket/HTTP/OkHttp/TLS) + dropper reveal. Emulator-detection universally defeat.
  - **Orchestrator** (`modules/dynamic_sandbox.py`): frida-server auto-start, install, perms+exemptions, spawn (headless spawn-gating fallback), comprehensive stimulation (SMS inject + broadcasts + reboot trigger), tcpdump pcap analyze, noise-filter, threat-intel, cleanup.
  - **Non-APK (.exe/.dll/.pdf/.elf/scripts) → VirusTotal cloud sandbox** (`modules/vt_behavior.py`): network behaviour + MITRE.
  - **Router** (`modules/sandbox_router.py`): file-type routing + **VT fallback/merge for APK** (local dormant ho to VT se C2).
  - **UI**: VT-style "Dynamic Sandbox — Behavior" section + `/run_dynamic` endpoint.
  - _Proven: METER C2 `45.128.12.10` (local), rtochallan C2 `104.21.64.137`/`172.67.151.52` (VT fallback, threat-intel confirmed MALICIOUS)._
  - _Known limits (har x86 sandbox ki tarah): ARM-only-packed dynamic run nahi hoti (static/VT se cover), boot-only-trigger ko real reboot chahiye, dead C2 capture nahi hota._

### Phase C — Visualization ✅ DONE
- [x] **IP Geolocation map** — Leaflet world map, IPs color-coded by reputation (`modules/geolocation.py`, ip-api.com)
- [x] **Relationship graph** — vis-network node-link: file → IPs/domains/behaviours/similar-samples (`modules/relationship_graph.py`)
- [x] **Diff analysis** — do scans compare (added/removed perms/IPs/URLs/APIs/YARA + risk change) (`modules/diff_analysis.py`, `/diff`)

### Phase D — Report ✅ DONE (3 July 2026)
- [x] **Download report update** — saare naye sections: AI Analysis, Malware Detection Engines (VT engine list), Risk Indicators, cert forensics, repackaging, suspicious APIs, MITRE (static + sandbox), secrets (+public keys alag), identity, app-info, all permissions, MalwareBazaar, URLhaus, fuzzy variant, Dynamic Sandbox C2 (merged VT+local, threat-intel tagged), file details
- [x] **UX flow** — dynamic sandbox ab static scan ke baad **auto-run** hota hai (button hataya); Download/Copy JSON buttons dynamic complete hone ke baad hi dikhte hai; AI conclusion + dynamic result scanData mein save → report mein aate hai

### Phase E — Platform (full-stack) ✅ DONE
- [x] **Scan history** (database) — `modules/database.py` (SQLAlchemy ORM, SQLite; `DATABASE_URL` env se Postgres-ready). Har scan auto-save; `templates/history.html` dashboard (search/filter/open/delete); `/history` + `/api/history` + `/api/scan/<id>` (GET/DELETE/PATCH). Uploaded files ab safe uuid naam se save hote hai (Windows reserved-name/path-traversal fix).
- [x] **User accounts** + login — Flask-Login, `User` model (password werkzeug se hashed). Login **optional** (guest bhi scan kar sakta hai; login pe scans user se link + sirf apni history dikhe). `login.html` + `signup.html`; `/signup` `/login` `/logout` `/api/me`; nav mein auth state.
- [x] **Public API** — token-based. `ApiKey` model (raw key sirf ek baar, SHA-256 hashed store). `/api/v1/scan` endpoint (Bearer / X-API-Key auth), 30 req/min rate limit (in-memory). Scan logic `run_full_scan()` helper mein nikaali (browser + API dono share karte hai). `apikeys.html` (key generate/list/revoke) + `docs.html` (API docs). Routes: `/account` `/docs` `/api/keys` (GET/POST/DELETE) `/api/v1/scan`.

**⚙️ Setup note:** `pip install SQLAlchemy Flask-Login` zaroori. `uploads/` folder ko Windows Defender exclusions mein daala hua hai (warna real malware quarantine ho jata hai). Naye DB columns add hue toh `totalware.db` delete karke restart.

### Phase F — Community ✅ DONE
- [x] **Community threat scoring** (upvote/downvote) — `Vote` model, `/api/vote` + `/api/votes/<sha256>`, "Community Verdict" widget on scan results (one vote per user per file).
- [x] **Community threat feed** — `/feed` public page, recent malicious/suspicious samples with vote counts (`community_feed()`).
- [x] **Organizations + dashboard** — `Organization` + `OrgMember` models, invite-code join, `/organizations` page: team stats, alerts (recent threats), members, team scans. Routes: `/api/orgs` (GET/POST), `/api/orgs/join`, `/api/org/<id>`.

### 🌐 English cleanup ✅ DONE — all UI text, error messages, docstrings, and code comments converted from Hinglish to professional English across every template, app.py, and all modules/*.py. Verified: no Hinglish remains, all Python compiles.

### Phase G — Ship
- [x] **Testing** + bug fixes — `pytest` suite added (`test_risk_engine.py`, `test_database.py`); 17/17 passing. Bugs fixed: (1) `run_full_scan` now wrapped in try/except in both `/scan` and `/api/v1/scan` (a bad file/network hiccup returns clean JSON instead of a 500); (2) `PATCH /api/scan/<id>` now requires login + ownership (was writable by anyone); (3) `/api/history` guards non-numeric `limit`/`offset`; (4) `/ai_conclusion` + `/export_report` handle empty/invalid JSON bodies; (5) **engine bug caught by tests** — a single decisive signal (VT ≥10 engines, exact MalwareBazaar match, or fuzzy variant) only reached POTENTIALLY UNWANTED on its own; added score floors so each is decisively MALICIOUS; (6) future-proofed `datetime.utcnow()` → timezone-aware `_utcnow()` for Python 3.12+.
- [ ] **Deployment** (cloud)
- [ ] **Documentation**

---

## 🔧 Minor items / tech debt
- [x] **Obfuscation heuristic** (`risk_engine.py`) — tuned during the false-positive fix: now uses a vowel-ratio check (< 25%) plus a legit-prefix skip, so long lowercase package segments no longer trigger false positives.
- [x] **Dead `apk_analysis.risk`** (old shallow score) removed from `apk_analyzer.py`; the UI fallback in `index.html` was updated to use only `risk_assessment.final_score`.
- [ ] **Rotate all API keys** — the keys were pasted in chat earlier, so they should be regenerated on each provider's dashboard (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, Groq, abuse.ch/MalwareBazaar) and updated in `.env`. `.env` is already git-ignored. **Manual task — must be done by the owner.**
- [x] Added `totalware.db` + `*.db` to `.gitignore` (contains user accounts / password hashes).
- [x] **False-positive fixes** (legit apps): Telegram/PayPal/Weblate + Anthropic/DigiCert/Adobe/Datadog/Facebook/go.dev added to known-good hosts; when VT is strongly clean (40+ engines, 0 malicious) a single AbuseIPDB/OTX "malicious IP" (shared cloud/CDN infra noise) is no longer treated as hard evidence — so signed legit apps (e.g. Claude Setup.exe, VT 0/74) come back CLEAN while VT-dirty malware (rtochallan 23/75) stays HIGH.
- [ ] **Future: Authenticode signature verification for PE files** — the PE analyzer currently shows "No certificate data"; extracting + validating the code-signing certificate (e.g. via `signify`) would give signed binaries from trusted CAs a proper trust signal (the correct long-term fix for signed-EXE false positives).

---

## 📌 Suggested order (mera suggestion)
1. Download report update (quick, demo-ready banata hai)
2. Office + PCAP analyzers (analyzer set complete)
3. ssdeep + MalwareBazaar + URLhaus (intel layer)
4. Sandbox API (behavioural)
5. Geo map + relationship graph + diff (visualization)
6. Platform (accounts/history/API) → Community → Deploy
