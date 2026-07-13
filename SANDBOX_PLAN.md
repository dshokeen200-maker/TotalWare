# TotalWare — Dynamic Sandbox Plan

**Goal:** Kisi bhi APK ko ek safe Android emulator mein **actually chala ke** uska live network traffic capture karna, taaki uska **asli C2 IP/domain** mil jaye — chahe woh static code mein chhupa ho (reflection/runtime-loaded), jaise rtochallan.

---

## Yeh sab kaise connect hota hai (architecture)

```
APK  →  Android Emulator (detonate)
              │  live traffic capture (tcpdump)
              ▼
        capture.pcap
              │  feed into EXISTING module
              ▼
     pcap_analyzer.py  →  real IPs / domains
              │
              ▼
     threat_intel (AbuseIPDB/OTX)  →  reputation
              │
              ▼
     risk_engine + UI
```

**Best part:** sab pieces (pcap analyzer, threat intel, risk, UI) **already bani hui hai.** Sirf "APK ko chala ke pcap banana" wala part naya hai.

---

## Key trick

Android emulator mein ek built-in flag hai:
```
emulator -avd <name> -tcpdump capture.pcap
```
Yeh emulator ka **saara network traffic** ek pcap mein record kar deta hai — har connection ki **destination IP** included (HTTPS bhi, kyunki humein content nahi, IP chahiye). Yahi hamara C2 capture karega.

---

## Prerequisites (one-time setup)

1. **Android Studio** install (ya sirf command-line tools + emulator)
2. **Ek AVD banao** — recommend: Android 9 ya 10, **Google APIs** image (Play Store wala nahi — taaki rootable rahe aur malware compatible ho)
3. **ADB** (Android Debug Bridge) — Android Studio ke saath aata hai
4. (Advanced, baad mein) **Frida** + frida-server — runtime API hooking ke liye

---

## ⚠️ Safety / Isolation (IMPORTANT — real malware chala rahe hai)

- Emulator mein **koi personal data / account mat daalo**
- Har run ke baad emulator ko **snapshot se reset** karo (clean state)
- Malware **live C2 se baat karega** → woh **tumhara IP dekh lega**. Analysis ke waqt host pe **VPN** use karo taaki tumhara asli IP attacker ko na mile
- Emulator ko isolated rakho; sensitive network pe mat chalao

---

## Build steps (phased)

### Step 1 — Emulator setup + manual test
- AVD banao, boot karo
- `adb install sample.apk`
- `emulator -avd <name> -tcpdump test.pcap` se boot karke app chalao
- `test.pcap` ko apne **existing pcap analyzer** pe daal ke dekho IPs nikal rahe hai

### Step 2 — Automation module (`modules/dynamic_sandbox.py`)
Ek function `run_dynamic(apk_path)` jo:
1. Emulator ko tcpdump ke saath start kare (ya already-running emulator pe capture shuru kare)
2. `adb install` se APK install kare
3. `adb shell monkey` / `am start` se app launch kare
4. ~30–60 sec wait kare (app ko chalne de)
5. Capture stop karke `.pcap` pull kare
6. `analyze_pcap(pcap)` call kare → IPs/domains return

### Step 3 — Integrate into app.py
- Ek alag **"Run Dynamic Analysis"** button/endpoint (kyunki yeh slow hai + emulator chahiye)
- Result ko risk + UI mein dikhao (real C2 IPs → threat intel)

### Step 4 (Advanced) — Frida hooks
- frida-server emulator pe chalao
- `connect()` / `InetAddress` / OkHttp calls hook karke **asli destination log** karo — yeh **VPN/encryption ke peeche bhi** dikhata hai
- Yeh ultimate C2 reveal hai

---

## Realistic note
Yeh poore project ka sabse bada part hai. Step 1 (emulator setup) sabse bada hurdle hai — woh ho gaya toh baaki Python automation easy hai (pieces ready hai). Agar emulator setup mushkil lage, toh **MobSF** (open-source tool) yeh sab package karke deta hai — use bhi integrate kar sakte hai. Par apna banane mein seekhna zyada hai.
