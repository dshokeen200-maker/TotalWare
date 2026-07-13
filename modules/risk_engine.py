import re

# ═══════════════════════════════════════════════════════════════
#  Known-legit ecosystem whitelists (Google / Firebase / Flutter)
#  — none of these are C2/repackaging/obfuscation
# ═══════════════════════════════════════════════════════════════

LEGIT_PKG_PREFIXES = (
    "com.google", "com.android", "androidx", "android",
    "io.flutter", "dev.flutter", "dev.fluttercommunity",
    "com.pairip",                       # Google Play app-protection (integrity)
    "kotlin", "kotlinx", "org.jetbrains", "dagger",
    "com.squareup", "io.reactivex", "org.apache", "javax", "java",
    "com.facebook", "com.unity3d", "com.onesignal", "com.razorpay",
)

KNOWN_GOOD_HOSTS = (
    "googleapis.com", "google.com", "gstatic.com", "googleusercontent.com",
    "firebasestorage.app", "firebaseio.com", "firebase.google.com",
    "app-measurement.com", "crashlytics.com", "google-analytics.com",
    "googletagmanager.com", "android.com", "googlesource.com",
    "github.com", "githubusercontent.com", "gitlab.com",
    "microsoft.com", "apple.com", "cloudflare.com",
    "w3.org", "schemas.android.com", "example.com",
    "t.me", "telegram.org", "telegram.me", "paypal.com", "weblate.org",
    "anthropic.com", "claude.ai", "digicert.com", "adobe.com",
    "datadoghq.com", "facebook.net", "go.dev",
)

# Google's IP ranges (for the raw-IP URL check)
GOOGLE_IP_PREFIXES = (
    "64.233.", "142.250.", "142.251.", "172.217.",
    "74.125.", "216.239.", "8.8.8.", "8.8.4.",
)

# Inside an APK these keywords are common in legit native libs (Flutter/NDK/busybox strings)
WEAK_KEYWORDS_FOR_APK = {"wget", "curl", "chmod", "sudo", "base64", "rm -rf"}


def _host_of(url_or_host):
    h = url_or_host.lower().strip()
    h = re.sub(r'^https?://', '', h)
    return h.split('/')[0].split(':')[0]


def _is_known_good_host(url_or_host):
    h = _host_of(url_or_host)
    return any(h == d or h.endswith('.' + d) for d in KNOWN_GOOD_HOSTS)


def _is_google_ip(ip):
    return any(ip.startswith(p) for p in GOOGLE_IP_PREFIXES)


def _vowel_ratio(s):
    if not s:
        return 1.0
    return sum(1 for c in s.lower() if c in "aeiou") / len(s)


def calculate_risk(hashes, strings, entropy, yara_results, apk_results=None, office_results=None, pcap_results=None, ip_intel=None, fuzzy_results=None, malwarebazaar=None, urlhaus=None, virustotal=None):
    score = 0
    reasons = []
    indicators = []

    # "Hard evidence" flags — if any of these hit, the VT-clean cap does NOT apply
    hard_evidence = False

    # "Definitive malware" flags — a single one of these is decisive on its own
    # (a strong VirusTotal consensus, an exact MalwareBazaar match, or a fuzzy variant),
    # so we apply a score floor at the end to guarantee the right verdict.
    mb_hit = False
    fuzzy_variant_hit = False
    vt_strong_malicious = False

    # VirusTotal strongly-clean consensus (40+ engines, none malicious).
    # When VT is this confident, a single AbuseIPDB/OTX "malicious IP" hit — usually
    # noise on shared cloud/CDN infrastructure (Cloudflare/AWS/GCP/Anthropic/Meta) —
    # is NOT treated as hard evidence, so it can't override VT to MALICIOUS.
    _vt_stats = (virustotal or {}).get("stats", {}) if (virustotal and virustotal.get("found")) else {}
    vt_strong_clean = (
        _vt_stats.get("total_engines", 0) >= 40
        and _vt_stats.get("malicious", 0) == 0
        and _vt_stats.get("suspicious", 0) <= 1
    )

# ── Entropy Score (non-APK only; an APK is a ZIP = always high entropy) ──
    if not apk_results:
        entropy_score = entropy.get("score", 0)
        if entropy_score > 7.5:
            score += 30
            reasons.append("Extremely high entropy — file is heavily packed/encrypted")
            indicators.append({"type": "entropy", "severity": "CRITICAL", "detail": f"Entropy: {entropy_score}/8.0"})
        elif entropy_score > 7.0:
            score += 20
            reasons.append("High entropy — file may be packed")
            indicators.append({"type": "entropy", "severity": "HIGH", "detail": f"Entropy: {entropy_score}/8.0"})
        elif entropy_score > 5.0:
            score += 10
            reasons.append("Medium entropy — slightly suspicious")
            indicators.append({"type": "entropy", "severity": "MEDIUM", "detail": f"Entropy: {entropy_score}/8.0"})

    # ── Suspicious Keywords ────────────────────────
    suspicious = strings.get("suspicious_keywords", [])
    if apk_results:
        # APK: wget/curl/chmod keywords are normal strings in Flutter/NDK libs — skip
        suspicious = [k for k in suspicious if k.lower() not in WEAK_KEYWORDS_FOR_APK]
    if suspicious:
        score += min(len(suspicious) * 10, 30)          # cap 30 — keyword spam se hi 100 na ho jaye
        reasons.append(f"Suspicious keywords found: {', '.join(suspicious)}")
        indicators.append({"type": "strings", "severity": "HIGH", "detail": f"Keywords: {', '.join(suspicious)}"})

# ── YARA Matches ───────────────────────────────
    # NOTE: these are our own heuristic rules — NOT hard_evidence (they don't block the VT trust cap)
    # + total YARA contribution cap 35 (double-counting: same rule main_file + classes.dex)
    yara_matches = yara_results.get("matches", [])
    yara_score = 0
    for match in yara_matches:
        sev = match.get("severity", "LOW")
        if sev == "CRITICAL":
            yara_score += 30
        elif sev == "HIGH":
            yara_score += 20
        elif sev == "MEDIUM":
            yara_score += 10
        else:
            yara_score += 5
        reasons.append(f"YARA rule matched: {match.get('rule')} — {match.get('description')}")
        indicators.append({"type": "yara", "severity": sev, "detail": match.get("rule")})
    score += min(yara_score, 35)

# ── APK Specific ───────────────────────────────
    if apk_results and "error" not in apk_results:
        dangerous_perms = apk_results.get("permissions", {}).get("dangerous_permissions", [])

        # Dangerous permissions
        if len(dangerous_perms) >= 5:
            score += 25
            reasons.append(f"Many dangerous permissions: {len(dangerous_perms)} found")
            indicators.append({"type": "permissions", "severity": "CRITICAL", "detail": f"{len(dangerous_perms)} dangerous permissions"})
        elif len(dangerous_perms) >= 2:
            score += 15
            reasons.append(f"Dangerous permissions found: {', '.join(dangerous_perms)}")
            indicators.append({"type": "permissions", "severity": "HIGH", "detail": f"{len(dangerous_perms)} dangerous permissions"})

# REQUEST_INSTALL_PACKAGES — very suspicious
        if "android.permission.REQUEST_INSTALL_PACKAGES" in dangerous_perms:
            score += 20
            reasons.append("Can install other apps silently — dropper malware indicator")
            indicators.append({"type": "permissions", "severity": "CRITICAL", "detail": "REQUEST_INSTALL_PACKAGES"})

# ── VPN permission (can intercept all device traffic) ──
        if apk_results.get("permissions", {}).get("uses_vpn"):
            score += 15
            reasons.append("Requests VPN permission (BIND_VPN_SERVICE) — can intercept all device traffic")
            indicators.append({"type": "permissions", "severity": "HIGH", "detail": "BIND_VPN_SERVICE (VPN)"})

# Package name obfuscation — vowel-ratio check + legit-prefix skip
        package = apk_results.get("app_info", {}).get("package_name", "")

        if package and not package.startswith(LEGIT_PKG_PREFIXES):
            parts = package.split(".")
            # long + lowercase isn't enough — it must be genuinely unreadable (vowels < 25%)
            obfuscated = any(
                len(p) > 10 and p.isalpha() and p.islower() and _vowel_ratio(p) < 0.25
                for p in parts
            )
            if obfuscated:
                score += 20
                reasons.append(f"Obfuscated package name detected: {package}")
                indicators.append({"type": "obfuscation", "severity": "CRITICAL", "detail": f"Package: {package}"})

# Receivers — common in malware for persistence
        receivers = apk_results.get("components", {}).get("receivers", [])
        suspicious_receivers = [r for r in receivers
                                if any(x in r.lower() for x in ['boot', 'sms', 'call'])
                                and not r.startswith(LEGIT_PKG_PREFIXES)]
        if suspicious_receivers:
            score += 15
            reasons.append(f"Suspicious receivers found: {', '.join(suspicious_receivers)}")
            indicators.append({"type": "components", "severity": "HIGH", "detail": f"Suspicious receivers: {len(suspicious_receivers)}"})

# ── Repackaging red flags — Google/Flutter/pairip whitelist ke saath ──
        repack = apk_results.get("repackaging", {})
        foreign = [p for p in repack.get("foreign_packages", [])
                   if not p.startswith(LEGIT_PKG_PREFIXES)]
        legit_segments = {seg for pref in LEGIT_PKG_PREFIXES for seg in pref.split(".")}
        legit_segments.update({"fluttercommunity", "pairip", "firebase", "flutter", "gms", "ads"})
        gibberish = [g for g in repack.get("gibberish_packages", []) if g not in legit_segments]

        repack_flags = []
        if foreign:
            repack_flags.append(f"Alag package family se components: {', '.join(foreign)}")
        if gibberish:
            repack_flags.append(f"Random/obfuscated package naam: {', '.join(gibberish)}")
        if repack_flags:
            score += 12
            reasons.append(f"Repackaging detected: {', '.join(repack_flags)}")
            indicators.append({
                "type": "repackaging",
                "severity": "CRITICAL",
                "detail": ', '.join(repack_flags)
            })

# ── Suspicious API calls ──
        sus_apis = apk_results.get("suspicious_apis", {}).get("apis", [])
        if sus_apis:
            api_names = [a["behavior"] for a in sus_apis]
            critical = {"Dynamic Code Loading", "Shell Execution", "SMS Sending"}
            weak = {"Reflection", "Installed Apps Enum"}      # common, kamzor signal
            for a in sus_apis:
                b = a["behavior"]
                if b in critical:
                    score += 25                              # genuinely dangerous
                elif b in weak:
                    score += 3                               # common, weak signal
                else:
                    score += 10                              # beech wala
            reasons.append(f"Suspicious API calls: {', '.join(api_names)}")
            indicators.append({
                "type": "api",
                "severity": "HIGH",
                "detail": ', '.join(api_names)
            })

# ── Name vs package mismatch ──
        name_flags = apk_results.get("name_mismatch", {}).get("red_flags", [])
        if name_flags:
            score += 10
            reasons.append(f"Identity mismatch: {', '.join(name_flags)}")
            indicators.append({
                "type": "identity",
                "severity": "MEDIUM",
                "detail": ', '.join(name_flags)
            })

         # ── Office macros ──
    if office_results and "error" not in office_results and office_results.get("has_macros"):
        auto = office_results.get("auto_exec", [])
        susp = office_results.get("suspicious", [])
        if auto:
            score += 25
            reasons.append(f"Auto-executing macro(s): {', '.join(a['keyword'] for a in auto)}")
            indicators.append({"type": "macro", "severity": "CRITICAL", "detail": "Auto-exec macro present"})
        if susp:
            score += min(len(susp) * 8, 30)
            reasons.append(f"Suspicious macro calls: {', '.join(s['keyword'] for s in susp)}")
            indicators.append({"type": "macro", "severity": "HIGH", "detail": f"{len(susp)} suspicious macro calls"})

# ── PCAP / network capture ──
    if pcap_results and "error" not in pcap_results:
        ports = pcap_results.get("suspicious_ports", [])
        if ports:
            score += 20
            reasons.append(f"Suspicious network ports: {', '.join(str(p) for p in ports)}")
            indicators.append({"type": "network", "severity": "HIGH", "detail": f"Ports: {', '.join(str(p) for p in ports)}"})

# ── IP reputation (did the file contact a known-bad IP?) ──
    if ip_intel and "results" in ip_intel:
        # Google IPs (64.233.x, 142.250.x, ...) cause false positives in threat-intel — skip
        mal = [r["ip"] for r in ip_intel["results"] if r.get("overall_verdict") == "MALICIOUS" and not _is_google_ip(r["ip"])]
        susp = [r["ip"] for r in ip_intel["results"] if r.get("overall_verdict") == "SUSPICIOUS" and not _is_google_ip(r["ip"])]
        if mal:
            score += 40
            if not vt_strong_clean:          # VT-clean → don't let shared-infra IP noise force MALICIOUS
                hard_evidence = True
            reasons.append(f"Contacts known-malicious IP(s): {', '.join(mal)}")
            indicators.append({"type": "network", "severity": "CRITICAL", "detail": f"Malicious IPs: {', '.join(mal)}"})
        if susp:
            score += 15
            reasons.append(f"Contacts suspicious IP(s): {', '.join(susp)}")
            indicators.append({"type": "network", "severity": "HIGH", "detail": f"Suspicious IPs: {', '.join(susp)}"})

   # ── Suspicious URLs (by structure, not by domain name) ──
    urls = strings.get("urls", [])
    shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 'is.gd', 'rebrand.ly', 't.cn']
    suspicious_urls = []
    for u in urls:
        if _is_known_good_host(u):                                          # googleapis/gstatic/firebase — skip
            continue
        ip_match = re.search(r'https?://(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', u)
        if ip_match and not _is_google_ip(ip_match.group(1)):               # raw-IP URL (not a Google IP)
            suspicious_urls.append(u)
        elif any(s in u for s in shorteners):                               # shortener
            suspicious_urls.append(u)
    if suspicious_urls:
        score += 10
        reasons.append(f"Structurally suspicious URLs: {', '.join(suspicious_urls[:3])}")
        indicators.append({"type": "network", "severity": "MEDIUM", "detail": f"{len(suspicious_urls)} suspicious URLs"})

# ── Fuzzy hash similarity (known malware variant?) ──
    if fuzzy_results and "error" not in fuzzy_results and fuzzy_results.get("is_variant"):
        bm = fuzzy_results.get("best_match", {})
        score += 40
        hard_evidence = True
        fuzzy_variant_hit = True
        reasons.append(f"Similar to known malware: {bm.get('name')} ({bm.get('similarity')}% match)")
        indicators.append({"type": "similarity", "severity": "CRITICAL", "detail": f"{bm.get('similarity')}% similar to {bm.get('name')}"})

# ── MalwareBazaar (confirmed known malware?) ──
    if malwarebazaar and malwarebazaar.get("found"):
        sig = malwarebazaar.get("signature") or "known malware"
        score += 45
        hard_evidence = True
        mb_hit = True
        reasons.append(f"Found in MalwareBazaar — confirmed malware: {sig}")
        indicators.append({"type": "intel", "severity": "CRITICAL", "detail": f"MalwareBazaar: {sig}"})

# ── URLhaus (known malware-distribution host?) — known-good hosts skip ──
    if urlhaus and urlhaus.get("found_malicious"):
        bad_hosts = [h["host"] for h in urlhaus.get("malicious_hosts", [])
                     if not _is_known_good_host(h["host"])]
        if bad_hosts:
            score += 40
            hard_evidence = True
            reasons.append(f"Contacts known malware-distribution host(s): {', '.join(bad_hosts)}")
            indicators.append({"type": "intel", "severity": "CRITICAL", "detail": f"URLhaus: {', '.join(bad_hosts)}"})

# ── VirusTotal consensus (sabse bharosemand signal) ──
    if virustotal and virustotal.get("found") and "stats" in virustotal:
        st = virustotal["stats"]
        total = st.get("total_engines", 0)
        malc = st.get("malicious", 0)
        susc = st.get("suspicious", 0)

        if malc >= 10:
            score += 40
            hard_evidence = True
            vt_strong_malicious = True
            reasons.append(f"VirusTotal: {malc}/{total} engines flag this as malicious")
            indicators.append({"type": "intel", "severity": "CRITICAL", "detail": f"VT: {malc}/{total} malicious"})
        elif malc >= 3:
            score += 25
            reasons.append(f"VirusTotal: {malc}/{total} engines flag this as malicious")
            indicators.append({"type": "intel", "severity": "HIGH", "detail": f"VT: {malc}/{total} malicious"})
        elif malc >= 1:
            score += 10
            reasons.append(f"VirusTotal: {malc}/{total} engines flag this file")
            indicators.append({"type": "intel", "severity": "MEDIUM", "detail": f"VT: {malc}/{total} malicious"})
        elif total >= 40 and malc == 0 and susc <= 1 and not hard_evidence:
            # 40+ engines, all clean, no hard evidence → STRONG trust signal
            score = min(score, 15)
            reasons.append(f"VirusTotal trust: 0/{total} engines flagged — heuristic score capped (clean consensus)")
            indicators.append({"type": "intel", "severity": "INFO", "detail": f"VT clean consensus: 0/{total} — trust cap applied"})

    # ── Definitive-malware score floors ────────────
    # A single decisive signal must land in MALICIOUS territory on its own.
    if vt_strong_malicious or mb_hit:
        score = max(score, 90)          # VT consensus or exact MalwareBazaar match → MALICIOUS
    elif fuzzy_variant_hit:
        score = max(score, 80)          # high-similarity variant of known malware → MALICIOUS

    # ── Final Score ────────────────────────────────
    score = min(score, 100)

    if score >= 75:
        verdict = "MALICIOUS"
        color = "RED"
        conclusion = f"This file is highly likely to be malicious. {len(reasons)} threat indicators were detected including: {reasons[0] if reasons else 'multiple suspicious patterns'}. Immediate action recommended — do not install or execute this file."
    elif score >= 50:
        verdict = "SUSPICIOUS"
        color = "ORANGE"
        conclusion = f"This file shows suspicious behavior. {len(reasons)} indicators found. Further analysis recommended before use."
    elif score >= 25:
        verdict = "POTENTIALLY UNWANTED"
        color = "YELLOW"
        conclusion = f"This file has some suspicious traits but may not be malicious. Exercise caution."
    else:
        verdict = "CLEAN"
        color = "GREEN"
        conclusion = "No significant threats detected. File appears to be clean."

    return {
        "final_score": score,
        "verdict": verdict,
        "color": color,
        "conclusion": conclusion,
        "total_indicators": len(indicators),
        "reasons": reasons,
        "indicators": indicators
    }
