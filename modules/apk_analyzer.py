from androguard.misc import AnalyzeAPK
try:
    from androguard.core.apk import APK            # androguard 4.x
except ImportError:                                # pragma: no cover
    from androguard.core.bytecodes.apk import APK  # androguard 3.x
import os
import re
import base64

from loguru import logger
logger.disable("androguard")

# In low-memory environments (e.g. a 512MB free cloud instance), skip androguard's
# heavy full-DEX Analysis and do lightweight manifest-level APK analysis only.
# Set LOW_MEMORY=1 in the environment to enable it. Locally it stays off (full analysis).
LOW_MEMORY = os.getenv("LOW_MEMORY", "").lower() in ("1", "true", "yes")

SUSPICIOUS_APIS = {
    # name: (class descriptor, method, what it does)
    "SMS Sending":          ("Landroid/telephony/SmsManager;", "sendTextMessage", "Sends SMS silently (OTP theft / premium fraud)"),
    "IMEI Theft":           ("Landroid/telephony/TelephonyManager;", "getDeviceId", "Reads the device's unique IMEI"),
    "SIM Serial Theft":     ("Landroid/telephony/TelephonyManager;", "getSimSerialNumber", "Reads the SIM serial number"),
    "Subscriber Theft":     ("Landroid/telephony/TelephonyManager;", "getSubscriberId", "Reads the IMSI / subscriber ID"),
    "Dynamic Code Loading": ("Ldalvik/system/DexClassLoader;", "<init>", "Loads hidden code at runtime (dropper)"),
    "Shell Execution":      ("Ljava/lang/Runtime;", "exec", "Runs system/shell commands"),
    "Reflection":           ("Ljava/lang/reflect/Method;", "invoke", "Hides calls via reflection (evasion)"),
    "Installed Apps Enum":  ("Landroid/content/pm/PackageManager;", "getInstalledPackages", "Enumerates installed apps (target selection)"),
    "Audio Recording":      ("Landroid/media/MediaRecorder;", "start", "Records audio (spying)"),
}


def detect_suspicious_apis(dx):
    found = []
    for name, (cls, method, desc) in SUSPICIOUS_APIS.items():
        matches = list(dx.find_methods(classname=cls, methodname=method))
        if matches:
            found.append({"behavior": name, "api": method, "description": desc})
    return {
        "total_found": len(found),
        "apis": found,
    }

def is_gibberish(segment):
    # Decides whether a package segment is "readable" or random junk.
    # Idea: real words contain vowels (a,e,i,o,u); "asdfwerwa" has very few.
    if len(segment) < 5:
        return False                      # short names (com, io) are normal, skip
    vowels = sum(1 for c in segment.lower() if c in "aeiou")
    ratio = vowels / len(segment)         # percentage of letters that are vowels
    return ratio < 0.15                   # under 15% vowels = gibberish

KNOWN_LIBRARIES = (
    "androidx", "android", "com.google", "com.android",
    "kotlin", "kotlinx", "org.jetbrains", "dagger",
    "com.squareup", "io.reactivex", "org.apache", "javax", "java",
)

def detect_repackaging(package_name, activities, services, receivers):
    # The app's own "family name" — the first 2 segments, e.g. com.github
    app_base = ".".join(package_name.split(".")[:2])

    components = list(activities) + list(services) + list(receivers)
    foreign_packages = set()      # components from a different package family
    gibberish_packages = set()    # random/junk names

    for comp in components:
        parts = comp.split(".")
        base = ".".join(parts[:2])        # this component's family name
        if base != app_base and not base.startswith(KNOWN_LIBRARIES):              # <-- KEY: family name doesn't match?
            foreign_packages.add(base)                                             # then it's an injected foreign package
        for seg in parts[:-1]:            # the last part is the class name, skip it
            if is_gibberish(seg):
                gibberish_packages.add(seg)

    flags = []
    if foreign_packages:
        flags.append(f"Components from a different package family: {', '.join(foreign_packages)}")
    if gibberish_packages:
        flags.append(f"Random/obfuscated package names: {', '.join(gibberish_packages)}")

    return {
        "app_base_package": app_base,
        "foreign_packages": list(foreign_packages),
        "gibberish_packages": list(gibberish_packages),
        "red_flags": flags,
        "is_repackaged": len(flags) > 0
    }

COMMON_PKG_WORDS = {"com", "org", "io", "net", "app", "apps",
                    "android", "github", "gitlab", "mobile", "co", "free"}

def detect_name_mismatch(app_name, package_name):
    if not app_name or not package_name:
        return {"mismatch": False, "red_flags": []}

    name_words = set(re.findall(r"[a-z]+", app_name.lower()))
    pkg_tokens = set(package_name.lower().split(".")) - COMMON_PKG_WORDS

    overlap = False
    for w in name_words:
        if len(w) < 3:
            continue
        for t in pkg_tokens:
            if w in t:                 # is a word from the name inside a package token?
                overlap = True

    flags = []
    if name_words and not overlap:
        flags.append(f"App name '{app_name}' does not match package '{package_name}'")

    return {
        "name_matches_package": overlap,
        "red_flags": flags,
        "mismatch": len(flags) > 0,
    }

PERMISSION_MITRE = {
    "android.permission.SEND_SMS":             ("T1582", "SMS Control", "Impact"),
    "android.permission.RECEIVE_SMS":          ("T1582", "SMS Control", "Impact"),
    "android.permission.READ_SMS":             ("T1636.004", "Protected User Data: SMS", "Collection"),
    "android.permission.READ_CONTACTS":        ("T1636.003", "Protected User Data: Contacts", "Collection"),
    "android.permission.RECORD_AUDIO":         ("T1429", "Audio Capture", "Collection"),
    "android.permission.CAMERA":               ("T1512", "Video Capture", "Collection"),
    "android.permission.ACCESS_FINE_LOCATION": ("T1430", "Location Tracking", "Collection"),
    "android.permission.ACCESS_COARSE_LOCATION":("T1430", "Location Tracking", "Collection"),
    "android.permission.READ_PHONE_STATE":     ("T1426", "System Information Discovery", "Discovery"),
    "android.permission.REQUEST_INSTALL_PACKAGES":("T1407", "Download New Code at Runtime", "Defense Evasion"),
    "android.permission.RECEIVE_BOOT_COMPLETED":("T1624.001", "Broadcast Receivers (Persistence)", "Persistence"),
    "android.permission.INTERNET":             ("T1437", "Application Layer Protocol (C2)", "Command & Control"),
}

API_MITRE = {
    "SMS Sending":          ("T1582", "SMS Control", "Impact"),
    "IMEI Theft":           ("T1426", "System Information Discovery", "Discovery"),
    "SIM Serial Theft":     ("T1426", "System Information Discovery", "Discovery"),
    "Subscriber Theft":     ("T1426", "System Information Discovery", "Discovery"),
    "Dynamic Code Loading": ("T1407", "Download New Code at Runtime", "Defense Evasion"),
    "Shell Execution":      ("T1623", "Command and Scripting Interpreter", "Execution"),
    "Reflection":           ("T1406", "Obfuscated Files or Information", "Defense Evasion"),
    "Installed Apps Enum":  ("T1418", "Software Discovery", "Discovery"),
    "Audio Recording":      ("T1429", "Audio Capture", "Collection"),
}


def map_to_mitre(permissions, suspicious_apis):
    techniques = {}   # dedupe by technique id
    for perm in permissions:
        if perm in PERMISSION_MITRE:
            tid, name, tactic = PERMISSION_MITRE[perm]
            techniques[tid] = {"id": tid, "name": name, "tactic": tactic, "evidence": perm}
    for api in suspicious_apis:
        if api["behavior"] in API_MITRE:
            tid, name, tactic = API_MITRE[api["behavior"]]
            techniques[tid] = {"id": tid, "name": name, "tactic": tactic, "evidence": "API: " + api["api"]}
    return {
        "total_techniques": len(techniques),
        "techniques": list(techniques.values()),
    }


def _is_public_ip(ip):
    try:
        nums = [int(p) for p in ip.split(".")]
    except ValueError:
        return False
    if len(nums) != 4 or any(n > 255 for n in nums):
        return False
    if nums[0] in (0, 10, 127): return False          # reserved/private/localhost
    if nums[0] == 192 and nums[1] == 168: return False  # private
    if nums[0] == 172 and 16 <= nums[1] <= 31: return False  # private
    if nums[0] == 169 and nums[1] == 254: return False  # link-local
    if nums[0] >= 224: return False                    # multicast/reserved
    return True


def extract_deep_iocs(dx):
    ip_re = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_re = re.compile(r'https?://[^\s\'"<>]{4,}')
    b64_re = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

    ips, urls = set(), set()
    b64_hits = []
    decode_attempts = 0

    for s_obj in dx.get_strings():
        s = str(s_obj.get_value())
        for ip in ip_re.findall(s):
            if _is_public_ip(ip):
                ips.add(ip)
        for u in url_re.findall(s):
            urls.add(u)
        # look for C2 hidden in base64 (limited, to avoid slowing down)
        if decode_attempts < 3000:
            for b in b64_re.findall(s):
                decode_attempts += 1
                if decode_attempts >= 3000:
                    break
                try:
                    dec = base64.b64decode(b + "=" * (-len(b) % 4)).decode("utf-8", errors="ignore")
                except Exception:
                    continue
                pub = [ip for ip in ip_re.findall(dec) if _is_public_ip(ip)]
                durls = url_re.findall(dec)
                if pub or durls:
                    ips.update(pub)
                    urls.update(durls)
                    b64_hits.append({"decoded": dec[:120]})

    return {"ips": sorted(ips), "urls": sorted(urls), "base64_decoded_iocs": b64_hits[:20]}


# ── Low-memory helpers ───────────────────────────────
# These read the raw DEX bytes and run regex directly, instead of building
# androguard's heavy cross-reference Analysis (which is what blows past 512MB).
# They recover the most important signal — URLs / IPs / suspicious APIs — cheaply.
def _all_dex_bytes(a):
    try:
        return b"".join(a.get_all_dex())
    except Exception:
        return b""


def _lightweight_iocs_from_apk(a):
    """Extract URLs/IPs by regex over the raw DEX bytes (no heavy Analysis object)."""
    blob = _all_dex_bytes(a)
    ip_re  = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    url_re = re.compile(rb'https?://[^\x00-\x1f\s\'"<>]{4,}')
    urls = {u.decode("latin-1", errors="ignore") for u in url_re.findall(blob)}
    ips = set()
    for m in ip_re.findall(blob):
        ip = m.decode("latin-1", errors="ignore")
        if _is_public_ip(ip):
            ips.add(ip)
    return {"ips": sorted(ips), "urls": sorted(urls)[:300], "base64_decoded_iocs": []}


def _lightweight_apis_from_apk(a):
    """Flag a suspicious API when both its class descriptor and method name appear
    in the DEX bytes — a cheap heuristic that skips method-level cross-referencing."""
    blob = _all_dex_bytes(a)
    found = []
    for name, (cls, method, desc) in SUSPICIOUS_APIS.items():
        if cls.encode() in blob and method.encode() in blob:
            found.append({"behavior": name, "api": method, "description": desc})
    return {"total_found": len(found), "apis": found}


def analyze_apk(file_path):
    try:
        if LOW_MEMORY:
            # Lightweight: parse the manifest + scan raw DEX bytes (no heavy Analysis object)
            a = APK(file_path)
            dx = None
            suspicious_apis = _lightweight_apis_from_apk(a)
        else:
            a, d, dx = AnalyzeAPK(file_path)
            suspicious_apis = detect_suspicious_apis(dx)

        # Basic Info
        package_name = a.get_package()
        app_name = a.get_app_name()
        version_name = a.get_androidversion_name()
        version_code = a.get_androidversion_code()

        # Permissions
        permissions = a.get_permissions()

        # Dangerous permissions list
        dangerous_perms = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.READ_CALL_LOG",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.ACCESS_COARSE_LOCATION",
            "android.permission.READ_PHONE_STATE",
            "android.permission.PROCESS_OUTGOING_CALLS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.WAKE_LOCK",
            "android.permission.GET_ACCOUNTS",
            "android.permission.BIND_VPN_SERVICE",
        ]

        found_dangerous = [p for p in permissions if p in dangerous_perms]

        # Activities, Services, Receivers
        activities = a.get_activities()
        services = a.get_services()
        receivers = a.get_receivers()
        repackaging = detect_repackaging(package_name, activities, services, receivers)
        name_mismatch = detect_name_mismatch(app_name, package_name)
        mitre = map_to_mitre(permissions, suspicious_apis["apis"])
        uses_vpn = "android.permission.BIND_VPN_SERVICE" in permissions

  # Certificate Info — Forensics
        certs = a.get_certificates()
        cert_info = []
        cert_red_flags = []
        for cert in certs:
            subject = cert.subject.native
            issuer = cert.issuer.native

            self_signed = (subject == issuer)
            cn = subject.get("common_name", "Unknown")
            org = subject.get("organization_name", "Unknown")
            hash_algo = cert.hash_algo
            weak_hash = hash_algo in ("md5", "sha1")
            valid_from = cert.not_valid_before
            valid_to = cert.not_valid_after
            validity_years = round((valid_to - valid_from).days / 365, 1)

            # ── Red flags ──
            if self_signed:
                cert_red_flags.append("Self-signed certificate (subject == issuer)")
            if weak_hash:
                cert_red_flags.append(f"Weak hash algorithm: {hash_algo}")
            if len(str(cn)) <= 4 or str(cn).lower() in ("android", "test", "debug", "dpt"):
                cert_red_flags.append(f"Suspicious / placeholder signer name: '{cn}'")
            if validity_years > 25:
                cert_red_flags.append(f"Unusually long validity: {validity_years} years")

            cert_info.append({
                "common_name": cn,
                "organization": org,
                "self_signed": self_signed,
                "valid_from": str(valid_from),
                "valid_to": str(valid_to),
                "validity_years": validity_years,
                "signature_algo": cert.signature_algo,
                "hash_algo": hash_algo,
                "weak_hash": weak_hash,
            })

# Deep C2/IP extraction — full Analysis locally, lightweight DEX-regex in low-memory mode
        if dx is not None:
            deep_iocs = extract_deep_iocs(dx)
        else:
            deep_iocs = _lightweight_iocs_from_apk(a)
        urls = deep_iocs["urls"]
        ips = deep_iocs["ips"]

        return {
            "app_info": {
                "package_name": package_name,
                "app_name": app_name,
                "version_name": version_name,
                "version_code": version_code,
            },
            "permissions": {
                "all_permissions": list(permissions),
                "dangerous_permissions": found_dangerous,
                "total_permissions": len(permissions),
                "total_dangerous": len(found_dangerous),
                "uses_vpn": uses_vpn,
            },
            "components": {
                "activities": list(activities),
                "services": list(services),
                "receivers": list(receivers)
            },

            "repackaging": repackaging,

            "name_mismatch": name_mismatch,

            "mitre_attack": mitre,

            "network": {
                "urls_found": urls,
                "ips_found": ips,
                "base64_decoded_iocs": deep_iocs["base64_decoded_iocs"],
            },
            
            "suspicious_apis": suspicious_apis,

            "certificate": {
                "certificates_found": len(certs),
                "details": cert_info,
                "red_flags": cert_red_flags,
            }
        }

    except Exception as e:
        return {"error": str(e)}