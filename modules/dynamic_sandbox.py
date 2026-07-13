"""
dynamic_sandbox.py — TotalWare Dynamic Sandbox Orchestrator (v1)
================================================================
AUTOMATICALLY detonates an APK in an emulator to extract live C2/traffic.
Automates the manual flow (frida-server -> install -> spawn -> inject -> stimulate -> capture)
into a single function.

Flow:
  1. ensure frida-server (root + start if stopped)
  2. install APK + get package name
  3. grant exemptions (battery/background) + dangerous perms
  4. spawn app + inject anti_detect.js   (spawn-gating fallback for headless apps)
  5. stimulate: monkey launch + system broadcasts (boot/SMS/unlock)
  6. collect [C2]/[URL]/[DROP] from Frida hooks
  7. (optional) analyze emulator -tcpdump pcap (reuses pcap_analyzer)
  8. noise filter (drop Google/Cloudflare/internal) -> candidate C2
  9. verify via threat intel (AbuseIPDB/OTX/Shodan)
 10. cleanup (uninstall)
 11. return verdict + IOCs

Standalone test:
    python -m modules.dynamic_sandbox  <path-to.apk | package.name>  [pcap_path]
"""

import os
import re
import sys
import time
import json
import subprocess

# ── Config ──
SDK         = os.environ.get("ANDROID_SDK", r"C:\Users\dshok\AppData\Local\Android\Sdk")
SCRIPT_PATH = os.path.join(os.path.dirname(__file__), "..", "sandbox", "anti_detect.js")
FRIDA_SERVER_PATH = "/data/local/tmp/frida-server"
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOST_RE = re.compile(r"https?://([^/\s:'\"]+)")

# Noise filter — these prefixes/hosts are "known good" (not C2)
GOOD_IP_PREFIXES = (
    "10.0.2.", "127.", "169.254.", "224.", "239.", "255.", "0.",
    # Google
    "142.250.", "142.251.", "172.217.", "172.253.", "173.194.",
    "216.239.", "192.178.", "74.125.", "216.58.", "108.177.",
)
GOOD_HOST_SUFFIX = (
    "google.com", "gstatic.com", "googleapis.com", "android.com",
    "crashlytics.com", "gvt1.com", "gvt2.com", "googleusercontent.com",
    "ggpht.com", "doubleclick.net",
)
# Cloudflare — C2 can hide behind it, so we mark it "suspicious" (not filtered out)
CLOUDFLARE_PREFIXES = ("172.67.", "104.21.", "104.16.", "104.17.", "104.18.", "104.19.")


class _R:
    """Dummy result when a command times out/fails — so it never crashes."""
    def __init__(self, out="", err="", rc=1):
        self.stdout, self.stderr, self.returncode = out, err, rc

def adb(*args, timeout=30):
    try:
        return subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return _R(err="timeout")
    except Exception as e:
        return _R(err=str(e))

def sh(cmd, timeout=12):
    """adb shell — short timeout, ignore on hang (am broadcast can block)."""
    return adb("shell", cmd, timeout=timeout)


# ──────────────────────────────────────────────────────────────
def ensure_frida_server():
    """Get root and start frida-server (skip if it's already running)."""
    adb("root"); time.sleep(1.5)
    running = sh("pgrep -f frida-server").stdout.strip()
    if not running:
        subprocess.Popen(["adb", "shell", FRIDA_SERVER_PATH],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
    return True


def install_apk(apk_path):
    """Install the APK and extract the new package name."""
    before = set(sh("pm list packages -3").stdout.split())
    res = adb("install", "-r", apk_path, timeout=240)
    after = set(sh("pm list packages -3").stdout.split())
    new = [p.replace("package:", "") for p in (after - before)]
    return new[0] if new else None, res.stdout.strip()


def grant_exemptions(pkg):
    """Remove background/battery restrictions + grant declared dangerous perms."""
    sh(f"dumpsys deviceidle whitelist +{pkg}")
    sh(f"cmd appops set {pkg} RUN_ANY_IN_BACKGROUND allow")
    info = sh(f"dumpsys package {pkg}").stdout
    granted = 0
    for perm in sorted(set(re.findall(r"(android\.permission\.[A-Z_]+)", info))):
        r = adb("shell", "pm", "grant", pkg, perm)
        if r.returncode == 0:
            granted += 1
    return granted


# ── Frida message collector ──
class Collector:
    def __init__(self):
        self.c2, self.urls, self.drops, self.logs, self.runs = [], [], [], [], []

    def on_message(self, message, data):
        if message.get("type") == "log":
            line = message.get("payload", "") or ""
            self.logs.append(line)
            if   line.startswith("[C2]"):  self.c2.append(line)
            elif line.startswith("[URL]"): self.urls.append(line)
            elif line.startswith("[DROP]"):self.drops.append(line)
            elif line.startswith("[run]"): self.runs.append(line)
        elif message.get("type") == "error":
            self.logs.append("JS-ERROR: " + str(message.get("description", "")))


def _load_script(device, session, collector):
    import frida  # noqa
    with open(SCRIPT_PATH, "r", encoding="utf-8") as f:
        code = f.read()
    script = session.create_script(code)
    script.on("message", collector.on_message)
    script.load()
    return script


def detonate(pkg, duration=45):
    """Spawn + inject + stimulate the app, and collect C2 from Frida."""
    import frida
    device = frida.get_usb_device(timeout=15)
    col = Collector()
    session = None

    # 1. Normal spawn (launcher wali apps)
    try:
        pid = device.spawn([pkg])
        session = device.attach(pid)
        _load_script(device, session, col)
        device.resume(pid)
        print("[+] spawned + injected:", pkg)
    except Exception as e:
        # 2. Headless fallback — spawn-gating + broadcast se jagao
        print(f"[i] normal spawn fail ({e}); headless mode")
        try:
            device.enable_spawn_gating()
        except Exception:
            pass
        sh(f"am broadcast -a android.intent.action.BOOT_COMPLETED -p {pkg}")
        for _ in range(15):
            for p in device.enumerate_processes():
                if pkg in (p.name or ""):
                    try:
                        session = device.attach(p.pid)
                        _load_script(device, session, col)
                        print("[+] headless attach:", pkg, p.pid)
                    except Exception:
                        pass
                    break
            if session:
                break
            time.sleep(0.6)

    # 3. Stimulate — GENERIC, comprehensive (poke every trigger-based malware)
    #    Not sample-specific — tries all common triggers at once.
    sh(f"monkey -p {pkg} -c android.intent.category.LAUNCHER 8", timeout=15)   # launch + random taps

    # (a) Fake SMS — wakes up SMS-stealer/OTP-theft malware (from the emulator console = a REAL SMS event)
    adb("emu", "sms", "send", "+919876543210", "Your bank OTP is 482910. Do not share.", timeout=8)
    adb("emu", "sms", "send", "+910000000000", "ACCOUNT ALERT: verify now", timeout=8)

    # (b) Common broadcasts (protected ones may be denied, but best-effort)
    for action in ("android.intent.action.BOOT_COMPLETED",
                   "android.provider.Telephony.SMS_RECEIVED",
                   "android.provider.Telephony.SMS_DELIVER",
                   "android.intent.action.USER_PRESENT",
                   "android.intent.action.SCREEN_ON",
                   "android.net.conn.CONNECTIVITY_CHANGE",
                   "android.intent.action.PACKAGE_ADDED",
                   "android.intent.action.NEW_OUTGOING_CALL"):
        sh(f"am broadcast -a {action} -p {pkg}", timeout=8)

    # (c) If a service/receiver is exported, start it directly (best-effort)
    sh(f"am start-foreground-service {pkg} 2>/dev/null || am startservice {pkg}", timeout=8)

    # (d) A few more monkey taps in between (for UI-driven behaviour)
    for _ in range(3):
        sh(f"monkey -p {pkg} 15", timeout=12)
        time.sleep(max(2, duration // 4))

    time.sleep(max(5, duration // 3))
    try:
        if session: session.detach()
    except Exception:
        pass
    return col


# ── Noise filter + IOC extraction ──
def _is_good_ip(ip):
    return any(ip.startswith(p) for p in GOOD_IP_PREFIXES)

def _is_good_host(host):
    host = host.lower()
    return any(host.endswith(s) for s in GOOD_HOST_SUFFIX)

def extract_iocs(collector, pcap_result=None):
    raw_ips, raw_hosts = set(), set()

    # Frida lines se
    for line in collector.c2 + collector.urls:
        for ip in IP_RE.findall(line): raw_ips.add(ip)
        for h in HOST_RE.findall(line): raw_hosts.add(h)
        # "host:port" form
        m = re.search(r"createSocket:\s*([^:\s]+):", line)
        if m: raw_hosts.add(m.group(1))
        m = re.search(r"getByName:\s*(\S+)", line)
        if m and not IP_RE.match(m.group(1)): raw_hosts.add(m.group(1))

    # from pcap (if provided)
    if pcap_result and "error" not in pcap_result:
        raw_ips.update(pcap_result.get("destination_ips", []))
        raw_hosts.update(pcap_result.get("http_hosts", []))
        raw_hosts.update(pcap_result.get("dns_queries", []))

    candidate_ips, cloudflare_ips, good_ips = [], [], []
    for ip in sorted(raw_ips):
        if _is_good_ip(ip):        good_ips.append(ip)
        elif any(ip.startswith(p) for p in CLOUDFLARE_PREFIXES): cloudflare_ips.append(ip)
        else:                      candidate_ips.append(ip)

    candidate_hosts = sorted(h for h in raw_hosts
                             if not _is_good_host(h) and not h.endswith(".local"))

    return {
        "candidate_c2_ips":  candidate_ips,     # ← run threat-intel on these
        "cloudflare_ips":    cloudflare_ips,    # C2 can hide behind these
        "filtered_good_ips": good_ips,          # noise (Google/internal)
        "candidate_hosts":   candidate_hosts,
    }


# ── Main entry ──
def run_dynamic(apk_path=None, package=None, pcap_path=None, duration=45, cleanup=True):
    result = {"status": "ok", "steps": []}
    try:
        import frida  # noqa
    except ImportError:
        return {"status": "error", "error": "Install the frida Python module: pip install frida"}

    # frida-server
    ensure_frida_server(); result["steps"].append("frida-server ready")

    # install (if an apk path was given). Note: if a package was already passed, keep it
    # (the install diff can be empty if the app is already installed).
    if apk_path:
        detected, msg = install_apk(apk_path)
        if detected:
            package = detected
        result["steps"].append(f"installed: {package} ({msg})")
    if not package:
        return {"status": "error", "error": "package name not found"}
    result["package"] = package

    # exemptions + perms
    granted = grant_exemptions(package)
    result["steps"].append(f"granted {granted} perms + bg exemption")

    # detonate
    col = detonate(package, duration=duration)
    result["frida_c2_lines"]   = col.c2
    result["frida_url_lines"]  = col.urls
    result["frida_drop_lines"] = col.drops
    result["fgs_bypass_lines"] = col.runs

    # pcap (optional — emulator -tcpdump file)
    pcap_result = None
    if pcap_path and os.path.exists(pcap_path):
        try:
            from modules.pcap_analyzer import analyze_pcap
            pcap_result = analyze_pcap(pcap_path)
            result["pcap"] = pcap_result
        except Exception as e:
            result["pcap_error"] = str(e)

    # IOC extract + filter
    iocs = extract_iocs(col, pcap_result)
    result["iocs"] = iocs

    # threat intel on candidates
    try:
        from modules.threat_intel import analyze_ips
        check = iocs["candidate_c2_ips"] + iocs["cloudflare_ips"]
        if check:
            result["threat_intel"] = analyze_ips(check)
    except Exception as e:
        result["threat_intel_error"] = str(e)

    # cleanup
    if cleanup:
        adb("uninstall", package)
        result["steps"].append("uninstalled (cleanup)")

    # verdict
    n = len(iocs["candidate_c2_ips"])
    result["verdict"] = (
        f"{n} candidate C2 IP(s) found" if n else
        ("Cloudflare-fronted endpoints found (verify)" if iocs["cloudflare_ips"] else
         "No clear C2 found in this run (app dormant or C2 dead)")
    )
    return result


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m modules.dynamic_sandbox <apk_path|package> [pcap_path]")
        sys.exit(1)
    target = sys.argv[1]
    pcap = sys.argv[2] if len(sys.argv) > 2 else None
    if target.lower().endswith(".apk"):
        out = run_dynamic(apk_path=target, pcap_path=pcap)
    else:
        out = run_dynamic(package=target, pcap_path=pcap)
    print(json.dumps(out, indent=2, ensure_ascii=False))
