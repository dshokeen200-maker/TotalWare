"""
sandbox_router.py — Universal Sandbox Router
============================================
A single entry point that routes ANY file to the right sandbox:

    .apk / .xapk                -> local Android emulator (modules/dynamic_sandbox)
    .exe .dll .sys .scr         -> VT cloud sandbox behaviour (Windows)
    .elf / Linux bins           -> VT cloud sandbox behaviour (Linux)
    .pdf .doc(x) .xls(x) .ppt   -> VT cloud sandbox behaviour
    .js .vbs .ps1 .hta .bat .sh -> VT cloud sandbox behaviour
    (anything else)             -> VT cloud sandbox behaviour

Output has the SAME shape for every type: { engine, dynamic:{ips,domains,urls,...} }
so the downstream filter + threat_intel + risk pipeline works uniformly.

Note: standing up a local Windows/Linux VM is impractical (a separate project), so for
non-APK files we reuse VT's ready-made sandboxes (zero new infrastructure).
"""

import os

APK_EXT = (".apk", ".xapk", ".apks")

# Noise filter (sandbox_router level) — known-good IP prefixes
GOOD_IP_PREFIXES = (
    "10.", "127.", "169.254.", "192.168.", "172.16.", "224.", "239.", "255.", "0.",
    "142.250.", "142.251.", "172.217.", "172.253.", "173.194.",
    "216.239.", "192.178.", "74.125.", "216.58.", "108.177.",
    "64.233.", "8.8.8.", "8.8.4.", "34.104.", "35.190.", "35.191.",   # Google/GCP frontends + DNS
)
GOOD_HOST_SUFFIX = (
    "google.com", "gstatic.com", "googleapis.com", "android.com", "windows.com",
    "microsoft.com", "msftncsi.com", "windowsupdate.com", "crashlytics.com",
    "firebaseio.com", "firebasestorage.app", "app-measurement.com",
    "googleusercontent.com", "gvt1.com", "gvt2.com", "1e100.net",
    "google-analytics.com", "googletagmanager.com",
)


def _filter_iocs(ips, domains, urls):
    cand_ips   = [ip for ip in ips if not any(ip.startswith(p) for p in GOOD_IP_PREFIXES)]
    cand_hosts = [h for h in domains if not any(h.lower().endswith(s) for s in GOOD_HOST_SUFFIX)]
    return {
        "candidate_c2_ips":   sorted(set(cand_ips)),
        "candidate_hosts":    sorted(set(cand_hosts)),
        "candidate_urls":     sorted(set(urls)),
        "filtered_good_ips":  sorted(set(ip for ip in ips if ip not in cand_ips)),
    }


def route_sandbox(file_path, sha256=None, duration=45, run_local=True, package=None):
    """Route the file to the right sandbox by type, then filter IOCs and return."""
    ext = os.path.splitext(file_path)[1].lower()

    # ── APK -> local Android dynamic sandbox ──
    if ext in APK_EXT:
        if not run_local:
            return {"engine": "skipped", "message": "local run_local=False"}
        try:
            from modules.dynamic_sandbox import run_dynamic
            res = run_dynamic(apk_path=file_path, package=package, duration=duration)
            res["engine"] = "local-android-emulator"
            res["file_type"] = ext
        except Exception as e:
            res = {"engine": "local-android-emulator", "status": "error", "error": str(e)}

        # ── VT fallback/augment: if local finds no C2, pull from VT cloud sandbox + merge ──
        if sha256:
            try:
                from modules.vt_behavior import get_vt_behavior
                vt = get_vt_behavior(sha256)
                if vt.get("available"):
                    vt_iocs = _filter_iocs(vt.get("ips", []), vt.get("domains", []), vt.get("urls", []))
                    res["vt_behavior"] = {"available": True, "source": "VirusTotal cloud sandbox",
                                          "iocs": vt_iocs, "mitre": vt.get("mitre", [])}
                    # clear the local error/status — VT provided data, so the UI shouldn't short-circuit
                    res.pop("error", None)
                    res.pop("status", None)
                    loc = res.get("iocs", {}) or {}
                    merged_ips   = sorted(set((loc.get("candidate_c2_ips") or []) + vt_iocs["candidate_c2_ips"]))
                    merged_hosts = sorted(set((loc.get("candidate_hosts") or []) + vt_iocs["candidate_hosts"]))
                    res["merged_candidate_c2_ips"] = merged_ips
                    res["merged_candidate_hosts"]  = merged_hosts
                    # threat intel on merged set
                    if merged_ips:
                        try:
                            from modules.threat_intel import analyze_ips
                            res["threat_intel"] = analyze_ips(merged_ips)
                        except Exception:
                            pass

                    # For the map — geolocate the candidate C2 IPs (with their verdict)
                    try:
                        from modules.geolocation import geolocate_ips
                        vmap = {}
                        if res.get("threat_intel", {}).get("results"):
                            vmap = {r["ip"]: r.get("overall_verdict", "UNKNOWN")
                                    for r in res["threat_intel"]["results"]}
                        res["ip_geolocation"] = geolocate_ips(merged_ips, vmap)
                    except Exception as e:
                        res["geo_error"] = str(e)

                    # local was empty but VT provided data -> update the verdict
                    if not (loc.get("candidate_c2_ips")) and vt_iocs["candidate_c2_ips"]:
                        res["verdict"] = (f"Local sandbox was dormant; VT cloud sandbox found "
                                          f"{len(vt_iocs['candidate_c2_ips'])} candidate C2(s)")
                else:
                    res["vt_behavior"] = vt
            except Exception as e:
                res["vt_behavior_error"] = str(e)
        return res

    # ── Everything else -> VT cloud sandbox behaviour ──
    from modules.vt_behavior import get_vt_behavior
    if not sha256:
        return {"engine": "vt-cloud-sandbox", "status": "error",
                "error": "sha256 is required for non-APK files (computed in app.py)"}

    beh = get_vt_behavior(sha256)
    out = {"engine": "vt-cloud-sandbox", "file_type": ext or "unknown", "dynamic": beh}

    if beh.get("available"):
        out["iocs"] = _filter_iocs(beh.get("ips", []), beh.get("domains", []), beh.get("urls", []))
        # threat intel on candidate IPs
        try:
            from modules.threat_intel import analyze_ips
            cand = out["iocs"]["candidate_c2_ips"]
            if cand:
                out["threat_intel"] = analyze_ips(cand)
        except Exception as e:
            out["threat_intel_error"] = str(e)
        n = len(out["iocs"]["candidate_c2_ips"])
        out["verdict"] = f"{n} candidate C2 IP(s) (VT sandbox)" if n else "No clear C2 (VT sandbox)"
    else:
        out["verdict"] = "Dynamic behaviour unavailable — relying on static analysis (app.py)"
    return out


if __name__ == "__main__":
    import sys, json, hashlib
    if len(sys.argv) < 2:
        print("Usage: python -m modules.sandbox_router <file_path>")
        sys.exit(1)
    fp = sys.argv[1]
    sha = hashlib.sha256(open(fp, "rb").read()).hexdigest()
    print("SHA256:", sha)
    print(json.dumps(route_sandbox(fp, sha256=sha), indent=2, ensure_ascii=False))
