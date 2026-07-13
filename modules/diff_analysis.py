"""diff_analysis.py — compare two scans (what was added / what was removed)."""


def _extract(scan):
    apk = scan.get("apk_analysis", {}) or {}
    ip_res = (scan.get("ip_intelligence", {}) or {}).get("results", [])
    return {
        "perms": set(apk.get("permissions", {}).get("dangerous_permissions", [])),
        "ips":   set(r.get("ip") for r in ip_res if r.get("ip")),
        "urls":  set((scan.get("strings", {}) or {}).get("urls", [])),
        "apis":  set(a.get("behavior") for a in apk.get("suspicious_apis", {}).get("apis", [])),
        "yara":  set(m.get("rule") for m in (scan.get("yara_scan", {}) or {}).get("matches", [])),
    }


def diff_scans(old, new):
    o, n = _extract(old), _extract(new)
    out = {}
    for k in ("perms", "ips", "urls", "apis", "yara"):
        out[k] = {"added": sorted(x for x in (n[k] - o[k]) if x),
                  "removed": sorted(x for x in (o[k] - n[k]) if x)}
    out["files"] = {"old": old.get("filename"), "new": new.get("filename")}
    out["score_change"] = (new.get("risk_assessment", {}) or {}).get("final_score", 0) - \
                          (old.get("risk_assessment", {}) or {}).get("final_score", 0)
    return out