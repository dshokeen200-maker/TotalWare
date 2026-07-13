"""
test_risk_engine.py — regression tests for the risk scoring engine.

Run from the project root:
    pip install pytest
    pytest test_risk_engine.py -v

These lock in the false-positive tuning: legitimate apps must come back LOW/CLEAN,
while real malware must stay HIGH/MALICIOUS. If a future change breaks this, a test fails.
"""

from modules.risk_engine import calculate_risk


def _scan(**overrides):
    """Build calculate_risk() arguments with sensible clean defaults, overridable per test."""
    args = dict(
        hashes={},
        strings={"suspicious_keywords": [], "urls": [], "ips": []},
        entropy={"score": 5.0},
        yara_results={"matches": []},
        apk_results=None,
        office_results=None,
        pcap_results=None,
        ip_intel={"results": []},
        fuzzy_results={},
        malwarebazaar={"found": False},
        urlhaus={"found_malicious": False},
        virustotal={"found": True, "stats": {"malicious": 0, "suspicious": 0,
                                             "harmless": 70, "undetected": 5, "total_engines": 75}},
    )
    args.update(overrides)
    return calculate_risk(**args)


# ─────────────────────────── CLEAN cases (false-positive guards) ───────────────────────────

def test_clean_flutter_apk_is_low():
    """Awaaz-style legit Flutter app: VT 0/75, Google/Flutter packages, no real threat."""
    r = _scan(
        strings={"suspicious_keywords": ["base64", "payload", "chmod"],
                 "urls": ["https://firebasestorage.googleapis.com/v0"], "ips": []},
        entropy={"score": 6.4},
        yara_results={"matches": [
            {"rule": "Android_Malware_Indicators", "severity": "MEDIUM", "description": "x"},
            {"rule": "Suspicious_Network_Activity", "severity": "LOW", "description": "x"},
        ]},
        apk_results={
            "permissions": {"dangerous_permissions": ["INTERNET", "ACCESS_NETWORK_STATE", "WAKE_LOCK", "RECORD_AUDIO"]},
            "app_info": {"package_name": "com.awaaz.app", "app_name": "Awaaz"},
            "components": {"receivers": []},
            "repackaging": {"foreign_packages": ["dev.fluttercommunity", "com.pairip", "io.flutter"], "gibberish_packages": []},
            "suspicious_apis": {"apis": [{"behavior": "Reflection"}, {"behavior": "Audio Recording"}]},
            "name_mismatch": {"red_flags": []},
        },
    )
    assert r["verdict"] == "CLEAN", r["reasons"]
    assert r["final_score"] <= 25


def test_clean_pdf_is_low():
    """A clean PDF from an official site (VT 0/72)."""
    r = _scan(entropy={"score": 7.2},
              virustotal={"found": True, "stats": {"malicious": 0, "suspicious": 0,
                                                   "harmless": 68, "undetected": 4, "total_engines": 72}})
    assert r["verdict"] == "CLEAN"
    assert r["final_score"] <= 25


def test_signed_exe_with_shared_infra_ip_is_clean():
    """Claude Setup.exe-style: VT 0/74 clean, but a shared cloud IP got AbuseIPDB-flagged.
    VT-strong-clean must prevent the shared-infra IP from forcing MALICIOUS."""
    r = _scan(
        strings={"suspicious_keywords": ["base64", "payload", "wget", "chmod", "sudo",
                                         "VirtualAlloc", "WriteProcessMemory"],
                 "urls": ["https://api.anthropic.com/x"], "ips": ["162.159.36.2"]},
        entropy={"score": 6.26},
        yara_results={"matches": [{"rule": "Suspicious_Base64_Encoded_Payload", "severity": "MEDIUM", "description": "x"}]},
        ip_intel={"results": [{"ip": "162.159.36.2", "overall_verdict": "MALICIOUS"}]},
        virustotal={"found": True, "stats": {"malicious": 0, "suspicious": 0,
                                             "harmless": 60, "undetected": 14, "total_engines": 74}},
    )
    assert r["verdict"] == "CLEAN", r["reasons"]


def test_google_ip_not_flagged():
    """Google IPs must be skipped in IP reputation scoring."""
    r = _scan(ip_intel={"results": [{"ip": "64.233.180.94", "overall_verdict": "MALICIOUS"}]})
    assert r["verdict"] == "CLEAN"


# ─────────────────────────── MALICIOUS cases (must still catch real threats) ───────────────────────────

def test_rtochallan_malware_is_high():
    """rtochallan-style: VT 23/75 dirty + malicious C2 IP → must be MALICIOUS."""
    r = _scan(
        strings={"suspicious_keywords": ["payload"], "urls": [], "ips": ["104.21.64.137"]},
        entropy={"score": 7.9},
        yara_results={"matches": [{"rule": "RTO_Challan_Fake_App", "severity": "CRITICAL", "description": "x"}]},
        ip_intel={"results": [{"ip": "104.21.64.137", "overall_verdict": "MALICIOUS"}]},
        virustotal={"found": True, "stats": {"malicious": 23, "suspicious": 2,
                                             "harmless": 40, "undetected": 10, "total_engines": 75}},
    )
    assert r["verdict"] == "MALICIOUS", r["reasons"]
    assert r["final_score"] >= 75


def test_malwarebazaar_match_is_high():
    """A confirmed MalwareBazaar hit is hard evidence — must stay MALICIOUS even if VT is clean."""
    r = _scan(malwarebazaar={"found": True, "signature": "AndroidRAT"})
    assert r["verdict"] == "MALICIOUS"


def test_fuzzy_variant_is_high():
    """A fuzzy-hash match to known malware is hard evidence."""
    r = _scan(fuzzy_results={"is_variant": True,
                             "best_match": {"name": "METER", "similarity": 92}})
    assert r["verdict"] == "MALICIOUS"


def test_vt_many_detections_is_high():
    """VT 30/75 malicious → MALICIOUS regardless of anything else."""
    r = _scan(virustotal={"found": True, "stats": {"malicious": 30, "suspicious": 3,
                                                   "harmless": 30, "undetected": 12, "total_engines": 75}})
    assert r["verdict"] == "MALICIOUS"


# ─────────────────────────── structure / sanity ───────────────────────────

def test_result_shape():
    r = _scan()
    for key in ("final_score", "verdict", "color", "conclusion", "total_indicators", "reasons", "indicators"):
        assert key in r
    assert 0 <= r["final_score"] <= 100
    assert r["verdict"] in ("MALICIOUS", "SUSPICIOUS", "POTENTIALLY UNWANTED", "CLEAN")
