"""
vt_behavior.py — VirusTotal Sandbox Behaviour puller
=====================================================
This is where the "dynamic traffic" for non-APK files (.exe/.dll/.pdf/.elf/scripts) comes from.
VirusTotal runs each file in its MULTIPLE sandboxes (Windows/Linux/Android) and records
the network behaviour — the same "IP Traffic" shown on the VT website. We pull it via the
API and feed it into our own pipeline (filter + risk).

In short: APK -> our local Android sandbox; everything else -> VT's cloud sandbox behaviour.
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"
HEADERS  = {"x-apikey": API_KEY}


def get_vt_behavior(sha256):
    """Network behaviour from VT's sandboxes (IPs/domains/URLs/files/processes) by sha256."""
    try:
        url = f"{BASE_URL}/files/{sha256}/behaviour_summary"
        r = requests.get(url, headers=HEADERS, timeout=30)

        if r.status_code == 404:
            return {"available": False,
                    "message": "VT has no sandbox behaviour for this file (or the file is new)"}
        if r.status_code in (401, 403):
            return {"available": False,
                    "message": "VT behaviour endpoint not allowed for this API key (premium/limit)"}
        if r.status_code != 200:
            return {"available": False, "message": f"VT behaviour API error: {r.status_code}"}

        d = r.json().get("data", {})

        ips = sorted({x.get("destination_ip") for x in d.get("ip_traffic", [])
                      if isinstance(x, dict) and x.get("destination_ip")})
        domains = sorted({x.get("hostname") for x in d.get("dns_lookups", [])
                          if isinstance(x, dict) and x.get("hostname")})
        urls = sorted({x.get("url") for x in d.get("http_conversations", [])
                       if isinstance(x, dict) and x.get("url")})

        return {
            "available": True,
            "source": "VirusTotal multi-sandbox behaviour",
            "ips":     ips,
            "domains": domains,
            "urls":    urls,
            "files_written":     d.get("files_written", [])[:25],
            "files_dropped":     [f.get("path") if isinstance(f, dict) else f
                                  for f in d.get("files_dropped", [])][:25],
            "processes_created": d.get("processes_created", [])[:25],
            "registry_keys_set": d.get("registry_keys_set", [])[:25],
            "command_executions":d.get("command_executions", [])[:25],
            "mitre":   d.get("mitre_attack_techniques", []) if isinstance(d.get("mitre_attack_techniques"), list) else [],
            "verdicts":d.get("verdicts", []),
            "tags":    d.get("tags", []),
        }
    except Exception as e:
        return {"available": False, "error": str(e)}
