import requests
import os
from dotenv import load_dotenv

load_dotenv()

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

# ── AbuseIPDB ──────────────────────────────────
def check_ip_abuseipdb(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        response = requests.get(url, headers=headers, params=params)
        data = response.json().get("data", {})

        abuse_score = data.get("abuseConfidenceScore", 0)

        if abuse_score >= 80:
            verdict = "MALICIOUS"
        elif abuse_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "source": "AbuseIPDB",
            "ip": ip,
            "abuse_score": abuse_score,
            "total_reports": data.get("totalReports", 0),
            "country": data.get("countryCode", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "is_tor": data.get("isTor", False),
            "verdict": verdict
        }
    except Exception as e:
        return {"source": "AbuseIPDB", "error": str(e)}


# ── Shodan ─────────────────────────────────────
def check_ip_shodan(ip):
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": SHODAN_API_KEY}
        response = requests.get(url, params=params)

        if response.status_code == 404:
            return {
                "source": "Shodan",
                "ip": ip,
                "found": False,
                "message": "IP not found in Shodan"
            }

        data = response.json()

        return {
            "source": "Shodan",
            "ip": ip,
            "found": True,
            "country": data.get("country_name", "Unknown"),
            "city": data.get("city", "Unknown"),
            "org": data.get("org", "Unknown"),
            "isp": data.get("isp", "Unknown"),
            "open_ports": data.get("ports", []),
            "hostnames": data.get("hostnames", []),
            "tags": data.get("tags", []),
            "vulns": list(data.get("vulns", {}).keys())[:5]
        }
    except Exception as e:
        return {"source": "Shodan", "error": str(e)}


# ── AlienVault OTX ─────────────────────────────
def check_ip_otx(ip):
    try:
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": OTX_API_KEY}
        response = requests.get(url, headers=headers)
        data = response.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)

        if pulse_count >= 5:
            verdict = "MALICIOUS"
        elif pulse_count >= 1:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "source": "AlienVault OTX",
            "ip": ip,
            "pulse_count": pulse_count,
            "verdict": verdict,
            "country": data.get("country_name", "Unknown"),
            "asn": data.get("asn", "Unknown"),
        }
    except Exception as e:
        return {"source": "AlienVault OTX", "error": str(e)}


# ── Check all sources ──────────────────────────
def analyze_ips(ip_list):
    if not ip_list:
        return {"message": "No IPs found to analyze"}

    results = []
    for ip in ip_list[:10]:  # Max 10 IPs
        ip_result = {
            "ip": ip,
            "abuseipdb": check_ip_abuseipdb(ip),
            "shodan": check_ip_shodan(ip),
            "otx": check_ip_otx(ip)
        }

        # Overall IP verdict
        verdicts = [
            ip_result["abuseipdb"].get("verdict", "CLEAN"),
            ip_result["otx"].get("verdict", "CLEAN")
        ]
        if "MALICIOUS" in verdicts:
            ip_result["overall_verdict"] = "MALICIOUS"
        elif "SUSPICIOUS" in verdicts:
            ip_result["overall_verdict"] = "SUSPICIOUS"
        else:
            ip_result["overall_verdict"] = "CLEAN"

        results.append(ip_result)

    return {
        "total_ips_checked": len(results),
        "results": results
    }