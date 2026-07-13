"""
geolocation.py — IP Geolocation (for the world map)
====================================================
Maps a file's IPs to lat/lon/country/city (ip-api.com batch — free, no key).
Each IP also carries its reputation verdict so the map can be colour-coded:
  MALICIOUS = laal, SUSPICIOUS = orange, CLEAN = green.
"""

import ipaddress
import requests

BATCH_URL = "http://ip-api.com/batch"  # free tier HTTP only, 100 IP/batch
FIELDS = "query,status,country,countryCode,city,lat,lon,isp,org,as"

# Google IP ranges — noise on the map (almost every app talks to these), skip
GOOGLE_IP_PREFIXES = (
    "64.233.", "142.250.", "142.251.", "172.217.", "172.253.", "173.194.",
    "74.125.", "216.239.", "216.58.", "192.178.", "108.177.", "8.8.8.", "8.8.4.",
)


def _is_public(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_global and not a.is_private and not a.is_multicast
    except Exception:
        return False


def _is_google(ip):
    return any(ip.startswith(p) for p in GOOGLE_IP_PREFIXES)


def geolocate_ips(ip_list, verdict_map=None):
    """Geolocate public IPs. verdict_map = {ip: 'MALICIOUS'/'SUSPICIOUS'/'CLEAN'}."""
    verdict_map = verdict_map or {}
    pub = [ip for ip in dict.fromkeys(ip_list) if _is_public(ip) and not _is_google(ip)]   # unique + public + non-Google
    if not pub:
        return {"total": 0, "locations": [], "countries": []}

    try:
        body = [{"query": ip, "fields": FIELDS} for ip in pub[:100]]
        r = requests.post(BATCH_URL, json=body, timeout=20)
        data = r.json()

        locations, countries = [], {}
        for item in data:
            if item.get("status") != "success":
                continue
            ip = item.get("query")
            v = verdict_map.get(ip, "UNKNOWN")
            cc = item.get("countryCode")
            countries[cc] = countries.get(cc, 0) + 1
            locations.append({
                "ip": ip,
                "verdict": v,
                "country": item.get("country"),
                "country_code": cc,
                "city": item.get("city"),
                "lat": item.get("lat"),
                "lon": item.get("lon"),
                "isp": item.get("isp"),
                "org": item.get("org"),
                "asn": item.get("as"),
            })

        return {
            "total": len(locations),
            "locations": locations,
            "countries": [{"code": k, "count": v} for k, v in sorted(countries.items(), key=lambda x: -x[1])],
        }
    except Exception as e:
        return {"error": str(e), "total": 0, "locations": [], "countries": []}
