import os
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

load_dotenv()

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
AUTH_KEY = os.getenv("ABUSE_CH_AUTH_KEY")

# Known-good hosts — these cause false positives in the URLhaus host-level check
# (googleapis/github can HOST malware, but the host itself is not malicious)
KNOWN_GOOD_HOSTS = (
    "googleapis.com", "google.com", "gstatic.com", "googleusercontent.com",
    "firebasestorage.app", "firebaseio.com", "firebase.google.com",
    "app-measurement.com", "crashlytics.com", "google-analytics.com",
    "googletagmanager.com", "android.com", "googlesource.com",
    "github.com", "githubusercontent.com", "gitlab.com",
    "microsoft.com", "apple.com", "cloudflare.com",
    "amazonaws.com", "dropbox.com", "discord.com", "discordapp.com",
    "w3.org", "schemas.android.com", "example.com", "localhost",
    "t.me", "telegram.org", "telegram.me", "paypal.com", "weblate.org",
    "anthropic.com", "claude.ai", "digicert.com", "adobe.com",
    "datadoghq.com", "facebook.net", "go.dev",
)


def _is_known_good(host):
    h = host.lower()
    return any(h == d or h.endswith("." + d) for d in KNOWN_GOOD_HOSTS)


def _check_host(host):
    headers = {"Auth-Key": AUTH_KEY} if AUTH_KEY else {}
    resp = requests.post(URLHAUS_API, headers=headers, data={"host": host}, timeout=15)
    data = resp.json()
    if data.get("query_status") == "ok" and data.get("url_count"):
        return {
            "host": host,
            "url_count": data.get("url_count"),
            "blacklists": data.get("blacklists", {}),
        }
    return None


def check_urlhaus(urls):
    # extract unique hosts from the URLs (skip known-good — also saves API quota)
    hosts = set()
    for u in urls:
        try:
            h = urlparse(u).netloc or u
        except Exception:
            h = u
        if h and not _is_known_good(h):
            hosts.add(h)

    malicious = []
    for h in list(hosts)[:10]:        # max 10
        try:
            r = _check_host(h)
            if r:
                malicious.append(r)
        except Exception:
            continue

    return {
        "hosts_checked": len(hosts),
        "malicious_hosts": malicious,
        "found_malicious": len(malicious) > 0,
    }
