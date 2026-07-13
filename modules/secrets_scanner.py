import re
import math

SECRET_PATTERNS = {
    "AWS Access Key":    r"AKIA[0-9A-Z]{16}",
    "Google API Key":    r"AIza[0-9A-Za-z\-_]{35}",
    "Private Key":       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "Slack Token":       r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "GitHub Token":      r"gh[pousr]_[0-9A-Za-z]{36,}",
    "Stripe Secret Key": r"sk_live_[0-9a-zA-Z]{24}",
    "JWT Token":         r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Google OAuth":      r"ya29\.[0-9A-Za-z\-_]+",
}

# These are not "secrets" — they are public client identifiers (public by design).
# A Firebase/Google AIza key is present in the APK of every legitimate Android app.
PUBLIC_KEY_TYPES = {"Google API Key"}


def shannon_entropy(s):
    if not s:
        return 0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def scan_secrets(strings):
    findings = []
    public_keys = []
    seen = set()
    for s in strings:
        for name, pattern in SECRET_PATTERNS.items():
            for match in re.findall(pattern, s):
                if match in seen:
                    continue
                seen.add(match)
                entry = {
                    "type": name,
                    "match": match,
                    "entropy": round(shannon_entropy(match), 2),
                }
                if name in PUBLIC_KEY_TYPES:
                    entry["public"] = True
                    public_keys.append(entry)
                else:
                    findings.append(entry)
    return {
        "total_found": len(findings),      # counts only REAL secrets
        "secrets": findings,
        "public_keys": public_keys,        # info-only (Firebase/Google client keys)
    }
