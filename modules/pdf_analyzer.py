"""
TotalWare — PDF Analyzer Module
Extracts: metadata, URLs, IPs, emails, JavaScript, embedded files,
          suspicious keywords, object entropy, stream analysis
"""

import re
import math
import os
from typing import Optional

# ── helpers ─────────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    e = 0.0
    for c in counts:
        if c:
            p = c / total
            e -= p * math.log2(p)
    return round(e, 4)

def _extract_iocs(text: str):
    urls     = list(set(re.findall(r'https?://[^\s\'"<>\])+]{4,}', text)))
    ips      = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    emails   = list(set(re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)))
    domains  = list(set(re.findall(
        r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|onion)\b', text
    )))
    return urls, ips, emails, domains

SUSPICIOUS_KEYWORDS = [
    # JS / actions
    "eval", "unescape", "String.fromCharCode", "this.exportDataObject",
    "app.launchURL", "util.printf", "getAnnots", "getField",
    "submitForm", "importData",
    # shell / exploits
    "cmd.exe", "powershell", "shellcode", "exploit", "payload",
    "meterpreter", "CreateRemoteThread", "VirtualAlloc",
    "base64", "wget", "curl", "chmod +x",
    # obfuscation
    "\\x", "%u", "fromCharCode", "decodeURIComponent",
    # CVEs commonly exploited via PDF
    "CVE-", "Collab.collectEmailInfo", "media.newPlayer",
]

def _find_suspicious_keywords(text: str):
    text_lower = text.lower()
    found = []
    for kw in SUSPICIOUS_KEYWORDS:
        if kw.lower() in text_lower:
            found.append(kw)
    return found

# ── main analyzer ────────────────────────────────────────────────────────────

def analyze_pdf(file_path: str) -> dict:
    result = {
        "metadata":            {},
        "page_count":          0,
        "urls":                [],
        "ips":                 [],
        "emails":              [],
        "domains":             [],
        "javascript_found":    False,
        "javascript_snippets": [],
        "embedded_files":      [],
        "suspicious_keywords": [],
        "object_count":        0,
        "stream_entropy":      [],
        "high_entropy_streams":0,
        "auto_actions":        [],
        "forms_found":         False,
        "encrypted":           False,
        "risk_indicators":     [],
        "risk_score":          0,
        "verdict":             "CLEAN",
    }

    # ── 1. pdfplumber — text + metadata + pages ──────────────────────────────
    try:
        import pdfplumber
        with pdfplumber.open(file_path) as pdf:
            result["page_count"] = len(pdf.pages)

            # metadata
            meta = pdf.metadata or {}
            result["metadata"] = {
                "title":        meta.get("Title", ""),
                "author":       meta.get("Author", ""),
                "creator":      meta.get("Creator", ""),
                "producer":     meta.get("Producer", ""),
                "creation_date":str(meta.get("CreationDate", "")),
                "mod_date":     str(meta.get("ModDate", "")),
                "subject":      meta.get("Subject", ""),
            }

            # full text extraction
            full_text = ""
            for page in pdf.pages:
                try:
                    t = page.extract_text() or ""
                    full_text += t + "\n"
                except Exception:
                    pass

            urls, ips, emails, domains = _extract_iocs(full_text)
            result["urls"]    = urls
            result["ips"]     = ips
            result["emails"]  = emails
            result["domains"] = domains
            result["suspicious_keywords"] = _find_suspicious_keywords(full_text)

    except Exception as e:
        result["metadata"]["error"] = str(e)

    # ── 2. pypdf — JS, embedded files, encryption, actions ──────────────────
    try:
        import pypdf
        reader = pypdf.PdfReader(file_path)

        result["encrypted"] = reader.is_encrypted

        # try to decrypt with blank password
        if reader.is_encrypted:
            try:
                reader.decrypt("")
            except Exception:
                pass

        # walk all objects
        js_snippets  = []
        embedded     = []
        auto_actions = []
        obj_count    = 0

        try:
            for obj_id in reader.xref_objStm or []:
                obj_count += 1
        except Exception:
            pass

        # iterate pages for annotations / actions
        for page in reader.pages:
            obj_count += 1
            try:
                annots = page.get("/Annots")
                if annots:
                    for annot in annots:
                        try:
                            obj = annot.get_object()
                            if obj.get("/Subtype") == "/Widget":
                                result["forms_found"] = True
                            a = obj.get("/A", {})
                            if hasattr(a, "get_object"):
                                a = a.get_object()
                            if a:
                                uri = a.get("/URI", "")
                                if uri:
                                    result["urls"].append(str(uri))
                        except Exception:
                            pass
            except Exception:
                pass

        # document-level JS and OpenAction
        try:
            catalog = reader.trailer.get("/Root", {})
            if hasattr(catalog, "get_object"):
                catalog = catalog.get_object()

            # OpenAction
            open_action = catalog.get("/OpenAction")
            if open_action:
                auto_actions.append("OpenAction detected")

            # AA (Additional Actions)
            aa = catalog.get("/AA")
            if aa:
                auto_actions.append("Additional Actions (AA) detected")

            # Names → JavaScript
            names = catalog.get("/Names")
            if names:
                if hasattr(names, "get_object"):
                    names = names.get_object()
                js_tree = names.get("/JavaScript")
                if js_tree:
                    result["javascript_found"] = True
                    auto_actions.append("Named JavaScript actions found")

            # AcroForm
            acro = catalog.get("/AcroForm")
            if acro:
                result["forms_found"] = True

            # EmbeddedFiles
            try:
                ef = catalog["/Names"]["/EmbeddedFiles"]
                if ef:
                    embedded.append("Embedded files detected in /Names/EmbeddedFiles")
            except Exception:
                pass

        except Exception:
            pass

        result["javascript_snippets"] = js_snippets[:5]   # cap at 5
        result["embedded_files"]      = embedded
        result["auto_actions"]        = auto_actions
        result["object_count"]        = obj_count

    except Exception as e:
        result["object_count"] = -1

    # ── 3. Raw byte scan — entropy per stream, extra IOC sweep ───────────────
    try:
        with open(file_path, "rb") as f:
            raw = f.read()

        # look for stream ... endstream blocks
        streams = re.findall(b'stream\r?\n(.*?)endstream', raw, re.DOTALL)
        entropies = []
        high = 0
        for s in streams:
            e = _entropy(s)
            entropies.append(e)
            if e > 7.0:
                high += 1
        result["stream_entropy"]       = entropies
        result["high_entropy_streams"] = high

        # extra IOC pass on raw decoded text
        try:
            raw_text = raw.decode("latin-1", errors="ignore")
            extra_urls, extra_ips, extra_emails, _ = _extract_iocs(raw_text)
            result["urls"]   = list(set(result["urls"]   + extra_urls))
            result["ips"]    = list(set(result["ips"]    + extra_ips))
            result["emails"] = list(set(result["emails"] + extra_emails))
        except Exception:
            pass

        # JS keywords in raw bytes
        raw_lower = raw.decode("latin-1", errors="ignore").lower()
        for kw in ["/javascript", "/js", "eval(", "unescape("]:
            if kw in raw_lower:
                result["javascript_found"] = True
                break

        # check for /EmbeddedFile
        if b"/EmbeddedFile" in raw:
            result["embedded_files"].append("/EmbeddedFile object found in raw bytes")

        # /Launch action (RCE vector)
        if b"/Launch" in raw:
            result["auto_actions"].append("/Launch action detected — RCE risk")

        # /RichMedia (Flash exploit vector)
        if b"/RichMedia" in raw:
            result["auto_actions"].append("/RichMedia detected — Flash exploit vector")

    except Exception:
        pass

    # ── 4. Risk scoring ───────────────────────────────────────────────────────
    indicators = []
    score = 0

    if result["javascript_found"]:
        indicators.append("JavaScript embedded in PDF")
        score += 25

    if result["high_entropy_streams"] > 0:
        indicators.append(f"{result['high_entropy_streams']} high-entropy stream(s) — possible shellcode/packed data")
        score += result["high_entropy_streams"] * 10

    if result["embedded_files"]:
        indicators.append("Embedded files detected")
        score += 20

    if result["encrypted"]:
        indicators.append("PDF is encrypted")
        score += 10

    if any("/Launch" in a for a in result["auto_actions"]):
        indicators.append("/Launch action — can execute arbitrary commands")
        score += 30

    if any("OpenAction" in a for a in result["auto_actions"]):
        indicators.append("OpenAction — auto-executes on open")
        score += 15

    if result["suspicious_keywords"]:
        indicators.append(f"Suspicious keywords: {', '.join(result['suspicious_keywords'][:5])}")
        score += len(result["suspicious_keywords"]) * 5

    if len(result["urls"]) > 10:
        indicators.append(f"High URL count ({len(result['urls'])}) — possible phishing")
        score += 10

    # cap score
    score = min(score, 100)

    result["risk_indicators"] = indicators
    result["risk_score"]      = score
    result["verdict"]         = (
        "MALICIOUS"  if score >= 70 else
        "SUSPICIOUS" if score >= 35 else
        "CLEAN"
    )

    return result


# ── quick CLI test ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Usage: python pdf_analyzer.py <file.pdf>")
        sys.exit(1)
    out = analyze_pdf(sys.argv[1])
    print(json.dumps(out, indent=2))
