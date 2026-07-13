from flask import Flask, request, jsonify, render_template, send_file, redirect, url_for
from flask_login import LoginManager, login_user, logout_user, current_user
from modules.apk_analyzer import analyze_apk
from modules.risk_engine import calculate_risk
from modules.pe_analyzer import analyze_pe
from modules.archive_analyzer import analyze_archive
from modules.virustotal import check_hash, upload_and_scan
from modules.threat_intel import analyze_ips
from modules.ai_conclusion import generate_ai_conclusion
from modules.pdf_analyzer import analyze_pdf
from modules.secrets_scanner import scan_secrets
from modules.office_analyzer import analyze_office
from modules.pcap_analyzer import analyze_pcap
from modules.fuzzy_hash import analyze_fuzzy
from modules.malwarebazaar import check_malwarebazaar
from modules.urlhaus import check_urlhaus
from modules.geolocation import geolocate_ips
from modules.relationship_graph import build_graph
from modules.database import (
    init_db, save_scan, update_scan_result,
    list_scans, get_scan, delete_scan, get_stats,
    create_user, verify_login, get_user_by_id,
    create_api_key, list_api_keys, revoke_api_key, verify_api_key,
    get_vote_summary, cast_vote, community_feed,
    create_org, join_org, get_user_orgs, get_org_dashboard
)
import hashlib
import uuid
import os
import re
import yara
import io
from datetime import datetime

app = Flask(__name__)

# Max upload size — reject bigger files cleanly (VirusTotal caps at ~650 MB too)
MAX_UPLOAD_MB = 650
app.config['MAX_CONTENT_LENGTH'] = MAX_UPLOAD_MB * 1024 * 1024

UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Scan history DB (SQLite for now; switch to Postgres via the DATABASE_URL env)
init_db()

# ── Auth (Flask-Login) — login optional ──
app.secret_key = os.getenv("SECRET_KEY", "totalware-dev-secret-change-me")
login_manager = LoginManager(app)

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

# Uploads bigger than MAX_CONTENT_LENGTH are rejected here with a clean JSON error
@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File too large — maximum upload size is {MAX_UPLOAD_MB} MB."}), 413

def get_hashes(file_path):
    # Stream the file in 1 MB chunks so large files don't load fully into RAM
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

def get_entropy(file_path):
    import math
    with open(file_path, 'rb') as f:
        data = f.read()
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0.0
    total = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        probability = count / total
        entropy -= probability * math.log2(probability)
    return round(entropy, 4)

def run_yara_scan(file_path):
    import zipfile
    import tempfile
    import shutil
    rules_dir = 'yara_rules'
    matches_found = []
    compiled_rules = []
    for rule_file in os.listdir(rules_dir):
        if rule_file.endswith('.yar'):
            try:
                rule_path = os.path.join(rules_dir, rule_file)
                rules = yara.compile(filepath=rule_path)
                compiled_rules.append(rules)
            except Exception as e:
                continue
    for rules in compiled_rules:
        try:
            matches = rules.match(file_path)
            for match in matches:
                severity = match.meta.get('severity', 'UNKNOWN')
                description = match.meta.get('description', 'No description')
                matches_found.append({
                    "rule": match.rule,
                    "severity": severity,
                    "description": description,
                    "found_in": "main_file"
                })
        except:
            continue
    if zipfile.is_zipfile(file_path):
        temp_dir = tempfile.mkdtemp()
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                try:
                    z.extractall(temp_dir)
                except (NotImplementedError, Exception):
                    for item in z.infolist():
                        try:
                            z.extract(item, temp_dir)
                        except:
                            continue
            for root, dirs, files in os.walk(temp_dir):
                for fname in files:
                    extracted_file = os.path.join(root, fname)
                    for rules in compiled_rules:
                        try:
                            matches = rules.match(extracted_file)
                            for match in matches:
                                severity = match.meta.get('severity', 'UNKNOWN')
                                description = match.meta.get('description', 'No description')
                                matches_found.append({
                                    "rule": match.rule,
                                    "severity": severity,
                                    "description": description,
                                    "found_in": fname
                                })
                        except:
                            continue
        finally:
            shutil.rmtree(temp_dir)
    seen = set()
    unique_matches = []
    for m in matches_found:
        key = m['rule'] + m['found_in']
        if key not in seen:
            seen.add(key)
            unique_matches.append(m)
    return {
        "total_rules_matched": len(unique_matches),
        "matches": unique_matches,
        "verdict": "MALICIOUS" if len(unique_matches) >= 2 else "SUSPICIOUS" if len(unique_matches) == 1 else "CLEAN"
    }

def extract_strings(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    ascii_strings = re.findall(b'[\x20-\x7e]{4,}', data)
    readable = [s.decode('ascii', errors='ignore') for s in ascii_strings]
    urls = []
    for s in readable:
        found = re.findall(r'https?://[^\s\'"<>]+', s)
        urls.extend(found)
    ips = []
    for s in readable:
        found = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s)
        ips.extend(found)
    emails = []
    for s in readable:
        found = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', s)
        emails.extend(found)
    suspicious_keywords = [
        'cmd.exe', 'powershell', 'base64', 'shellcode',
        'exploit', 'payload', 'reverse_shell', 'meterpreter',
        'wget', 'curl', 'chmod', 'sudo', 'rm -rf',
        'CreateRemoteThread', 'VirtualAlloc', 'WriteProcessMemory'
    ]
    found_suspicious = []
    full_text = ' '.join(readable).lower()
    for keyword in suspicious_keywords:
        if keyword.lower() in full_text:
            found_suspicious.append(keyword)

    secrets = scan_secrets(readable)

    return {
        "urls": list(set(urls)),
        "ips": list(set(ips)),
        "emails": list(set(emails)),
        "suspicious_keywords": found_suspicious,
        "total_strings_extracted": len(readable),
        "secrets": secrets,
    }

# ── Shared scan pipeline (used by both the browser /scan and the API /api/v1/scan) ──
def run_full_scan(file_path, original_name, stored_name, file_size, password=None):
    """Run the full analysis on a file and return the result dict."""
    hashes = get_hashes(file_path)
    strings = extract_strings(file_path)
    entropy = get_entropy(file_path)
    yara_results = run_yara_scan(file_path)

    apk_results = {}
    if original_name.lower().endswith('.apk'):
        apk_results = analyze_apk(file_path)

    office_results = {}
    if original_name.lower().endswith(('.doc','.docx','.docm','.xls','.xlsx','.xlsm','.ppt','.pptx','.pptm','.vba','.bas')):
        office_results = analyze_office(file_path)

    pcap_results = {}
    if original_name.lower().endswith(('.pcap', '.pcapng')):
        pcap_results = analyze_pcap(file_path)

    fuzzy_results = analyze_fuzzy(file_path)
    mb_results = check_malwarebazaar(hashes["sha256"])

    # VirusTotal — before the risk calculation
    vt_results = upload_and_scan(file_path, hashes["sha256"])

    all_urls = list(strings.get("urls", []))
    if apk_results and "network" in apk_results:
        all_urls += apk_results["network"].get("urls_found", [])
    if pcap_results.get("dns_queries"):
        all_urls += pcap_results["dns_queries"]
    if pcap_results.get("http_hosts"):
        all_urls += pcap_results["http_hosts"]
    urlhaus_results = check_urlhaus(all_urls)

    all_ips = strings.get("ips", [])
    if apk_results and "network" in apk_results:
        all_ips += apk_results["network"].get("ips_found", [])
    if pcap_results.get("destination_ips"):
        all_ips += pcap_results["destination_ips"]
    all_ips = list(set(all_ips))
    ip_intel = analyze_ips(all_ips)

    verdict_map = {r["ip"]: r.get("overall_verdict", "UNKNOWN") for r in ip_intel.get("results", [])}
    ip_geo = geolocate_ips(all_ips, verdict_map)

    risk = calculate_risk(
        hashes=hashes,
        strings=strings,
        entropy={"score": entropy},
        yara_results=yara_results,
        apk_results=apk_results if apk_results else None,
        office_results=office_results if office_results else None,
        pcap_results=pcap_results if pcap_results else None,
        ip_intel=ip_intel,
        fuzzy_results=fuzzy_results,
        malwarebazaar=mb_results,
        urlhaus=urlhaus_results,
        virustotal=vt_results,
    )

    pe_results = {}
    if original_name.lower().endswith(('.exe', '.dll', '.sys', '.drv')):
        pe_results = analyze_pe(file_path)
    pdf_results = {}
    if original_name.lower().endswith('.pdf'):
        pdf_results = analyze_pdf(file_path)

    archive_results = {}
    if original_name.lower().endswith(('.zip', '.7z', '.rar')):
        archive_results = analyze_archive(file_path, password=password)
        nested_apk_results = []
        if "files" in archive_results:
            import tempfile, zipfile, shutil
            temp_dir = tempfile.mkdtemp()
            try:
                with zipfile.ZipFile(file_path, 'r') as z:
                    z.extractall(temp_dir)
                for f in archive_results["files"]:
                    if f["extension"] == ".apk":
                        apk_path = os.path.join(temp_dir, f["filename"])
                        if os.path.exists(apk_path):
                            nres = analyze_apk(apk_path)
                            nres["filename"] = f["filename"]
                            nested_apk_results.append(nres)
            except Exception:
                pass
            finally:
                shutil.rmtree(temp_dir)
        if nested_apk_results:
            archive_results["apk_analysis"] = nested_apk_results

    rel_graph = build_graph({
        "filename": original_name,
        "risk_assessment": risk,
        "ip_intelligence": ip_intel,
        "strings": strings,
        "apk_analysis": apk_results,
        "fuzzy_hash": fuzzy_results,
        "malwarebazaar": mb_results,
    })

    return {
        "filename": original_name,
        "stored_name": stored_name,
        "size_bytes": file_size,
        "hashes": hashes,
        "strings": strings,
        "entropy": {
            "score": entropy,
            "verdict": "HIGH - Possibly packed/encrypted" if entropy > 7.0 else "MEDIUM - Slightly suspicious" if entropy > 5.0 else "LOW - Normal file"
        },
        "yara_scan": yara_results,
        "apk_analysis": apk_results,
        "risk_assessment": risk,
        "pe_analysis": pe_results,
        "archive_analysis": archive_results,
        "virustotal": vt_results,
        "ip_intelligence": ip_intel,
        "ip_geolocation": ip_geo,
        "relationship_graph": rel_graph,
        "pdf_analysis": pdf_results,
        "office_analysis": office_results,
        "pcap_analysis": pcap_results,
        "fuzzy_hash": fuzzy_results,
        "malwarebazaar": mb_results,
        "urlhaus": urlhaus_results,
    }


def _save_uploaded_file(file):
    """Save the upload under a safe uuid name. Returns (file_path, original_name, stored_name, file_size) or None on error."""
    original_name = file.filename
    ext = re.sub(r'[^A-Za-z0-9.]', '', os.path.splitext(original_name)[1]).lower()
    stored_name = f"{uuid.uuid4().hex}{ext}"
    file_path = os.path.join(UPLOAD_FOLDER, stored_name)
    file.save(file_path)
    try:
        file_size = os.path.getsize(file_path)
        with open(file_path, 'rb') as _chk:
            _chk.read(1)
    except OSError:
        return None
    return file_path, original_name, stored_name, file_size


# ── Simple in-memory rate limiter (per API key) ──
from collections import deque
import time as _time
_RATE_LIMIT = 30     # requests
_RATE_WINDOW = 60    # seconds (i.e. 30 req/min)
_rate_state = {}

def _rate_limit_ok(key):
    now = _time.time()
    dq = _rate_state.setdefault(key, deque())
    while dq and dq[0] <= now - _RATE_WINDOW:
        dq.popleft()
    if len(dq) >= _RATE_LIMIT:
        return False, int(_RATE_WINDOW - (now - dq[0]))
    dq.append(now)
    return True, 0


# ── ROUTES ──────────────────────────────────────────

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    saved = _save_uploaded_file(file)
    if saved is None:
        return jsonify({
            "error": "Could not read the file on disk — Windows Defender most likely "
                     "flagged it as malware and quarantined it. Fix: add the 'uploads' folder "
                     "under Windows Security -> Virus & threat protection -> Manage settings -> "
                     "Exclusions, then scan again."
        }), 422
    file_path, original_name, stored_name, file_size = saved

    try:
        result = run_full_scan(file_path, original_name, stored_name, file_size,
                               password=request.form.get('password', None))
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Scan failed while analyzing the file: {e}"}), 500

    # Save to history — return scan_id in the response (for later updates)
    try:
        _uid = current_user.id if current_user.is_authenticated else None
        result["scan_id"] = save_scan(result, user_id=_uid)
    except Exception as e:
        result["scan_id"] = None
        print("save_scan error:", e)

    return jsonify(result)


# ── Public API — file scan via API key (Phase E — Step 3) ──
@app.route('/api/v1/scan', methods=['POST'])
def api_v1_scan():
    # Auth: "Authorization: Bearer <key>" or "X-API-Key: <key>"
    auth = request.headers.get('Authorization', '')
    key = auth[7:].strip() if auth.lower().startswith('bearer ') else request.headers.get('X-API-Key', '')
    user = verify_api_key(key)
    if not user:
        return jsonify({"error": "Invalid or missing API key"}), 401

    ok, retry = _rate_limit_ok(key)
    if not ok:
        return jsonify({"error": "Rate limit exceeded — please try again shortly",
                        "retry_after_seconds": retry}), 429

    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded (form field 'file')"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    saved = _save_uploaded_file(file)
    if saved is None:
        return jsonify({"error": "Could not read the file on the server (antivirus block?)"}), 422
    file_path, original_name, stored_name, file_size = saved

    try:
        result = run_full_scan(file_path, original_name, stored_name, file_size,
                               password=request.form.get('password', None))
    except Exception as e:
        return jsonify({"error": f"Scan failed while analyzing the file: {e}"}), 500
    try:
        result["scan_id"] = save_scan(result, user_id=user["id"])
    except Exception:
        result["scan_id"] = None

    # API response — clean summary (heavy graph/geo fields removed)
    risk = result.get("risk_assessment", {}) or {}
    return jsonify({
        "filename": result.get("filename"),
        "size_bytes": result.get("size_bytes"),
        "sha256": (result.get("hashes", {}) or {}).get("sha256"),
        "verdict": risk.get("verdict"),
        "score": risk.get("final_score"),
        "reasons": risk.get("reasons", []),
        "virustotal": (result.get("virustotal", {}) or {}).get("stats"),
        "scan_id": result.get("scan_id"),
    })


@app.route('/ai_conclusion', methods=['POST'])
def ai_conclusion():
    data = request.get_json(silent=True) or {}
    try:
        conclusion = generate_ai_conclusion(data)
    except Exception:
        conclusion = "AI summary temporarily unavailable — the automated analysis above is complete."
    return jsonify({"conclusion": conclusion})

@app.route('/run_dynamic', methods=['POST'])
def run_dynamic_route():
    """Dynamic Sandbox — VirusTotal-style 'Behavior' option. APK -> local emulator, others -> VT cloud."""
    data = request.get_json() or {}
    filename = data.get("stored_name") or data.get("filename", "")
    sha256 = data.get("sha256")
    package = data.get("package")
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    if not filename or not os.path.exists(file_path):
        return jsonify({"error": "File not found on the server — run a scan first"}), 404
    try:
        from modules.sandbox_router import route_sandbox
        return jsonify(route_sandbox(file_path, sha256=sha256, package=package))
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route('/diff', methods=['POST'])
def diff_route():
    data = request.get_json() or {}
    from modules.diff_analysis import diff_scans
    return jsonify(diff_scans(data.get("old", {}), data.get("new", {})))


@app.route('/export_report', methods=['POST'])
def export_report():
    data = request.get_json(silent=True) or {}
    filename  = data.get("filename", "unknown")
    risk      = data.get("risk_assessment", {}) or {}
    score     = risk.get("final_score", 0)
    verdict   = risk.get("verdict", "UNKNOWN")
    reasons   = risk.get("reasons", [])
    vt        = data.get("virustotal", {}) or {}
    vt_stats  = vt.get("stats", {}) or {}
    vt_det    = vt_stats.get("malicious", 0)
    vt_total  = vt_stats.get("total_engines", 0)
    apk       = data.get("apk_analysis", {}) or {}
    app_info  = apk.get("app_info", {}) or {}
    perms     = (apk.get("permissions", {}) or {}).get("dangerous_permissions", [])
    cert      = apk.get("certificate", {}) or {}
    repack    = apk.get("repackaging", {}) or {}
    apis      = (apk.get("suspicious_apis", {}) or {}).get("apis", [])
    mitre     = (apk.get("mitre_attack", {}) or {}).get("techniques", [])
    identity  = apk.get("name_mismatch", {}) or {}
    secrets_d = (data.get("strings", {}) or {}).get("secrets", {}) or {}
    secrets   = secrets_d.get("secrets", [])
    pubkeys   = secrets_d.get("public_keys", [])
    mb        = data.get("malwarebazaar", {}) or {}
    uh        = data.get("urlhaus", {}) or {}
    fuzzy     = data.get("fuzzy_hash", {}) or {}
    dyn       = data.get("dynamic_analysis", {}) or {}
    dyn_iocs  = dyn.get("iocs", {}) or {}
    iocs      = list(set((data.get("strings", {}) or {}).get("urls", []) + (apk.get("network", {}) or {}).get("urls_found", [])))
    yara_m    = (data.get("yara_scan", {}) or {}).get("matches", [])
    hashes    = data.get("hashes", {}) or {}
    entropy   = (data.get("entropy", {}) or {}).get("score", "—")

    vc  = "#E02020" if score >= 75 else "#CC7700" if score >= 50 else "#C9A900" if score >= 25 else "#1A8A1A"
    now = datetime.now().strftime("%d %b %Y, %I:%M %p")

    def esc(x):
        return str(x).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    def row(text, cls="red"):
        return "<div class='row'><div class='dot " + cls + "'></div><div>" + text + "</div></div>"

    def section(title, body):
        if not body:
            return ""
        return "<div class='section'><div class='sh'>" + title + "</div><div class='sb'>" + body + "</div></div>"

    parts = []

    # ── Risk indicators (all of the engine's reasons) ──
    parts.append(section("🧮 Risk Indicators (" + str(len(reasons)) + ")",
                         "".join(row(esc(r), "red" if score >= 50 else "amber") for r in reasons)))

    # ── AI Analysis (TotalWare Intelligence) ──
    ai_text = data.get("ai_conclusion") or ""
    if ai_text:
        parts.append(section("🤖 AI Analysis — TotalWare Intelligence",
                             "<div style='font-size:13px;line-height:1.65;color:#333'>" + esc(ai_text) + "</div>"))

    # ── VirusTotal + Malware Detection Engines ──
    if vt.get("found"):
        body = row(str(vt_det) + "/" + str(vt_total) + " engines flagged — verdict: " + esc(vt.get("verdict", "—")),
                   "red" if vt_det else "green")
        for e in vt.get("malicious_engines", []):
            body += row("<strong>" + esc(e.get("engine", "—")) + "</strong> — " + esc(e.get("result", "malicious")), "red")
        if not vt_det:
            body += row("No engine flagged this file (clean)", "green")
        if vt.get("permalink"):
            body += row("<a href='" + esc(vt["permalink"]) + "'>" + esc(vt["permalink"]) + "</a>", "blue")
        parts.append(section("🔬 Malware Detection Engines (VirusTotal)", body))

    # ── App info (APK only) ──
    if app_info:
        body  = row("App: <strong>" + esc(app_info.get("app_name", "—")) + "</strong> · Package: " + esc(app_info.get("package_name", "—")), "blue")
        body += row("Version: " + esc(app_info.get("version_name", "—")) + " (code " + esc(app_info.get("version_code", "—")) + ")", "blue")
        parts.append(section("📱 App Information", body))

    # ── Certificate forensics ──
    if cert.get("details") or cert.get("red_flags"):
        body = ""
        for c in cert.get("details", []):
            body += row("Signer: <strong>" + esc(c.get("common_name", "—")) + "</strong> · " +
                        ("SELF-SIGNED" if c.get("self_signed") else "CA-signed") + " · " +
                        esc(c.get("hash_algo", "—")) + " · valid " + esc(c.get("validity_years", "—")) + " yrs", "blue")
        for f in cert.get("red_flags", []):
            body += row(esc(f))
        parts.append(section("📜 Certificate Forensics", body))

    # ── Repackaging / Tampering ──
    parts.append(section("📦 Repackaging / Tampering",
                         "".join(row(esc(f)) for f in repack.get("red_flags", []))))

    # ── Suspicious API calls ──
    parts.append(section("⚙️ Suspicious API Calls",
                         "".join(row("<strong>" + esc(a.get("behavior", "—")) + "</strong> — " +
                                     esc(a.get("detail", "")) + " · API: " + esc(a.get("api", "—")), "amber")
                                 for a in apis)))

    # ── App identity ──
    parts.append(section("🎭 App Identity Check",
                         "".join(row(esc(f), "amber") for f in identity.get("red_flags", []))))

    # ── MITRE ATT&CK ──
    parts.append(section("🎯 MITRE ATT&CK Techniques",
                         "".join(row("<strong>" + esc(t.get("id", "—")) + "</strong> — " + esc(t.get("name", "—")) +
                                     " (" + esc(t.get("tactic", "—")) + ") · Evidence: " + esc(t.get("evidence", "—")), "amber")
                                 for t in mitre)))

    # ── Secrets + public client keys ──
    sec_body  = "".join(row("<strong>" + esc(s.get("type", "—")) + "</strong> — " + esc(s.get("match", "")), "red") for s in secrets)
    sec_body += "".join(row(esc(s.get("type", "—")) + " (public client key — not a secret) — " + esc(s.get("match", "")), "green") for s in pubkeys)
    parts.append(section("🔑 Embedded Secrets & Credentials", sec_body))

    # ── MalwareBazaar ──
    if mb.get("found"):
        parts.append(section("🗃️ MalwareBazaar",
                             row("Confirmed known malware — signature: <strong>" + esc(mb.get("signature") or "unknown") + "</strong>")))

    # ── URLhaus ──
    parts.append(section("🔗 URLhaus (Malware-distribution hosts)",
                         "".join(row("<strong>" + esc(h.get("host", "—")) + "</strong> — " + esc(h.get("url_count", 0)) + " malware URLs listed")
                                 for h in uh.get("malicious_hosts", []))))

    # ── Fuzzy hash variant ──
    if fuzzy.get("is_variant"):
        bm = fuzzy.get("best_match", {}) or {}
        parts.append(section("🧬 Fuzzy Hash (Variant Detection)",
                             row("Similar to known malware: <strong>" + esc(bm.get("name", "—")) + "</strong> (" + esc(bm.get("similarity", "—")) + "% match)")))

    # ── Dynamic sandbox (if it was run) ──
    # Shapes: APK-merged (merged_candidate_c2_ips), local (iocs), VT-cloud (iocs + dynamic.mitre), vt_behavior fallback
    vtb       = dyn.get("vt_behavior", {}) or {}
    vtb_iocs  = vtb.get("iocs", {}) or {}
    dyn_d     = dyn.get("dynamic", {}) or {}
    dyn_ips   = dyn.get("merged_candidate_c2_ips") or dyn_iocs.get("candidate_c2_ips") or vtb_iocs.get("candidate_c2_ips") or []
    dyn_hosts = dyn.get("merged_candidate_hosts") or dyn_iocs.get("candidate_hosts") or vtb_iocs.get("candidate_hosts") or []
    dyn_mitre = vtb.get("mitre") or dyn_d.get("mitre") or []
    ti_mal    = [r.get("ip") for r in (dyn.get("threat_intel", {}) or {}).get("results", [])
                 if r.get("overall_verdict") == "MALICIOUS"]

    dyn_body = ""
    if dyn.get("verdict"):
        dyn_body += row(esc(dyn.get("verdict")), "blue")
    for ip in dyn_ips:
        dyn_body += row("C2 IP: <strong>" + esc(ip) + "</strong>" +
                        (" — ⚠️ threat-intel confirmed MALICIOUS" if ip in ti_mal else ""), "red")
    for h in dyn_hosts:
        dyn_body += row("C2 Host: <strong>" + esc(h) + "</strong>", "amber")
    for t in dyn_mitre[:15]:
        dyn_body += row(esc(t.get("id", "—")) + " — " + esc(t.get("signature_description", "")), "amber")
    if dyn and not dyn_ips and not dyn_hosts:
        dyn_body += row("No clear C2 / network IOCs found (file dormant, C2 dead, or benign)", "green")
    parts.append(section("💥 Dynamic Sandbox — Behavior & Candidate C2", dyn_body))

    # ── Network IOCs (max 40) ──
    parts.append(section("🌐 Network IOCs (" + str(len(iocs)) + ")",
                         "".join(row(esc(u), "blue") for u in sorted(iocs)[:40])))

    # ── Dangerous permissions ──
    parts.append(section("🔐 Dangerous Permissions",
                         "".join(row(esc(p.replace("android.permission.", "")), "amber") for p in perms)))

    # ── All requested permissions ──
    all_perms = (apk.get("permissions", {}) or {}).get("all_permissions", [])
    parts.append(section("🗝️ All Requested Permissions (" + str(len(all_perms)) + ")",
                         "".join(row(esc(p), "blue") for p in sorted(all_perms))))

    # ── YARA ──
    parts.append(section("🧿 YARA Matches",
                         "".join(row("<strong>" + esc(y.get("rule", "—")) + "</strong><br><span style='font-size:11px;color:#888'>[" +
                                     esc(y.get("severity", "—")) + "] " + esc(y.get("description", "")) + "</span>",
                                     "red" if y.get("severity") in ("CRITICAL", "HIGH") else "amber")
                                 for y in yara_m)))

    # ── File details ──
    fd  = row("SHA256: " + esc(hashes.get("sha256", "—")), "blue")
    fd += row("MD5: " + esc(hashes.get("md5", "—")) + " · SHA1: " + esc(hashes.get("sha1", "—")), "blue")
    fd += row("Entropy: " + esc(entropy), "blue")
    parts.append(section("📄 File Details", fd))

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>TotalWare Report — {filename}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,'Segoe UI',sans-serif;background:#fff;color:#1a1a1a;padding:2rem}}
.container{{max-width:860px;margin:0 auto}}
.header{{display:flex;align-items:center;gap:14px;padding-bottom:1.5rem;border-bottom:3px solid {vc};margin-bottom:2rem}}
.logo{{font-size:28px;font-weight:800}}.logo span{{color:#E02020}}
.meta{{margin-left:auto;text-align:right;font-size:12px;color:#888}}
.verdict{{background:#F8F8F8;border:2px solid #EEE;border-radius:12px;padding:1.25rem 1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:16px}}
.vt{{font-size:20px;font-weight:700;color:{vc}}}.vs{{font-size:13px;color:#888;margin-top:4px}}
.sc{{width:64px;height:64px;border-radius:50%;background:{vc};color:#fff;display:flex;flex-direction:column;align-items:center;justify-content:center;margin-left:auto;flex-shrink:0}}
.sc .n{{font-size:22px;font-weight:800;line-height:1}}.sc .l{{font-size:9px;opacity:.85}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:1.5rem}}
.stat{{background:#F8F8F8;border-radius:10px;padding:1rem;text-align:center;border:1px solid #EEE}}
.stat .v{{font-size:26px;font-weight:700;color:{vc}}}.stat .l{{font-size:11px;color:#888;margin-top:3px}}
.section{{border:1px solid #EEE;border-radius:10px;margin-bottom:1rem;overflow:hidden}}
.sh{{background:#F8F8F8;padding:11px 16px;border-bottom:1px solid #EEE;font-size:14px;font-weight:600}}
.sb{{padding:12px 16px}}
.row{{display:flex;align-items:flex-start;gap:8px;padding:7px 0;border-bottom:1px solid #F0F0F0;font-size:13px;word-break:break-all}}
.row:last-child{{border:none}}
.dot{{width:8px;height:8px;border-radius:50%;background:#E02020;flex-shrink:0;margin-top:4px}}
.dot.amber{{background:#CC7700}}.dot.green{{background:#1A8A1A}}.dot.blue{{background:#2277CC}}
.footer{{text-align:center;font-size:11px;color:#BBB;padding-top:1.5rem;border-top:1px solid #EEE;margin-top:2rem}}
.footer span{{color:#E02020;font-weight:600}}
</style></head><body>
<div class="container">
  <div class="header">
    <div class="logo">Total<span>Ware</span></div>
    <div class="meta"><div>Generated: {now}</div><div>{filename}</div></div>
  </div>
  <div class="verdict">
    <div><div class="vt">{verdict} — Score: {score}/100</div>
    <div class="vs">{filename} · SHA256: {hashes.get('sha256','—')[:24]}...</div></div>
    <div class="sc"><div class="n">{score}</div><div class="l">RISK</div></div>
  </div>
  <div class="stats">
    <div class="stat"><div class="v">{vt_det}</div><div class="l">Engines Detected</div></div>
    <div class="stat"><div class="v">{len(perms)}</div><div class="l">Dangerous Perms</div></div>
    <div class="stat"><div class="v">{len(iocs)}</div><div class="l">IOCs Found</div></div>
    <div class="stat"><div class="v">{len(yara_m)}</div><div class="l">YARA Matches</div></div>
  </div>
  {"".join(parts)}
  <div class="footer">Generated by <span>TotalWare</span> — Universal Malware Analysis Platform</div>
</div></body></html>"""

    buf = io.BytesIO(html.encode('utf-8'))
    buf.seek(0)
    return send_file(buf, mimetype='text/html', as_attachment=True,
                     download_name=f'TotalWare_Report_{filename}.html')


# ── Scan History (Phase E) — only the logged-in user's own scans ──
@app.route('/history')
def history_page():
    return render_template('history.html')


@app.route('/api/history')
def api_history():
    if not current_user.is_authenticated:
        return jsonify({"auth_required": True,
                        "stats": {"total": 0, "malicious": 0, "clean": 0},
                        "scans": []})
    uid = current_user.id
    search  = request.args.get('search')
    verdict = request.args.get('verdict')
    # Guard against non-numeric query params (e.g. ?limit=abc) so they don't 500
    try:
        limit = min(max(int(request.args.get('limit', 100)), 1), 500)
    except (TypeError, ValueError):
        limit = 100
    try:
        offset = max(int(request.args.get('offset', 0)), 0)
    except (TypeError, ValueError):
        offset = 0
    return jsonify({
        "stats": get_stats(user_id=uid),
        "scans": list_scans(limit=limit, offset=offset, search=search, verdict=verdict, user_id=uid),
    })


@app.route('/api/scan/<int:scan_id>')
def api_get_scan(scan_id):
    uid = current_user.id if current_user.is_authenticated else None
    data = get_scan(scan_id, user_id=uid)
    if not data:
        return jsonify({"error": "Scan not found"}), 404
    return jsonify(data)


@app.route('/api/scan/<int:scan_id>', methods=['DELETE'])
def api_delete_scan(scan_id):
    uid = current_user.id if current_user.is_authenticated else None
    ok = delete_scan(scan_id, user_id=uid)
    return jsonify({"deleted": ok}), (200 if ok else 404)


@app.route('/api/scan/<int:scan_id>', methods=['PATCH'])
def api_update_scan(scan_id):
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required"}), 401
    payload = request.get_json() or {}
    ok = update_scan_result(scan_id, payload, user_id=current_user.id)
    return jsonify({"updated": ok}), (200 if ok else 404)


# ── Auth routes (Phase E — Step 2) ──────────────────
@app.route('/login')
def login_page():
    return render_template('login.html')


@app.route('/signup')
def signup_page():
    return render_template('signup.html')


@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json() or {}
    ok, res = create_user(data.get('username'), data.get('email'), data.get('password'))
    if not ok:
        return jsonify({"ok": False, "error": res}), 400
    login_user(get_user_by_id(res['id']))
    return jsonify({"ok": True, "user": res})


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    u = verify_login(data.get('identifier'), data.get('password'))
    if not u:
        return jsonify({"ok": False, "error": "Incorrect username/email or password"}), 401
    login_user(get_user_by_id(u['id']))
    return jsonify({"ok": True, "user": u})


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/api/me')
def api_me():
    if current_user.is_authenticated:
        return jsonify({"user": {"id": current_user.id,
                                 "username": current_user.username,
                                 "email": current_user.email}})
    return jsonify({"user": None})


# ── Community voting (Phase F) ──
@app.route('/api/votes/<sha256>')
def api_votes(sha256):
    uid = current_user.id if current_user.is_authenticated else None
    return jsonify(get_vote_summary(sha256, uid))


@app.route('/api/vote', methods=['POST'])
def api_vote():
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required to vote"}), 401
    data = request.get_json() or {}
    sha256 = data.get("sha256")
    vote = data.get("vote")
    if not sha256 or vote not in (1, -1):
        return jsonify({"error": "sha256 and vote (1 or -1) required"}), 400
    return jsonify(cast_vote(current_user.id, sha256, vote))


@app.route('/feed')
def feed_page():
    return render_template('feed.html')


@app.route('/api/feed')
def api_feed():
    return jsonify({"feed": community_feed(limit=50)})


# ── Organizations (Phase F) ──
@app.route('/organizations')
def organizations_page():
    return render_template('orgs.html')


@app.route('/api/orgs', methods=['GET'])
def api_orgs_list():
    if not current_user.is_authenticated:
        return jsonify({"auth_required": True, "orgs": []}), 401
    return jsonify({"orgs": get_user_orgs(current_user.id)})


@app.route('/api/orgs', methods=['POST'])
def api_orgs_create():
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    org, err = create_org(current_user.id, data.get("name"))
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"org": org})


@app.route('/api/orgs/join', methods=['POST'])
def api_orgs_join():
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    org, err = join_org(current_user.id, data.get("invite_code"))
    if err:
        return jsonify({"error": err}), 400
    return jsonify({"org": org})


@app.route('/api/org/<int:org_id>')
def api_org_dashboard(org_id):
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required"}), 401
    data = get_org_dashboard(org_id, current_user.id)
    if not data:
        return jsonify({"error": "Not found or access denied"}), 404
    return jsonify(data)


# ── API Key management (Phase E — Step 3) ──────────────
@app.route('/account')
def account_page():
    return render_template('apikeys.html')


@app.route('/docs')
def docs_page():
    return render_template('docs.html')


@app.route('/api/keys', methods=['GET'])
def api_keys_list():
    if not current_user.is_authenticated:
        return jsonify({"auth_required": True, "keys": []}), 401
    return jsonify({"keys": list_api_keys(current_user.id)})


@app.route('/api/keys', methods=['POST'])
def api_keys_create():
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required"}), 401
    data = request.get_json() or {}
    return jsonify(create_api_key(current_user.id, data.get("name", "default")))


@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
def api_keys_revoke(key_id):
    if not current_user.is_authenticated:
        return jsonify({"error": "Login required"}), 401
    ok = revoke_api_key(key_id, current_user.id)
    return jsonify({"revoked": ok}), (200 if ok else 404)


if __name__ == '__main__':
    app.run(debug=True)
