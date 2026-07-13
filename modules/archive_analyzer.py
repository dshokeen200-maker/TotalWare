import zipfile
import py7zr
import rarfile
import os
import shutil
import tempfile
import hashlib
import math
import re

def get_entropy(data):
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

def get_file_hashes(data):
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest()
    }

def analyze_archive(file_path, password=None):
    try:
        ext = os.path.splitext(file_path)[1].lower()
        temp_dir = tempfile.mkdtemp()
        file_list = []
        is_password_protected = False

        # ── Extract based on type ──────────────────
        try:
            if ext == '.zip':
                with zipfile.ZipFile(file_path, 'r') as z:
                    try:
                        z.extractall(temp_dir)
                    except RuntimeError:
                        is_password_protected = True
                    file_list = z.namelist()

            elif ext == '.7z':
                with py7zr.SevenZipFile(file_path, mode='r') as z:
                    try:
                        z.extractall(path=temp_dir)
                    except Exception:
                        is_password_protected = True
                    file_list = z.getnames()

            elif ext in ['.rar']:
                with rarfile.RarFile(file_path) as z:
                    try:
                        z.extractall(temp_dir)
                    except Exception:
                        is_password_protected = True
                    file_list = z.namelist()

        except Exception as e:
            return {"error": f"Could not open archive: {str(e)}"}

        # ── Analyze each extracted file ────────────
        analyzed_files = []
        suspicious_files = []
        dangerous_extensions = [
            '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs',
            '.js', '.jar', '.apk', '.sys', '.scr', '.com',
            '.pif', '.msi', '.reg', '.hta', '.wsf'
        ]

        for root, dirs, files in os.walk(temp_dir):
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read()

                    file_ext = os.path.splitext(fname)[1].lower()
                    entropy = get_entropy(data)
                    hashes = get_file_hashes(data)
                    size = len(data)

                    # String extraction
                    ascii_strings = re.findall(b'[\x20-\x7e]{4,}', data)
                    readable = [s.decode('ascii', errors='ignore') for s in ascii_strings]
                    urls = []
                    ips = []
                    for s in readable:
                        urls.extend(re.findall(r'https?://[^\s\'"<>]+', s))
                        ips.extend(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', s))

                    is_suspicious = (
                        file_ext in dangerous_extensions or
                        entropy > 7.0
                    )

                    file_info = {
                        "filename": fname,
                        "extension": file_ext,
                        "size_bytes": size,
                        "entropy": entropy,
                        "hashes": hashes,
                        "urls_found": list(set(urls)),
                        "ips_found": list(set(ips)),
                        "suspicious": is_suspicious,
                        "reason": []
                    }

                    if file_ext in dangerous_extensions:
                        file_info["reason"].append(f"Dangerous file type: {file_ext}")
                    if entropy > 7.0:
                        file_info["reason"].append(f"High entropy: {entropy}")

                    analyzed_files.append(file_info)

                    if is_suspicious:
                        suspicious_files.append(fname)

                except Exception:
                    continue

        # Cleanup
        shutil.rmtree(temp_dir)

        # ── Summary ────────────────────────────────
        total_files = len(analyzed_files)
        total_suspicious = len(suspicious_files)

        if total_suspicious >= 3:
            verdict = "MALICIOUS"
            risk_score = 90
        elif total_suspicious >= 1:
            verdict = "SUSPICIOUS"
            risk_score = 60
        else:
            verdict = "CLEAN"
            risk_score = 10

        return {
            "archive_info": {
                "total_files": total_files,
                "total_suspicious": total_suspicious,
                "password_protected": is_password_protected,
                "verdict": verdict,
                "risk_score": risk_score
            },
            "files": analyzed_files,
            "suspicious_files": suspicious_files
        }

    except Exception as e:
        return {"error": str(e)}