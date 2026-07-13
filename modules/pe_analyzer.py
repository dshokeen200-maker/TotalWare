import pefile
import math
import os

def get_section_entropy(data):
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

def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)

        # ── Basic Info ─────────────────────────────
        machine_types = {
            0x14c: "x86 (32-bit)",
            0x8664: "x64 (64-bit)",
            0x1c0: "ARM",
            0xaa64: "ARM64"
        }
        machine = machine_types.get(pe.FILE_HEADER.Machine, "Unknown")

        # File type
        if pe.is_dll():
            file_type = "DLL"
        elif pe.is_exe():
            file_type = "EXE"
        elif pe.is_driver():
            file_type = "Driver"
        else:
            file_type = "Unknown PE"

        # Compile time
        import datetime
        timestamp = pe.FILE_HEADER.TimeDateStamp
        try:
            compile_time = datetime.datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S UTC')
        except:
            compile_time = "Unknown"

        # ── Sections Analysis ──────────────────────
        sections = []
        suspicious_sections = []
        for section in pe.sections:
            name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            entropy = get_section_entropy(section.get_data())
            size = section.SizeOfRawData
            virtual_size = section.Misc_VirtualSize

            section_info = {
                "name": name,
                "entropy": entropy,
                "raw_size": size,
                "virtual_size": virtual_size,
                "suspicious": entropy > 7.0
            }
            sections.append(section_info)

            if entropy > 7.0:
                suspicious_sections.append(name)

        # ── Imports Analysis ───────────────────────
        dangerous_imports = {
            # Process injection
            "CreateRemoteThread": "Process injection — can inject code into other processes",
            "VirtualAllocEx": "Memory allocation in remote process",
            "WriteProcessMemory": "Write to another process memory",
            "OpenProcess": "Open handle to another process",

            # Keylogging
            "SetWindowsHookEx": "Hooking — used for keylogging",
            "GetAsyncKeyState": "Keystate monitoring — keylogger indicator",

            # Network
            "WSAStartup": "Network activity",
            "connect": "Network connection",
            "InternetOpenUrl": "HTTP requests",
            "URLDownloadToFile": "Download files from internet",

            # Registry persistence
            "RegSetValueEx": "Registry modification — persistence mechanism",
            "RegCreateKeyEx": "Registry key creation",

            # Anti-analysis
            "IsDebuggerPresent": "Anti-debugging technique",
            "CheckRemoteDebuggerPresent": "Anti-debugging technique",
            "GetTickCount": "Timing attack — anti-sandbox",
            "Sleep": "Delay execution — anti-sandbox evasion",

            # Crypto
            "CryptEncrypt": "Encryption — possible ransomware",
            "CryptDecrypt": "Decryption",

            # Shell execution
            "ShellExecute": "Execute commands/files",
            "WinExec": "Execute programs",
            "CreateProcess": "Create new process",
        }

        found_imports = []
        found_dangerous = []

        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8', errors='ignore')
                        found_imports.append(f"{dll_name}::{func_name}")
                        if func_name in dangerous_imports:
                            found_dangerous.append({
                                "function": func_name,
                                "dll": dll_name,
                                "reason": dangerous_imports[func_name]
                            })
        except:
            pass

        # ── Packer Detection ───────────────────────
        known_packers = {
            "UPX0": "UPX Packer",
            "UPX1": "UPX Packer",
            "UPX2": "UPX Packer",
            ".aspack": "ASPack Packer",
            ".adata": "ASPack Packer",
            "MPRESS1": "MPRESS Packer",
            "MPRESS2": "MPRESS Packer",
        }

        detected_packer = None
        for section in pe.sections:
            sec_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if sec_name in known_packers:
                detected_packer = known_packers[sec_name]
                break

        # ── Risk Score ─────────────────────────────
        risk_score = 0
        risk_reasons = []

        if found_dangerous:
            risk_score += len(found_dangerous) * 10
            risk_reasons.append(f"{len(found_dangerous)} dangerous API calls found")

        if suspicious_sections:
            risk_score += 20
            risk_reasons.append(f"High entropy sections: {', '.join(suspicious_sections)}")

        if detected_packer:
            risk_score += 20
            risk_reasons.append(f"Packer detected: {detected_packer}")

        risk_score = min(risk_score, 100)

        if risk_score >= 70:
            verdict = "HIGH RISK - Likely Malicious"
        elif risk_score >= 40:
            verdict = "MEDIUM RISK - Suspicious"
        else:
            verdict = "LOW RISK - Possibly Clean"

        return {
            "basic_info": {
                "file_type": file_type,
                "architecture": machine,
                "compile_time": compile_time,
            },
            "sections": {
                "total": len(sections),
                "details": sections,
                "suspicious_sections": suspicious_sections
            },
            "imports": {
                "total_imports": len(found_imports),
                "dangerous_imports": found_dangerous,
                "total_dangerous": len(found_dangerous)
            },
            "packer": {
                "detected": detected_packer is not None,
                "name": detected_packer
            },
            "risk": {
                "score": risk_score,
                "verdict": verdict,
                "reasons": risk_reasons
            }
        }

    except Exception as e:
        return {"error": str(e)}