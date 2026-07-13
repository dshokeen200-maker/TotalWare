from oletools.olevba import VBA_Parser


def analyze_office(file_path):
    try:
        vba = VBA_Parser(file_path)
        has_macros = vba.detect_vba_macros()

        auto_exec = []      # macros that run as soon as the file is opened
        suspicious = []     # dangerous calls (Shell, powershell, etc.)
        iocs = []           # embedded URLs/IPs
        red_flags = []

        if has_macros:
            for kw_type, keyword, description in vba.analyze_macros():
                item = {"keyword": keyword, "description": description}
                if kw_type == "AutoExec":
                    auto_exec.append(item)
                elif kw_type == "Suspicious":
                    suspicious.append(item)
                elif kw_type == "IOC":
                    iocs.append(item)

            if auto_exec:
                red_flags.append(f"Auto-executing macros: {', '.join(a['keyword'] for a in auto_exec)}")
            if suspicious:
                red_flags.append(f"Suspicious macro calls: {', '.join(s['keyword'] for s in suspicious)}")

        vba.close()
        return {
            "has_macros": bool(has_macros),
            "auto_exec": auto_exec,
            "suspicious": suspicious,
            "iocs": iocs,
            "red_flags": red_flags,
        }
    except Exception as e:
        return {"error": str(e)}