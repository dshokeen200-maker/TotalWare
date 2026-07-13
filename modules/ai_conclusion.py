import os
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))

def generate_ai_conclusion(scan_data: dict) -> str:
    try:
        filename   = scan_data.get("filename", "unknown")
        entropy    = scan_data.get("entropy", {}).get("score", 0)
        yara       = scan_data.get("yara_scan", {}).get("matches", [])
        strings    = scan_data.get("strings", {})
        urls       = strings.get("urls", [])
        ips        = strings.get("ips", [])
        keywords   = strings.get("suspicious_keywords", [])
        vt         = scan_data.get("virustotal", {})
        vt_det     = vt.get("stats", {}).get("malicious", 0)
        vt_total   = vt.get("stats", {}).get("total_engines", 75)
        apk        = scan_data.get("apk_analysis", {})
        perms      = apk.get("permissions", {}).get("dangerous_permissions", [])
        score      = scan_data.get("risk_assessment", {}).get("final_score", 0)

        prompt = f"""You are TotalWare, an expert malware analyst AI. Analyze this scan result and give a clear security conclusion.

File: {filename}
Risk Score: {score}/100
Entropy: {entropy}
VirusTotal: {vt_det}/{vt_total} engines detected malware
YARA Rules Matched: {len(yara)} ({', '.join([y['rule'] for y in yara[:3]])})
Dangerous Permissions: {len(perms)} ({', '.join([p.replace('android.permission.','') for p in perms[:5]])})
Suspicious URLs: {', '.join(urls[:4])}
Suspicious IPs: {', '.join(ips[:4])}
Suspicious Keywords: {', '.join(keywords[:8])}

Write a professional 3-4 sentence security conclusion explaining:
1. What this file likely is (malware type/family)
2. What it does (based on permissions, URLs, strings)
3. How dangerous it is and victim risks
4. Recommendation

Be specific and technical. Paragraph form only — no bullet points."""

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.4,
        )
        return response.choices[0].message.content

    except Exception as e:
        # Log the real error to the terminal (for debugging),
        # but show the user a clean message — not a raw error dump.
        print("AI conclusion error:", e)
        return "AI summary temporarily unavailable — automated rule-based analysis above is complete and reliable."