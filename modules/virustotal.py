import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {
    "x-apikey": API_KEY
}
def check_hash(sha256):
    """Check if hash is already known to VirusTotal"""
    try:
        url = f"{BASE_URL}/files/{sha256}"
        response = requests.get(url, headers=HEADERS)

        if response.status_code == 200:
            data = response.json()
            attrs = data["data"]["attributes"]

            stats = attrs.get("last_analysis_stats", {})
            results = attrs.get("last_analysis_results", {})

            # Get malicious engines
            malicious_engines = []
            suspicious_engines = []
            for engine, result in results.items():
                if result["category"] == "malicious":
                    malicious_engines.append({
                        "engine": engine,
                        "result": result.get("result", "malicious")
                    })
                elif result["category"] == "suspicious":
                    suspicious_engines.append({
                        "engine": engine,
                        "result": result.get("result", "suspicious")
                    })

            total_engines = sum(stats.values())
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            if malicious_count >= 10:
                verdict = "MALICIOUS"
            elif malicious_count >= 3:
                verdict = "SUSPICIOUS"
            elif malicious_count >= 1:
                verdict = "POTENTIALLY UNWANTED"
            else:
                verdict = "CLEAN"

            return {
                "found": True,
                "stats": {
                    "malicious": malicious_count,
                    "suspicious": suspicious_count,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_engines": total_engines
                },
                "verdict": verdict,
                "malicious_engines": malicious_engines[:10],
                "suspicious_engines": suspicious_engines[:5],
                "permalink": f"https://www.virustotal.com/gui/file/{sha256}"
            }

        elif response.status_code == 404:
            return {
                "found": False,
                "message": "File not found in VirusTotal database — never scanned before"
            }
        else:
            return {
                "found": False,
                "message": f"VirusTotal API error: {response.status_code}"
            }

    except Exception as e:
        return {"error": str(e)}


def upload_and_scan(file_path, sha256):
    """Upload file to VirusTotal and get results"""
    try:
        # First check if already exists
        existing = check_hash(sha256)
        if existing.get("found"):
            return existing

        # Upload file
        upload_url = f"{BASE_URL}/files"
        with open(file_path, 'rb') as f:
            files = {"file": f}
            response = requests.post(upload_url, headers=HEADERS, files=files)

        if response.status_code != 200:
            return {"error": f"Upload failed: {response.status_code}"}

        analysis_id = response.json()["data"]["id"]

        # Wait for analysis
        analysis_url = f"{BASE_URL}/analyses/{analysis_id}"
        for i in range(12):
            time.sleep(10)
            result = requests.get(analysis_url, headers=HEADERS).json()
            status = result["data"]["attributes"]["status"]
            if status == "completed":
                # Now fetch full file report
                return check_hash(sha256)

        return {"error": "Analysis timed out — try again in few minutes"}

    except Exception as e:
        return {"error": str(e)}