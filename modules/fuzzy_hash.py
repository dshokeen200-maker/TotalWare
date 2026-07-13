import ppdeep
import json
import os

KNOWN_DB = "known_hashes.json"   # known malware ke fuzzy hashes


def _load_known():
    if os.path.exists(KNOWN_DB):
        with open(KNOWN_DB) as f:
            return json.load(f)
    return {}


def compute_fuzzy(file_path):
    with open(file_path, "rb") as f:
        return ppdeep.hash(f.read())


def analyze_fuzzy(file_path):
    try:
        fuzzy = compute_fuzzy(file_path)
        known = _load_known()
        best = {"name": None, "similarity": 0}
        for name, h in known.items():
            sim = ppdeep.compare(fuzzy, h)   # 0–100 similarity
            if sim > best["similarity"]:
                best = {"name": name, "similarity": sim}
        return {
            "fuzzy_hash": fuzzy,
            "best_match": best if best["name"] else None,
            "is_variant": best["similarity"] >= 50,
        }
    except Exception as e:
        return {"error": str(e)}