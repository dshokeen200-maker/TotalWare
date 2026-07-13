"""relationship_graph.py — node-link graph of file <-> IOCs <-> similar samples (vis-network)."""
from urllib.parse import urlparse


def build_graph(data):
    nodes, edges, seen = [], [], set()

    def add_node(nid, label, group, title=None):
        if nid in seen:
            return
        seen.add(nid)
        n = {"id": nid, "label": label, "group": group}
        if title:
            n["title"] = title
        nodes.append(n)

    def add_edge(a, b, label):
        edges.append({"from": a, "to": b, "label": label})

    # 1. Center node — file
    fname = data.get("filename", "file")
    verdict = (data.get("risk_assessment", {}) or {}).get("verdict", "")
    add_node("file", fname, "file", title=f"{fname} — {verdict}")

    # 2. IPs (colour-grouped by threat-intel verdict)
    for r in (data.get("ip_intelligence", {}) or {}).get("results", []):
        ip = r.get("ip")
        if not ip:
            continue
        v = r.get("overall_verdict", "CLEAN")
        grp = "ip_bad" if v == "MALICIOUS" else "ip_sus" if v == "SUSPICIOUS" else "ip"
        add_node(ip, ip, grp, title=f"{ip} — {v}")
        add_edge("file", ip, "contacts")

    # 3. Domains / URLs (extracting the host)
    urls = list((data.get("strings", {}) or {}).get("urls", []))
    apk = data.get("apk_analysis", {}) or {}
    urls += (apk.get("network", {}) or {}).get("urls_found", [])
    for u in set(urls):
        try:
            host = urlparse(u).netloc or u
        except Exception:
            host = u
        if not host:
            continue
        nid = "dom:" + host
        add_node(nid, host, "domain", title=u)
        add_edge("file", nid, "connects")

    # 4. Suspicious behaviours (dropper / shell)
    for a in (apk.get("suspicious_apis", {}) or {}).get("apis", []):
        b = a.get("behavior")
        if b in ("Dynamic Code Loading", "Shell Execution", "SMS Sending"):
            nid = "beh:" + b
            add_node(nid, b, "behavior")
            add_edge("file", nid, "uses")

    # 5. Similar known sample (fuzzy hash)
    fz = data.get("fuzzy_hash", {}) or {}
    if fz.get("is_variant") and fz.get("best_match"):
        bm = fz["best_match"]
        nid = "sample:" + str(bm.get("name"))
        add_node(nid, bm.get("name"), "sample", title=f"{bm.get('similarity')}% similar")
        add_edge("file", nid, f"{bm.get('similarity')}% similar")

    # 6. Malware family (MalwareBazaar)
    mb = data.get("malwarebazaar", {}) or {}
    if mb.get("found") and mb.get("signature"):
        nid = "fam:" + str(mb["signature"])
        add_node(nid, mb["signature"], "family", title="MalwareBazaar family")
        add_edge("file", nid, "family")

    return {"nodes": nodes, "edges": edges, "total_nodes": len(nodes), "total_edges": len(edges)}