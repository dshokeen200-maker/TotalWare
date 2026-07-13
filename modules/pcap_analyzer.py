from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR, Raw

# Common malware / C2 ports
SUSPICIOUS_PORTS = {4444, 1337, 31337, 6666, 6667, 12345, 5555, 9001, 8080}


def analyze_pcap(file_path):
    try:
        packets = rdpcap(file_path)
        dst_ips = set()
        dns_queries = set()
        http_hosts = set()
        suspicious_ports = set()
        protocols = set()

        for pkt in packets:
            if pkt.haslayer(IP):
                dst_ips.add(pkt[IP].dst)
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                if q:
                    dns_queries.add(q)
            if pkt.haslayer(TCP):
                protocols.add("TCP")
                if pkt[TCP].dport in SUSPICIOUS_PORTS:
                    suspicious_ports.add(pkt[TCP].dport)
            if pkt.haslayer(UDP):
                protocols.add("UDP")
            if pkt.haslayer(Raw):
                payload = bytes(pkt[Raw].load)
                if b"HTTP" in payload:
                    for line in payload.split(b"\r\n"):
                        if line.lower().startswith(b"host:"):
                            http_hosts.add(line.split(b":", 1)[1].strip().decode(errors="ignore"))

        return {
            "total_packets": len(packets),
            "destination_ips": sorted(dst_ips),
            "dns_queries": sorted(dns_queries),
            "http_hosts": sorted(http_hosts),
            "suspicious_ports": sorted(suspicious_ports),
            "protocols": sorted(protocols),
        }
    except Exception as e:
        return {"error": str(e)} 