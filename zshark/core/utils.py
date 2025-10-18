import math
from typing import Dict, Any, Optional
from scapy.all import Packet, IP, TCP, UDP
from datetime import datetime

def get_flow_key(pkt: Packet) -> Optional[str]:

    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        proto = pkt[IP].proto

        src_port = None
        dst_port = None

        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport

        if src_ip < dst_ip:
            ip_pair = f"{src_ip}-{dst_ip}"
            port_pair = f"{src_port}-{dst_port}"
        elif src_ip > dst_ip:
            ip_pair = f"{dst_ip}-{src_ip}"
            port_pair = f"{dst_port}-{src_port}"
        else:
            ip_pair = f"{src_ip}-{dst_ip}"
            port_pair = f"{src_port}-{dst_port}"

        return f"{ip_pair}:{port_pair}:{proto}"
    return None

def shannon_entropy(data: list) -> float:
    if not data:
        return 0.0

    counts: Dict[Any, int] = {}
    for item in data:
        counts[item] = counts.get(item, 0) + 1

    total = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        entropy -= probability * math.log2(probability)

    return entropy

def calculate_window_stats(window_packets: list) -> Dict[str, Any]:

    if not window_packets:
        return {}

    start_time = float(window_packets[0].time)
    end_time = float(window_packets[-1].time)
    duration = end_time - start_time if end_time > start_time else 1e-6

    stats = {
        "start_time": datetime.fromtimestamp(start_time),
        "end_time": datetime.fromtimestamp(end_time),
        "duration_s": duration,
        "packet_count": len(window_packets),
        "total_bytes": sum(len(pkt) for pkt in window_packets),
        "pps": len(window_packets) / duration,
        "bps": sum(len(pkt) for pkt in window_packets) * 8 / duration,
    }

    src_ips = []
    dst_ips = []
    dst_ports = []
    inter_arrival_times = []

    prev_time = start_time
    for pkt in window_packets:
        if IP in pkt:
            src_ips.append(pkt[IP].src)
            dst_ips.append(pkt[IP].dst)

        if TCP in pkt:
            dst_ports.append(pkt[TCP].dport)
        elif UDP in pkt:
            dst_ports.append(pkt[UDP].dport)

        inter_arrival_times.append(float(pkt.time) - prev_time)
        prev_time = float(pkt.time)

    stats["src_ip_entropy"] = shannon_entropy(src_ips)
    stats["dst_ip_entropy"] = shannon_entropy(dst_ips)
    stats["dst_port_entropy"] = shannon_entropy(dst_ports)
    stats["inter_arrival_times"] = inter_arrival_times

    return stats
