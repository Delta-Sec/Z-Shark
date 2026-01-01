from typing import List, Dict
from collections import defaultdict
from scapy.all import Packet, ARP
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, WindowStats, ModelConfig
import time
from datetime import datetime

class ARPSpoofDetector(BaseDetectionModel):
    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.ip_mac_map: Dict[str, str] = {}
        self.last_seen: Dict[str, float] = {}
        self.max_gratuitous_arp = self.config.params.get("max_gratuitous_arp_per_window", 5)

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        gratuitous_arp_count: Dict[str, int] = defaultdict(int)

        try:
            current_ts = float(datetime.fromisoformat(window_stats.end_time).timestamp())
        except:
            current_ts = time.time()

        for pkt in window_packets:
            if ARP not in pkt:
                continue

            sender_ip = pkt[ARP].psrc
            sender_mac = pkt[ARP].hwsrc
            op_code = pkt[ARP].op

            self.last_seen[sender_ip] = current_ts

            if sender_ip in self.ip_mac_map:
                known_mac = self.ip_mac_map[sender_ip]
                if known_mac != sender_mac:
                    detections.append(Detection(
                        model_name=self.model_name,
                        timestamp=getattr(window_stats, "end_time", None),
                        severity=1.0,
                        score=1.0,
                        label="ARP Spoofing Detected (MAC Conflict)",
                        justification=f"IP {sender_ip} changed MAC from {known_mac} to {sender_mac}.",
                        evidence={"ip": sender_ip, "old_mac": known_mac, "new_mac": sender_mac}
                    ))
                   
                    self.ip_mac_map[sender_ip] = sender_mac 
            else:
                self.ip_mac_map[sender_ip] = sender_mac

            if op_code == 2 and sender_ip == pkt[ARP].pdst:
                gratuitous_arp_count[sender_ip] += 1
       
        for ip, count in gratuitous_arp_count.items():
            if count > self.max_gratuitous_arp:
                detections.append(Detection(
                    model_name=self.model_name,
                    timestamp=getattr(window_stats, "end_time", None),
                    severity=min(1.0, (count - self.max_gratuitous_arp)/5.0),
                    score=count,
                    label="Excessive Gratuitous ARP",
                    justification=f"IP {ip} sent {count} gratuitous ARPs.",
                    evidence={"ip": ip, "count": count}
                ))

        cleanup_threshold = 600
        expired_ips = [ip for ip, ts in self.last_seen.items() if current_ts - ts > cleanup_threshold]
        for ip in expired_ips:
            if ip in self.ip_mac_map: del self.ip_mac_map[ip]
            if ip in self.last_seen: del self.last_seen[ip]

        return detections

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass
