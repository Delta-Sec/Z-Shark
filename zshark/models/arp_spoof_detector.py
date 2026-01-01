from typing import List, Dict, Any
from collections import defaultdict
from loguru import logger
from scapy.all import Packet, ARP
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, WindowStats, ModelConfig

class ARPSpoofDetector(BaseDetectionModel):
    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.mac_ip_map: Dict[str, str] = {}
        self.ip_mac_map: Dict[str, str] = {}
        self.max_gratuitous_arp_per_window = self.config.params.get("max_gratuitous_arp_per_window", 5)

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        for pkt in window_packets:
            if ARP in pkt:
                sender_mac = pkt[ARP].hwsrc
                sender_ip = pkt[ARP].psrc
                if sender_mac and sender_ip:
                    self.mac_ip_map[sender_mac] = sender_ip
                    self.ip_mac_map[sender_ip] = sender_mac

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        gratuitous_arp_count: Dict[str, int] = defaultdict(int)

        for pkt in window_packets:
            if ARP in pkt:
                sender_mac = pkt[ARP].hwsrc
                sender_ip = pkt[ARP].psrc
                
                if pkt[ARP].op == 2 and pkt[ARP].psrc == pkt[ARP].pdst:
                    gratuitous_arp_count[sender_ip] += 1

        for ip, count in gratuitous_arp_count.items():
            if count > self.max_gratuitous_arp_per_window:
                detections.append(Detection(
                    model_name=self.model_name,
                    timestamp=window_stats.end_time,
                    severity=min(1.0, (count - self.max_gratuitous_arp_per_window)/5.0),
                    score=count,
                    label="Excessive Gratuitous ARP",
                    justification=f"IP {ip} sent {count} gratuitous ARP packets, exceeding threshold {self.max_gratuitous_arp_per_window}.",
                    evidence={"ip": ip, "count": count}
                ))

        self.update_baseline(window_stats, window_packets)
        return detections
