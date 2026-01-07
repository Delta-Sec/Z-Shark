from typing import List, Dict, Set
from collections import defaultdict
from datetime import datetime
from scapy.all import Packet, IP, TCP, UDP
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, WindowStats, ModelConfig

class PortScanDetector(BaseDetectionModel):
    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.min_unique_ports = self.config.params.get("min_unique_ports", 10)
        self.min_packets = self.config.params.get("min_packets", 5)
        self.scan_history: Dict[str, Set[int]] = defaultdict(set)
        self.last_seen: Dict[str, float] = {}

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        
        try:
            current_ts = datetime.fromisoformat(window_stats.end_time).timestamp()
        except:
            current_ts = datetime.now().timestamp()

        for pkt in window_packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_port = None
                if TCP in pkt:
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    dst_port = pkt[UDP].dport
                
                if dst_port is not None:
                    self.scan_history[src_ip].add(dst_port)
                    self.last_seen[src_ip] = current_ts

        for src_ip in list(self.scan_history.keys()):
            ports = self.scan_history[src_ip]
            last_seen_time = self.last_seen.get(src_ip, 0)

            if current_ts - last_seen_time > 300:
                del self.scan_history[src_ip]
                if src_ip in self.last_seen: del self.last_seen[src_ip]
                continue

            unique_ports_count = len(ports)
            

            if unique_ports_count >= self.min_unique_ports:
                score = unique_ports_count
                severity = min(1.0, (unique_ports_count - self.min_unique_ports) / 20.0)
                detections.append(Detection(
                    engine_name=self.engine_name,
                    timestamp=window_stats.end_time,
                    severity=severity,
                    score=score,
                    label="Port Scan Suspect (Stateful)",
                    justification=f"Source IP {src_ip} accessed {unique_ports_count} unique ports over time.",
                    evidence={"source_ip": src_ip, "unique_ports": unique_ports_count}
                ))
                self.scan_history[src_ip].clear()

        return detections
