from typing import List, Dict
from collections import defaultdict
from scapy.all import Packet, IP, TCP, UDP
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, WindowStats, ModelConfig

class PortScanDetector(BaseDetectionModel):
    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.min_unique_ports = self.config.params.get("min_unique_ports", 10)
        self.min_packets = self.config.params.get("min_packets", 5)

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        unique_ports_per_source: Dict[str, Dict[int, int]] = defaultdict(lambda: defaultdict(int))

        for pkt in window_packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_port = None
                if TCP in pkt:
                    dst_port = pkt[TCP].dport
                elif UDP in pkt:
                    dst_port = pkt[UDP].dport
                if dst_port is not None:
                    unique_ports_per_source[src_ip][dst_port] += 1

        for src_ip, ports in unique_ports_per_source.items():
            unique_ports = len(ports)
            total_packets = sum(ports.values())
            if unique_ports >= self.min_unique_ports and total_packets >= self.min_packets:
                score = unique_ports
                severity = min(1.0, (unique_ports - self.min_unique_ports) / 20.0)
                detections.append(Detection(
                    model_name=self.model_name,
                    timestamp=window_stats.end_time,
                    severity=severity,
                    score=score,
                    label="Port Scan Suspect",
                    justification=f"Source IP {src_ip} accessed {unique_ports} unique ports with {total_packets} packets.",
                    evidence={"source_ip": src_ip, "unique_ports": unique_ports, "total_packets": total_packets}
                ))

        return detections
