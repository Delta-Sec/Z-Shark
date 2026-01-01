from typing import List
import math
from scapy.all import Packet, DNS
from loguru import logger

from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, ModelConfig, WindowStats

class DNSAnomalyDetector(BaseDetectionModel):

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.entropy_threshold = float(self.config.params.get('entropy_threshold', 3.8))

    def _calculate_char_entropy(self, text: str) -> float:
        if not text:
            return 0.0
        text_len = len(text)
        counts = {}
        for char in text:
            counts[char] = counts.get(char, 0) + 1
        
        entropy = 0.0
        for count in counts.values():
            p = count / text_len
            entropy -= p * math.log2(p)
        return entropy

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        seen_domains = set()

        for packet in window_packets:
            try:
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    qr = packet.getlayer(DNS)
                    if qr.qd is not None:
                        raw_qname = getattr(qr.qd, "qname", None)
                        if raw_qname:
                            if isinstance(raw_qname, bytes):
                                qname = raw_qname.decode("utf-8", errors="ignore").rstrip(".")
                            else:
                                qname = str(raw_qname).rstrip(".")
                            
                            parts = qname.split(".")
                            if len(parts) >= 2:
                                domain_label = parts[-2]
                            else:
                                domain_label = parts[0]

                            if domain_label in seen_domains:
                                continue
                            seen_domains.add(domain_label)

                            if len(domain_label) < 5:
                                continue

                            entropy = self._calculate_char_entropy(domain_label)
                            
                            
                            if entropy > self.entropy_threshold:
                                detections.append(Detection(
                                    model_name=self.model_name,
                                    timestamp=getattr(window_stats, "end_time", None),
                                    severity=min(1.0, entropy / 5.0),
                                    score=entropy,
                                    label="DNS High Entropy (DGA Suspect)",
                                    justification=f"Domain '{qname}' has high character entropy ({entropy:.2f}), suggesting algorithmic generation.",
                                    evidence={"domain": qname, "entropy": entropy, "threshold": self.entropy_threshold}
                                ))
            except Exception as e:
                continue

        return detections
