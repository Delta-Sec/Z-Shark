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
     
        self.max_seen_domains = 50000 
        self.seen_domains = set()

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

        if len(self.seen_domains) > self.max_seen_domains:
            self.seen_domains.clear()
            
        detections: List[Detection] = []

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
                            domain_label = ""
                            
                            if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
                              
                                domain_label = parts[-3]
                            elif len(parts) >= 2:
                                domain_label = parts[-2]
                            else:
                                domain_label = parts[0]

                            if domain_label in self.seen_domains:
                                continue
                            self.seen_domains.add(domain_label)

                            if len(domain_label) < 5:
                                continue

                            entropy = self._calculate_char_entropy(domain_label)
                            
                            if entropy > self.entropy_threshold:
                                detections.append(Detection(
                                    engine_name=self.engine_name,
                                    timestamp=getattr(window_stats, "end_time", None),
                                    severity=min(1.0, entropy / 5.0),
                                    score=entropy,
                                    label="DNS High Entropy (DGA Suspect)",
                                    justification=f"Domain '{qname}' (Label: {domain_label}) has high entropy ({entropy:.2f}).",
                                    evidence={"domain": qname, "entropy": entropy}
                                ))
            except Exception as e:
                continue

        return detections
