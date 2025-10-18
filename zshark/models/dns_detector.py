from typing import List, Dict, Any
from collections import deque
from scapy.all import Packet, DNS, DNSQR
import math
from loguru import logger

from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, ModelConfig, WindowStats

class DNSAnomalyDetector(BaseDetectionModel):

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.history_size = int(self.config.params.get('history_size', 100))
        self.entropy_threshold = float(self.config.params.get('entropy_threshold', 3.5))
        self.domain_lengths = deque(maxlen=self.history_size)

    def _calculate_entropy(self, data: List[int]) -> float:
        if not data:
            return 0.0
        counts: Dict[int, int] = {}
        for x in data:
            counts[x] = counts.get(x, 0) + 1
        total = len(data)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        new_lengths: List[int] = []

        for packet in window_packets:
            try:
                if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
                    qr = packet.getlayer(DNS)
                    if qr.qd is not None:
                        q = qr.qd
                        raw_qname = getattr(q, "qname", None)
                        if raw_qname:
                            if isinstance(raw_qname, bytes):
                                qname = raw_qname.decode("utf-8", errors="ignore").rstrip(".")
                            else:
                                qname = str(raw_qname).rstrip(".")
                            parts = qname.split(".")
                            if len(parts) >= 1 and parts[0]:
                                domain_label = parts[0]
                                new_lengths.append(len(domain_label))
            except Exception:
                continue

        if not new_lengths:
            return detections

        self.domain_lengths.extend(new_lengths)

        current_entropy = self._calculate_entropy(list(self.domain_lengths))
        logger.debug(f"{self.model_name} current_entropy={current_entropy:.3f}")

        if len(self.domain_lengths) >= self.history_size and current_entropy < self.entropy_threshold:
            score = max(0.0, 1.0 - (current_entropy / (self.entropy_threshold or 1.0)))
            detections.append(Detection(
                model_name=self.model_name,
                timestamp=getattr(window_stats, "end_time", None),
                severity=min(1.0, score),
                score=score,
                label="DNS Low Entropy Anomaly (DGA Suspect)",
                justification=(f"Domain-length entropy {current_entropy:.3f} below threshold {self.entropy_threshold:.3f}."),
                evidence={"current_entropy": current_entropy, "threshold": self.entropy_threshold}
            ))

        return detections
