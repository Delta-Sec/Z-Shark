from typing import List, Dict, Any
from collections import deque
from scapy.all import Packet
import numpy as np
from loguru import logger

from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, ModelConfig, WindowStats

class DDoSDetector(BaseDetectionModel):

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.history_size = int(self.config.params.get("history_size", 5))
        self.pps_history = deque(maxlen=self.history_size)
        self.entropy_history = deque(maxlen=self.history_size)

        default_pps = float(self.config.params.get("default_pps", 10.0))
        default_entropy = float(self.config.params.get("default_entropy", 5.0))
        for _ in range(self.history_size):
            self.pps_history.append(default_pps)
            self.entropy_history.append(default_entropy)

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:

        try:
            curr_pps = float(getattr(window_stats, "pps", 0.0))
        except Exception:
            curr_pps = 0.0

        try:
            curr_entropy = float(getattr(window_stats, "src_ip_entropy", 0.0))
        except Exception:
            curr_entropy = 0.0

        self.pps_history.append(curr_pps)
        self.entropy_history.append(curr_entropy)

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []

        current_pps = float(getattr(window_stats, "pps", 0.0))
        current_entropy = float(getattr(window_stats, "src_ip_entropy", 0.0))

        pps_array = np.array(self.pps_history, dtype=float)
        mean_pps = float(np.mean(pps_array)) if pps_array.size > 0 else 0.0
        std_pps = float(np.std(pps_array)) if pps_array.size > 0 else 0.0
        if std_pps == 0.0:
            std_pps = 1.0

        pps_z_score = (current_pps - mean_pps) / std_pps
        pps_threshold = float(self.config.params.get("pps_z_threshold", 5.0))

        if pps_z_score > pps_threshold:
            severity = min(1.0, (pps_z_score - pps_threshold) / max(pps_threshold, 1.0))
            detections.append(Detection(
                model_name=self.model_name,
                timestamp=getattr(window_stats, "end_time", None),
                severity=severity,
                score=pps_z_score,
                label="High Volume Anomaly (DDoS Suspect)",
                justification=f"PPS Z-score {pps_z_score:.2f} exceeds threshold {pps_threshold:.2f}.",
                evidence={"current_pps": current_pps, "mean_pps": mean_pps, "pps_z_score": pps_z_score}
            ))

        entropy_array = np.array(self.entropy_history, dtype=float)
        mean_entropy = float(np.mean(entropy_array)) if entropy_array.size > 0 else 0.0
        entropy_drop_ratio = float(self.config.params.get("entropy_drop_ratio", 0.5))

        if current_entropy > 0 and mean_entropy > 0 and current_entropy < mean_entropy * entropy_drop_ratio:
            severity = min(1.0, (mean_entropy - current_entropy) / mean_entropy)
            detections.append(Detection(
                model_name=self.model_name,
                timestamp=getattr(window_stats, "end_time", None),
                severity=severity,
                score=current_entropy,
                label="Source IP Entropy Collapse (DDoS Suspect)",
                justification=(f"Source IP entropy dropped to {current_entropy:.2f}, "
                               f"{(mean_entropy - current_entropy) / mean_entropy * 100:.1f}% below mean {mean_entropy:.2f}."),
                evidence={"current_entropy": current_entropy, "mean_entropy": mean_entropy}
            ))

        self.update_baseline(window_stats, window_packets)
        return detections
