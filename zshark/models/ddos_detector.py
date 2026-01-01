from typing import List
from collections import deque
from scapy.all import Packet
import numpy as np
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, ModelConfig, WindowStats

class DDoSDetector(BaseDetectionModel):

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.history_size = int(self.config.params.get("history_size", 100))
        self.pps_history = deque(maxlen=self.history_size)
        self.entropy_history = deque(maxlen=self.history_size)     

    def set_global_baseline(self, avg_pps: float):
        if avg_pps > 0:
            for _ in range(20):
                self.pps_history.append(avg_pps)

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
        
        self.update_baseline(window_stats, window_packets)

        current_pps = self.pps_history[-1] if self.pps_history else 0.0
        current_entropy = self.entropy_history[-1] if self.entropy_history else 0.0

        pps_list = list(self.pps_history)[:-1]
        if not pps_list: return detections
        
        pps_array = np.array(pps_list, dtype=float)
        mean_pps = float(np.mean(pps_array))
        std_pps = float(np.std(pps_array))
        
        if std_pps == 0.0: std_pps = 1.0 

        pps_z_score = (current_pps - mean_pps) / std_pps
        pps_threshold = float(self.config.params.get("pps_z_threshold", 5.0))

        if pps_z_score > pps_threshold:
            detections.append(Detection(
                model_name=self.model_name,
                timestamp=getattr(window_stats, "end_time", None),
                severity=min(1.0, (pps_z_score - pps_threshold) / max(pps_threshold, 1.0)),
                score=pps_z_score,
                label="High Volume Anomaly (DDoS Suspect)",
                justification=f"PPS Z-score {pps_z_score:.2f} exceeds threshold. Spike: {current_pps:.1f} PPS (Avg: {mean_pps:.1f})",
                evidence={"current_pps": current_pps, "mean_pps": mean_pps, "z_score": pps_z_score}
            ))

        entropy_array = np.array(list(self.entropy_history)[:-1], dtype=float)
        if entropy_array.size > 0:
            mean_entropy = float(np.mean(entropy_array))
          
            if current_entropy < mean_entropy * 0.5 and mean_entropy > 1.0:
                detections.append(Detection(
                    model_name=self.model_name,
                    timestamp=getattr(window_stats, "end_time", None),
                    severity=0.8,
                    score=current_entropy,
                    label="Source IP Entropy Collapse",
                    justification=f"Entropy dropped to {current_entropy:.2f} (Normal: {mean_entropy:.2f}). Possible flood.",
                    evidence={"current_entropy": current_entropy, "mean_entropy": mean_entropy}
                ))

        return detections
