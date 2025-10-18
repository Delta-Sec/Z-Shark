from typing import List, Dict, Any
from collections import deque
import numpy as np
from scapy.all import Packet
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, WindowStats, ModelConfig

class BeaconingDetector(BaseDetectionModel):

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.history_size = self.config.params.get('history_size', 500)
        self.fft_threshold = self.config.params.get('fft_threshold', 0.5)
        self.iat_history = deque(maxlen=self.history_size)
        self.last_packet_time = None

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []

        for pkt in window_packets:
            pkt_time = float(pkt.time)
            if self.last_packet_time is not None:
                iat = pkt_time - self.last_packet_time
                self.iat_history.append(iat)
            self.last_packet_time = pkt_time

        if len(self.iat_history) < self.history_size:
            return detections

        iat_array = np.array(self.iat_history)
        N = self.history_size
        T = 1.0
        yf = np.fft.fft(iat_array)
        xf = np.fft.fftfreq(N, T)[:N//2]
        magnitude = 2.0/N * np.abs(yf[0:N//2])

        peak_index = np.argmax(magnitude[1:]) + 1
        peak_magnitude = magnitude[peak_index]

        if peak_magnitude > self.fft_threshold:
            detections.append(Detection(
                model_name=self.model_name,
                timestamp=window_stats.end_time,
                severity=min(1.0, peak_magnitude / self.fft_threshold),
                score=peak_magnitude,
                label="C2 Beaconing Suspect (FFT)",
                justification=f"Significant peak in IAT magnitude spectrum (Magnitude: {peak_magnitude:.3f}). Periodic communication detected.",
                evidence={"peak_magnitude": peak_magnitude}
            ))

        return detections
