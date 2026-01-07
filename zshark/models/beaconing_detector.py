from typing import List
from collections import deque, defaultdict
import numpy as np
from scapy.all import Packet
from zshark.models.base import BaseDetectionModel
from zshark.core.data_structures import Detection, WindowStats, ModelConfig
from zshark.core.utils import get_flow_key 

class BeaconingDetector(BaseDetectionModel):

    def __init__(self, config: ModelConfig):
        super().__init__(config)
        self.history_size = int(self.config.params.get('history_size', 100))
        self.fft_threshold = float(self.config.params.get('fft_threshold', 0.5))
        
        self.flow_iat_histories = defaultdict(lambda: deque(maxlen=self.history_size))
        self.last_packet_times = {} 

        self.cleanup_counter = 0
        self.cleanup_interval = 1000 

    def _cleanup_stale_flows(self, current_time: float):

        stale_keys = []
        for key, last_time in self.last_packet_times.items():
            if current_time - last_time > 300:
                stale_keys.append(key)
        
        for key in stale_keys:
            del self.last_packet_times[key]
            if key in self.flow_iat_histories:
                del self.flow_iat_histories[key]

    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass

    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        detections: List[Detection] = []
        
       
        try:
            current_window_time = float(window_packets[-1].time) if window_packets else None
        except:
            current_window_time = None

        for pkt in window_packets:
            flow_key = get_flow_key(pkt)
            if not flow_key:
                continue

            try:
                pkt_time = float(pkt.time)
            except:
                continue
            
            if flow_key in self.last_packet_times:
                iat = pkt_time - self.last_packet_times[flow_key]
                if iat < 10.0: 
                    self.flow_iat_histories[flow_key].append(iat)
            
            self.last_packet_times[flow_key] = pkt_time

            self.cleanup_counter += 1
            if self.cleanup_counter >= self.cleanup_interval and current_window_time:
                self._cleanup_stale_flows(current_window_time)
                self.cleanup_counter = 0

       
        for flow_key, history in self.flow_iat_histories.items():
            if len(history) < self.history_size:
                continue

            iat_array = np.array(history)
            iat_array = iat_array - np.mean(iat_array)

            N = len(iat_array)
            yf = np.fft.fft(iat_array)
            magnitude = 2.0/N * np.abs(yf[0:N//2])

            if len(magnitude) > 1:
                peak_index = np.argmax(magnitude[1:]) + 1
                peak_magnitude = magnitude[peak_index]

                if peak_magnitude > self.fft_threshold:
                    detections.append(Detection(
                        engine_name=self.engine_name,
                        timestamp=getattr(window_stats, "end_time", None),
                        severity=min(1.0, peak_magnitude / self.fft_threshold),
                        score=peak_magnitude,
                        label="C2 Beaconing Suspect (FFT)",
                        justification=f"Periodic signal in {flow_key}. Peak: {peak_magnitude:.3f}",
                        evidence={"flow_key": flow_key, "peak_magnitude": peak_magnitude}
                    ))
                    history.clear()

        return detections
