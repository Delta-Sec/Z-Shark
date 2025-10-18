from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
from datetime import datetime



class Detection(BaseModel):
    model_name: str = Field(..., description="Name of the mathematical model that triggered the detection.")
    timestamp: datetime = Field(..., description="Timestamp of the packet/window that triggered the detection.")
    severity: float = Field(..., description="Severity score from 0.0 (low) to 1.0 (critical).")
    score: float = Field(..., description="Raw score from the model (e.g., Z-score, Entropy value).")
    label: str = Field(..., description="A human-readable label for the type of attack/anomaly.")
    justification: str = Field(..., description="Textual explanation of why the detection was triggered.")
    evidence: Dict[str, Any] = Field(default_factory=dict,
                                     description="Key metrics/data points that serve as evidence.")
    flow_key: Optional[str] = Field(None, description="A key identifying the flow (e.g., 'src_ip:dst_ip').")


class WindowStats(BaseModel):
    start_time: str = Field(..., description="ISO format start time of the window.")
    end_time: str = Field(..., description="ISO format end time of the window.")
    packet_count: int = Field(..., description="Total number of packets in the window.")
    total_bytes: int = Field(..., description="Total bytes of packets in the window.")
    pps: float = Field(0.0, description="Packets per second.")
    bps: float = Field(0.0, description="Bits per second.")
    src_ip_entropy: float = Field(0.0, description="Shannon entropy of source IP addresses.")
    dst_ip_entropy: float = Field(0.0, description="Shannon entropy of destination IP addresses.")

    def get(self, key: str, default=None):
        return getattr(self, key, default)
    
    def __getitem__(self, key):
        return getattr(self, key)

    def __setitem__(self, key, value):
        setattr(self, key, value)


class AnalysisResult(BaseModel):

    pcap_path: str
    start_time: datetime
    end_time: datetime
    total_packets: int
    total_bytes: int
    detections: List[Detection] = Field(default_factory=list)
    summary_stats: Dict[str, Any] = Field(default_factory=dict)
    model_stats: Dict[str, Any] = Field(default_factory=dict)
    window_stats: List[WindowStats] = Field(default_factory=list, description="List of per-window statistics")
    top_source_ips: List[Dict[str, Any]] = Field(default_factory=list, description="Top N source IPs by packet count")
    top_dest_ports: List[Dict[str, Any]] = Field(default_factory=list, description="Top N destination ports by packet "
                                                                                   "count")



class ModelConfig(BaseModel):
    enabled: bool = True
    threshold: float = Field(3.0, description="The primary detection threshold (e.g., Z-score limit).")
    window_size_s: int = Field(10, description="Time window size in seconds for statistical calculation.")
    weight: float = Field(1.0, description="Weight for score fusion.")
    params: Dict[str, Any] = Field(default_factory=dict, description="Model-specific parameters.")


class ZSharkConfig(BaseModel):
    analysis_profile: str = "default"
    output_dir: str = "results"
    parallel_workers: int = 1
    models: Dict[str, ModelConfig] = Field(default_factory=dict)

    @classmethod
    def default(cls) -> "ZSharkConfig":
        return cls(
            models={
                "ddos_volume": ModelConfig(
                    threshold=5.0,
                    params={"metric": "pps", "k": 5.0}
                ),
                "port_scan": ModelConfig(
                    threshold=0.8,
                    params={"min_unique_ports": 10}
                ),
                "arp_spoof": ModelConfig(
                    threshold=5,
                    params={"max_gratuitous_arp_per_s": 1}
                ),
                "dns_anomaly": ModelConfig(
                    threshold=0.7,
                    params={"history_size": 100, "entropy_threshold": 3.5}
                ),
                "beaconing": ModelConfig(
                    threshold=0.6,
                    params={"history_size": 500, "fft_threshold": 0.5}
                )
            }
        )
