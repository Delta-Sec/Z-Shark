from abc import ABC, abstractmethod
from typing import List
from scapy.all import Packet
from zshark.core.data_structures import Detection, ModelConfig, WindowStats

class BaseDetectionModel(ABC):

    def __init__(self, config: ModelConfig):
        self.config = config
        self.engine_name = self.__class__.__name__

    @abstractmethod
    def analyze(self, window_stats: WindowStats, window_packets: List[Packet]) -> List[Detection]:
        pass

    @abstractmethod
    def update_baseline(self, window_stats: WindowStats, window_packets: List[Packet]) -> None:
        pass
