from typing import List, Dict, Type
from zshark.core.data_structures import ZSharkConfig, ModelConfig
from zshark.models.base import BaseDetectionModel
from zshark.models.ddos_detector import DDoSDetector
from zshark.models.port_scan_detector import PortScanDetector
from zshark.models.arp_spoof_detector import ARPSpoofDetector
from zshark.models.dns_detector import DNSAnomalyDetector
from zshark.models.beaconing_detector import BeaconingDetector

MODEL_REGISTRY: Dict[str, Type[BaseDetectionModel]] = {
    "ddos_volume": DDoSDetector,
    "port_scan": PortScanDetector,
    "arp_spoof": ARPSpoofDetector,
    "dns_anomaly": DNSAnomalyDetector,
    "beaconing": BeaconingDetector,
}

def load_models(config: ZSharkConfig) -> List[BaseDetectionModel]:
    loaded_models: List[BaseDetectionModel] = []
    default_config = ZSharkConfig.default()

    for engine_name, model_class in MODEL_REGISTRY.items():
        model_config = config.models.get(engine_name)
        if model_config is None:
            model_config = default_config.models.get(engine_name, ModelConfig())
        if model_config.enabled:
            loaded_models.append(model_class(model_config))

    return loaded_models
