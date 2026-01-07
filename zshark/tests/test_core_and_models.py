import pytest
from scapy.all import Ether, IP, TCP, UDP, ARP, wrpcap
from pathlib import Path
import numpy as np
import os

from zshark.core.utils import shannon_entropy
from zshark.core.data_structures import ZSharkConfig, ModelConfig
from zshark.models.ddos_detector import DDoSDetector

@pytest.fixture
def normal_config():
    return ZSharkConfig.default()

@pytest.fixture
def ddos_detector(normal_config):
    config = normal_config.models["ddos_volume"]
    config.params["pps_z_threshold"] = 3.0
    config.params["entropy_drop_ratio"] = 0.6
    detector = DDoSDetector(config)
    for _ in range(detector.history_size):
        detector.pps_history.append(10.0)
        detector.entropy_history.append(5.0)
    return detector

def test_shannon_entropy_max():
    data = ['a', 'b', 'c', 'd']

    assert shannon_entropy(data) == pytest.approx(2.0)

def test_shannon_entropy_min():
    data = ['a', 'a', 'a', 'a']
    assert shannon_entropy(data) == pytest.approx(0.0)

def test_shannon_entropy_mixed():
    data = ['a', 'a', 'b', 'b']
    assert shannon_entropy(data) == pytest.approx(1.0)


def test_ddos_detector_no_detection(ddos_detector):

    window_stats = {
        "end_time": datetime.now(),
        "pps": 10.5,
        "src_ip_entropy": 4.8
    }
    detections = ddos_detector.run(window_stats, [])
    assert len(detections) == 0

def test_ddos_detector_volume_detection(ddos_detector):
    ddos_detector.pps_history = deque(np.random.normal(10.0, 1.0, ddos_detector.history_size), maxlen=ddos_detector.history_size)
    
    window_stats = {
        "end_time": datetime.now(),
        "pps": 20.0,
        "src_ip_entropy": 4.8,
    }

    mean_pps = np.mean(ddos_detector.pps_history)
    std_pps = np.std(ddos_detector.pps_history)

    if std_pps > 0.5:
        detections = ddos_detector.run(window_stats, [])
        assert len(detections) == 1
        assert "Volume Anomaly" in detections[0].label
        assert detections[0].score > 3.0
    else:
        pass

def test_ddos_detector_entropy_detection(ddos_detector):
    window_stats = {
        "end_time": datetime.now(),
        "pps": 10.5,
        "src_ip_entropy": 1.0,
    }
    detections = ddos_detector.run(window_stats, [])
    assert len(detections) == 1
    assert "Entropy Collapse" in detections[0].label
    assert detections[0].score == pytest.approx(1.0)
    
from collections import deque
from datetime import datetime