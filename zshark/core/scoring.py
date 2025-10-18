from typing import List
from zshark.core.data_structures import Detection

def calculate_final_severity(detections: List[Detection]) -> float:
    if not detections:
        return 0.0

    max_severity = max(d.severity for d in detections)
    
    return max_severity

def score_and_fuse(detections: List[Detection]) -> List[Detection]:

    return detections

