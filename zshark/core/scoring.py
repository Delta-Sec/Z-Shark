from typing import List, Dict
from zshark.core.data_structures import Detection

def calculate_final_severity(detections: List[Detection]) -> float:
    if not detections:
        return 0.0
  
    max_severity = max(d.severity for d in detections)
    return max_severity

def score_and_fuse(detections: List[Detection]) -> List[Detection]:

    if not detections:
        return []

    fused_map: Dict[str, Detection] = {}

    for det in detections:
       
        key_parts = [det.label]
        
        
        if det.evidence:
            if 'ip' in det.evidence:
                key_parts.append(str(det.evidence['ip']))
            elif 'source_ip' in det.evidence:
                key_parts.append(str(det.evidence['source_ip']))
            elif 'domain' in det.evidence:
                key_parts.append(str(det.evidence['domain']))
            elif 'flow_key' in det.evidence:
                key_parts.append(str(det.evidence['flow_key']))
        
        unique_key = "_".join(key_parts)

        if unique_key in fused_map:
            if det.score > fused_map[unique_key].score:
                fused_map[unique_key] = det
        else:
            fused_map[unique_key] = det

    return list(fused_map.values())
