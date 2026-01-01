from scapy.all import PcapReader, Packet
from typing import Iterator, List, Dict, Any, Tuple, Optional
from datetime import datetime
from loguru import logger
from zshark.core.utils import calculate_window_stats
from zshark.core.data_structures import ZSharkConfig, AnalysisResult, Detection, WindowStats
from zshark.models import load_models
from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP


class PacketStreamer:
    def __init__(self, pcap_path: str):
        self.pcap_path = pcap_path

    def stream(self) -> Iterator[Packet]:
        try:
            logger.info(f"Starting to stream packets from: {self.pcap_path}")
            for pkt in PcapReader(self.pcap_path):
                yield pkt
        except Exception as e:
            logger.error(f"Error reading PCAP file {self.pcap_path}: {e}")
            raise

class WindowProcessor:
    def __init__(self, config: ZSharkConfig):
        self.max_window_packets = 10000 
        
        self.window_size = config.models.get("ddos_volume", ZSharkConfig.default().models["ddos_volume"]).window_size_s
        self.current_window: List[Packet] = []
        self.window_start_time: Optional[float] = None
        self.dropped_packets_count = 0

    def process_stream(self, packet_stream: Iterator[Packet]) -> Iterator[Tuple[WindowStats, List[Packet]]]:
        for pkt in packet_stream:
            try:
                pkt_time = float(pkt.time)
            except Exception:
                continue

            if self.window_start_time is None:
                self.window_start_time = pkt_time

            if pkt_time >= self.window_start_time + self.window_size:

                if self.current_window:
                    stats_dict = calculate_window_stats(self.current_window)
                    stats_dict['start_time'] = datetime.fromtimestamp(self.window_start_time).isoformat()
                    stats_dict['end_time'] = datetime.fromtimestamp(self.window_start_time + self.window_size).isoformat()
                    
                  
                    if self.dropped_packets_count > 0:
                        logger.warning(f"Window overloaded! Dropped {self.dropped_packets_count} packets to save RAM.")
                    
                    stats = WindowStats(**stats_dict)
                    yield (stats, self.current_window)
                

                self.current_window = [pkt]
                self.window_start_time = pkt_time
                self.dropped_packets_count = 0
            else:

                if len(self.current_window) < self.max_window_packets:
                    self.current_window.append(pkt)
                else:
                    self.dropped_packets_count += 1

        if self.current_window and self.window_start_time is not None:
            stats_dict = calculate_window_stats(self.current_window)
            stats_dict['start_time'] = datetime.fromtimestamp(self.window_start_time).isoformat()
            stats_dict['end_time'] = datetime.fromtimestamp(self.window_start_time + self.window_size).isoformat()
            stats = WindowStats(**stats_dict)
            yield (stats, self.current_window)

class Analyzer:
    def __init__(self, config: ZSharkConfig):
        self.config = config
        self.window_processor = WindowProcessor(config)
        self.detection_models = load_models(config)
    
    def analyze_pcap(self, pcap_path: str) -> AnalysisResult:
       
        streamer = PacketStreamer(pcap_path)
        packet_stream = streamer.stream()
  
        first_packet = next(packet_stream, None)
        if not first_packet:
             logger.warning(f"PCAP file {pcap_path} is empty.")
             return AnalysisResult(pcap_path=pcap_path, start_time=datetime.now(), end_time=datetime.now(), total_packets=0, total_bytes=0)

        def full_stream():
            yield first_packet
            yield from packet_stream

        window_iterator = self.window_processor.process_stream(full_stream())

        all_detections: List[Detection] = []
        all_window_stats: List[WindowStats] = []
        total_packets = 0
        total_bytes = 0
        start_time = datetime.fromtimestamp(float(first_packet.time))
        end_time = start_time
        source_ip_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})
        dest_port_stats = defaultdict(lambda: {"packets": 0, "bytes": 0})

        for window_stats, window_packets in window_iterator:
            all_window_stats.append(window_stats)
            total_packets += window_stats.packet_count
            total_bytes += window_stats.total_bytes
            end_time = datetime.fromisoformat(window_stats.end_time)

            for model in self.detection_models:
                detections = model.analyze(window_stats, window_packets)
                all_detections.extend(detections)

            for pkt in window_packets:
                if IP in pkt:
                    ip_src = pkt[IP].src
                    source_ip_stats[ip_src]["packets"] += 1
                    source_ip_stats[ip_src]["bytes"] += len(pkt)
                if TCP in pkt:
                    port_dst = pkt[TCP].dport
                    dest_port_stats[port_dst]["packets"] += 1
                    dest_port_stats[port_dst]["bytes"] += len(pkt)
                elif UDP in pkt:
                    port_dst = pkt[UDP].dport
                    dest_port_stats[port_dst]["packets"] += 1
                    dest_port_stats[port_dst]["bytes"] += len(pkt)
        
        from zshark.core.scoring import score_and_fuse
        final_detections = score_and_fuse(all_detections)

        top_source_ips = sorted([{"ip": ip, **stats} for ip, stats in source_ip_stats.items()], key=lambda x: x["packets"], reverse=True)[:5]
        top_dest_ports = sorted([{"port": port, **stats} for port, stats in dest_port_stats.items()], key=lambda x: x["packets"], reverse=True)[:5]

        logger.info(f"Analysis complete. Total packets: {total_packets}")

        return AnalysisResult(
            pcap_path=pcap_path,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            total_packets=total_packets,
            total_bytes=total_bytes,
            detections=final_detections, 
            window_stats=all_window_stats,
            top_source_ips=top_source_ips,
            top_dest_ports=top_dest_ports,
            summary_stats={"total_packets": total_packets, "total_bytes": total_bytes}
        )
