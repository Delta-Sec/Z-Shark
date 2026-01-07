# Z-Shark Architecture Overview

Z-Shark is designed as a modular, high-performance packet analysis platform built on a Python 3.11+ asynchronous core. The architecture is structured to separate concerns, allowing for easy extension of detection models, reporting formats, and deployment methods.

## 1. Core Data Flow

The system operates on a streaming pipeline model to handle large PCAP files without loading the entire dataset into memory.

1.  **Packet Streamer (`zshark/core/processor.py`):** Uses `scapy.PcapReader` to read packets one-by-one from the input PCAP file.
2.  **Window Processor (`zshark/core/processor.py`):** Buffers the packet stream into fixed-size time windows (e.g., 10 seconds). For each window, it calculates a comprehensive set of statistical summaries (PPS, BPS, entropy, etc.) and yields both the summary and the raw packet list.
3.  **Analyzer (`zshark/core/processor.py`):** The central orchestrator. It loads all configured detection models and iterates through the window summaries.
4.  **Detection Models (`zshark/models`):** Each model processes the window summary and raw packets, runs its mathematical algorithm (e.g., Z-score, Entropy), and outputs a list of `Detection` objects.
5.  **Result Aggregation:** The Analyzer collects all `Detection` objects into a final `AnalysisResult` object, which is then serialized to a JSON file.

## 2. Modular Structure

The project is organized into distinct, decoupled modules:

| Module | Purpose | Key Components |
| :--- | :--- | :--- |
| `zshark/core` | Foundation of the system. Contains data structures, utility functions (entropy, flow key), and the streaming processor. | `data_structures.py`, `utils.py`, `processor.py` |
| `zshark/models` | Houses all mathematical and statistical detection algorithms. Models inherit from `BaseDetectionModel`. | `base.py`, `ddos_detector.py`, `port_scan_detector.py`, `arp_spoof_detector.py` |
| `zshark/cli` | The command-line interface, built using `typer`. It handles argument parsing and orchestrates the core analysis and reporting functions. | `main.py` |
| `zshark/reports` | Logic for generating human-readable output formats from the `AnalysisResult` JSON. | `pdf_generator.py` (using ReportLab) |
| `zshark/tests` | Unit and integration tests for ensuring code quality and model correctness. | `test_*.py` |
| `zshark/docs` | Project documentation, including this architecture guide. | `Architecture.md` |

## 3. Mathematical Models & Extensibility

The core strength of Z-Shark lies in its **mathematical models**.

### Model Design

All detection models adhere to the `BaseDetectionModel` interface, which requires two methods:
1.  `run(window_stats, window_packets)`: Executes the detection logic for a single time window.
2.  `update_baseline(window_stats, window_packets)`: Updates the model's internal state (e.g., moving averages, historical statistics) for the next window.

This design ensures that models can maintain state across the stream and allows for easy integration of new detection logic.

### Implemented Models (Mandatory)

| Model | Algorithm | Detection Focus |
| :--- | :--- | :--- |
| `DDoSDetector` | Z-score on Packet Rate (PPS), Shannon Entropy on Source IP distribution. | High-volume attacks, source-IP-spoofed floods. |
| `PortScanDetector` | Unique Destination Port Count per Source IP. | Vertical and horizontal port scanning activities. |
| `ARPSpoofDetector` | Gratuitous ARP frequency, Inconsistent MAC-IP mapping tracking. | Layer 2 man-in-the-middle attacks. |

### Plugin System (Future)

The `zshark/models` module acts as a simple plugin system. To add a new detector, a developer only needs to:
1.  Create a new class inheriting from `BaseDetectionModel`.
2.  Implement the `run` and `update_baseline` methods.
3.  Register the new class in `zshark/models/__init__.py`'s `MODEL_REGISTRY`.

## 4. Deployment

Z-Shark is designed for containerization, making it deployable in various environments.

*   **Dockerfile:** Provides a clean, multi-stage build for a lightweight image containing the Python environment and all dependencies.
*   **CLI:** The primary interface, suitable for running in a container for batch analysis on mounted PCAP volumes.
*   **Web Service (Future):** The `zshark serve` command is a placeholder for a FastAPI-based web API, which would allow for remote analysis submission and web-based reporting.

