<img width="1280" height="342" alt="Z-Shark" src="https://github.com/user-attachments/assets/2c821938-4424-45ff-8964-eb0c14b6022c" />

# Z-Shark: The World-Class Packet Analysis Platform

**CLI-first. Mathematical Models first. Fully Integrated.**

Z-Shark is a high-performance, extensible platform for deep packet analysis, focusing on the detection of network anomalies and attacks using sophisticated mathematical and statistical models. It is designed to be a CLI-first tool for rapid forensic analysis and can be deployed as a web service for continuous monitoring.

## 🌟 Features

*   **High-Performance PCAP Ingestion:** Efficiently process large `.pcap` and `.pcapng` files using streaming and chunked processing.
*   **Mathematical Anomaly Detection:** Utilizes advanced models like Z-score thresholding, Shannon Entropy, and Time-Series analysis (FFT) to detect subtle threats.
*   **Explainable Detections:** Every detection is accompanied by a clear, textual justification showing the underlying metrics and patterns that triggered the alert.
*   **Automated PDF Reporting:** Generate professional, well-formatted PDF reports complete with technical analysis, graphs, and mitigation recommendations.
*   **Modular & Extensible:** Clean architecture with a clear separation of concerns (`core`, `models`, `reports`) and a built-in plugin system for custom heuristics.
*   **CLI-First Design:** A powerful command-line interface for all primary operations.

## 🚀 Quick Start (CLI)

### Prerequisites

*   Python 3.11+
*   Poetry (recommended for dependency management)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-org/z-shark.git
    cd z-shark
    ```

2.  **Install dependencies:**
    ```bash
    python -m venv .venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

### Example Usage

1.  **Analyze a PCAP file:**
    ```bash
    python -m zshark.cli.main.py analyze input.pcap --out results/ --profile high-sensitivity
    ```

2.  **Generate a detailed PDF report:**
    ```bash
    python -m zshark.cli.main.py report results/analysis.json --pdf report.pdf
    ```

3.  **Get a quick summary:**
    ```bash
    python -m zshark.cli.main.py summary input.pcap --top 10
    ```

## 🛠️ Architecture

Z-Shark follows a clean, modular design:

| Module | Description |
| :--- | :--- |
| `zshark/core` | Core utilities, configuration, data structures, and the main packet stream processor. |
| `zshark/models` | Implementation of all mathematical and statistical detection algorithms. |
| `zshark/cli` | The command-line interface entry points and logic (using Typer). |
| `zshark/reports` | Logic for generating PDF, JSON, and other output formats (using ReportLab). |
| `zshark/web` | (Future) FastAPI-based web service and API. |
| `zshark/tests` | Unit and integration tests (using Pytest). |
| `zshark/docs` | Documentation, including the Architecture guide. |

## ⚖️ License

This project is licensed under the MIT License. See the `LICENSE` file for details.

