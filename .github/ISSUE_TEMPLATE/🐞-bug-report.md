---
name: "\U0001F41E Bug Report"
about: Create a report to help us improve Z-Shark
title: BUG
labels: bug
assignees: AyhamAsfoor

---

**Thank you for helping improve Z-Shark! To help us fix this bug, please provide the following details.**

### 1. Clear Bug Description
(A clear and concise description of what the bug is. Example: "The Beaconing Detector throws a 'DivideByZero' error when analyzing a PCAP containing only 2 packets.")

### 2. Steps to Reproduce
(Please provide a clear, step-by-step guide on how to trigger the bug. This is the most important part!)

1.  Run command: `python -m zshark.cli.main analyze sample.pcap --profile deep-scan`.
2.  Wait for the `WindowProcessor` to finish the first chunk...
3.  **BUG:** The process crashes with a traceback in `zshark/models/ddos_detector.py`.

### 3. Expected Behavior
(A clear description of what you expected to happen.)

* I expected the analyzer to skip the window with insufficient data or return a neutral score (0.0) instead of crashing.

### 4. Actual Behavior (The Bug)
(A description of what actually happened. **Please paste all terminal output, error messages, and stack traces here.** Use a code block for clarity.)

```text
Traceback (most recent call last):
  File "zshark/models/ddos_detector.py", line 45, in analyze
    z_score = (current_pps - mean) / std_dev
ZeroDivisionError: float division by zero

### 5. Your Development Environment
(This is critical for scientific computing debugging. Please fill out all relevant fields.)

* **Operating System:** (e.g., Ubuntu 22.04 LTS, Windows 11, Kali Linux)

* **Python Version:** (e.g., Python 3.11.4)

* **Z-Shark Version:** (e.g., v1.0.0 or specific commit hash)

**Key Dependencies:**

* **Scapy Version:** (e.g., 2.5.0)

* **NumPy Version:** (e.g., 1.26.0)

**Installation Method:**

  * [ ] Poetry (Recommended)

  * [ ] pip / venv

  * [ ] Docker

### 6. Additional Context
(Add any other context about the problem here.)

PCAP Details: (e.g., "The PCAP file is 500MB and contains mostly encrypted QUIC traffic.")

Sample File: (If possible, please upload a sanitized sample PCAP that reproduces the issue.)
