# 🤝 Contributing to Z-Shark

<p align="center">
  <img src="https://img.shields.io/badge/Status-Contributions%20Welcome!-brightgreen?style=flat-square" alt="Contributions Welcome!">
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License: MIT">
</p>

First off, thank you for considering contributing to **Z-Shark**! This project is driven by the community, and every contribution helps make it a more robust and mathematically precise tool for network forensics.

This document provides guidelines for contributing, whether it's through reporting a bug, suggesting a new mathematical model, or submitting code.

## 📜 Code of Conduct

Before contributing, please take a minute to read our **[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)**. We enforce this code strictly to ensure that the Z-Shark community remains a professional, welcoming, and inclusive environment for everyone.

---

<details>
  <summary><strong>Table of Contents</strong></summary>
  <ol>
    <li><a href="#-how-can-i-contribute">How Can I Contribute?</a></li>
    <li><a href="#%EF%B8%8F-setting-up-your-development-environment">Setting Up Your Development Environment</a></li>
    <li><a href="#-pull-request-pr-workflow">Pull Request (PR) Workflow</a></li>
    <li><a href="#%EF%B8%8F-coding-style-guides">Coding Style Guides</a></li>
  </ol>
</details>

---

## 💡 How Can I Contribute?

### 🐞 Reporting Bugs

If you find a bug, please **open a new Issue** on our GitHub repository. A good bug report is essential for us to fix it. Please include:

* **A clear, descriptive title:** e.g., "FFT Beaconing detector throws ValueError on empty PCAP windows."
* **Your Environment:** OS (e.g., Ubuntu 22.04), Python version (e.g., 3.11.5), and Scapy/NumPy versions.
* **Steps to Reproduce:** Provide a clear, step-by-step guide or a small sample PCAP that triggers the bug.
* **Expected Behavior:** What did you expect the model to detect?
* **Actual Behavior:** What happened instead? (Include full terminal output, stack traces, or error logs).

### ✨ Suggesting Enhancements or New Models

We are always looking for new ways to apply mathematics to security! If you have an idea for a new detection algorithm (e.g., using Machine Learning or advanced Entropy measures), please **open a new Issue**.

* **Describe the Feature:** What is the mathematical concept? (e.g., "Benford's Law for byte distribution analysis").
* **Pitch the solution:** How would you implement it as a `BaseDetectionModel` subclass?
* **Provide context:** How does this improve detection accuracy or reduce false positives?

---

## 🛠️ Setting Up Your Development Environment

Z-Shark is a Python-based platform heavily reliant on scientific computing libraries (`numpy`, `scipy`).

### Local Setup

To start working on `zshark/core`, `zshark/models`, or the CLI:

```bash
# 1. Clone the repository
git clone [https://github.com/Delta-Security/z-shark.git](https://github.com/Delta-Security/z-shark.git)
cd z-shark

# 2. Create and activate virtual environment (Python 3.11+ Required)
python3 -m venv .venv
source .venv/bin/activate  # Linux/macOS
# or .venv\Scripts\activate on Windows

# 3. Install dependencies
pip install -r requirements.txt
```

### Running Tests
Before submitting, ensure your changes don't break existing logic. (If tests are available):

```bash 
# Run the CLI on a sample PCAP
python -m zshark.cli.main analyze sample_pcaps/http-flood.pcap --out-dir results/

# Generate a test report
python -m zshark.cli.main report results/http-flood_analysis.json
```

## 🚀 Pull Request (PR) Workflow
Ready to submit your code? Follow these steps to ensure a smooth review process.

1) **Fork the Repository:** Create your own copy of `Delta-Security/z-shark`.

2) **Create a Feature Branch:** Branch off `main` to keep your changes isolated.
```bash
git checkout -b feat/new-entropy-model
```
3) **Commit Your Changes:** Make your changes and write clear, descriptive commit messages.
```bash
git commit -m "feat(models): Add Shannon Entropy detector for payload analysis"
git commit -m "fix(core): Resolve memory leak in WindowProcessor"
```
4) **Push to Your Branch:**
```bash
git push origin feat/new-entropy-model
```
5) **Open a Pull Request (PR):**

* Go to the main Z-Shark repository and click "New Pull Request".

* Provide a clear title and a detailed description.

* Critical: If adding a new detection model, please provide proof of concept (e.g., "Detected X attack in Y.pcap with Z confidence").

## ✍️ Coding Style Guides
To maintain the scientific rigor and readability of the codebase:

* Python: We follow PEP 8. Please run a linter (like `flake8` or `black`) before submitting.

* Type Hinting: Z-Shark uses strict type hinting (e.g., `def analyze(self, packets: List[Packet]) -> List[Detection]:`). Please ensure all new functions are typed.

* Documentation: Mathematical models must include docstrings explaining the underlying algorithm or formula used.

By contributing to Z-Shark, you agree that your contributions will be licensed under its [MIT License](https://github.com/Delta-Sec/Z-Shark/blob/main/LICENSE).
