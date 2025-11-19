# 🛡️ Z-Shark Security Policy

The Z-Shark team and the Delta-Security community take the security of this platform very seriously. Given the sensitive nature of forensic analysis and packet processing, we appreciate your efforts to responsibly disclose any vulnerabilities you may find.

## 📈 Supported Versions

Security is a rapidly evolving field. To ensure the integrity of forensic investigations, we only provide security support and patches for the **most recent stable version** of Z-Shark.

| Version | Supported |
| :--- | :--- |
| **`main` 1.0.0 (latest)** | :white_check_mark: |

If you are not using the latest version, please upgrade before reporting a vulnerability to ensure it has not already been fixed.

---

<h2 style="color: #FF0000; border-bottom: 2px solid #FF0000; padding-bottom: 10px;">
  ✉️ How to Report a Vulnerability
</h2>

**PLEASE DO NOT DISCLOSE VULNERABILITIES PUBLICLY.**

Do **NOT** open a public GitHub Issue for a security vulnerability. This can put other users at risk.

Instead, we ask that you report all security issues **privately** by emailing our security contact:

### **[contact@delta-sec.site](mailto:contact@delta-sec.site)**

Please use a clear and descriptive subject line, such as "Buffer Overflow in PCAP Streamer" or "Command Injection in PDF Reporter".

---

<h2 style="color: #007ACC; border-bottom: 2px solid #007ACC; padding-bottom: 10px;">
  📝 What to Include in Your Report
</h2>

To help us validate and fix the vulnerability as quickly as possible, please include the following in your report:

1.  **A Clear Description:** A brief summary of the vulnerability and its potential impact (e.g., DoS, RCE, Data Leakage).
2.  **Affected Component:** Specify which part of the platform is affected:
    * **Core Engine** (e.g., `processor.py`, `streamer`, `window_stats`)
    * **Detection Models** (e.g., `beaconing_detector.py`, `ddos_detector.py`, FFT/Entropy logic)
    * **CLI Interface** (e.g., `zshark/cli/main.py`, argument parsing)
    * **Reporting Module** (e.g., `pdf_generator.py`, `reportlab` integration)
3.  **Steps to Reproduce (PoC):** A clear, step-by-step guide or a **malicious PCAP sample** that triggers the vulnerability.
4.  **Environment:** Your operating system, Python version, and Scapy/NumPy versions.
5.  **(Optional) Suggested Fix:** If you have an idea of how to fix the issue, please let us know.

---

<h2 style="color: #4CAF50; border-bottom: 2px solid #4CAF50; padding-bottom: 10px;">
  ⏳ Our Commitment (What to Expect)
</h2>

When you report a vulnerability to us, you can expect the following:

1.  We will respond to your report promptly, typically **within 48 hours**, to acknowledge we have received it.
2.  We will conduct an internal investigation to confirm the vulnerability.
3.  We will work on a patch and prepare a new release.
4.  We will keep you updated on our progress and notify you once the vulnerability is patched.
5.  We will happily give you **public credit** (if you wish) in the release notes for your contribution to the security of the Z-Shark community.
