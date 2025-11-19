---
name: "✨ Feature Request"
about: Suggest an idea or new mathematical model for Z-Shark
title: ''
labels: enhancement
assignees: AyhamAsfoor

---

**Thank you for helping us make Z-Shark even smarter!**

To help us understand your idea, please provide as much detail as possible, especially regarding the mathematical or logic basis.

---

<h2 style="color: #007ACC; border-bottom: 2px solid #007ACC; padding-bottom: 10px;">
  Is your feature request related to a problem?
</h2>

(A clear and concise description of what the problem is. *Example: "I am frustrated when... because..."*)

*Example: "I am frustrated because the current `DDoSDetector` only looks at Packet Per Second (PPS) volume. It fails to detect 'Low-and-Slow' application layer attacks that use valid HTTP requests but keep connections open."*

---

<h2 style="color: #4CAF50; border-bottom: 2px solid #4CAF50; padding-bottom: 10px;">
  Describe the solution you'd like
</h2>

(A clear and concise description of what you want to happen.)

*Example: "I would like a new model (e.g., `SlowLorisDetector`) that analyzes the duration of open TCP connections and the inter-arrival time of HTTP headers. It should trigger if the mean connection duration exceeds a Z-Score threshold of 3.0 relative to the baseline."*

---

<h2 style="color: #FFC107; border-bottom: 2px solid #FFC107; padding-bottom: 10px;">
  Describe alternatives you've considered
</h2>

(A clear and concise description of any alternative solutions or features you've considered.)

*Example: "I considered using the generic `BeaconingDetector` (FFT), but it's tuned for periodic signals, not necessarily long-duration open connections, so it misses these specific attacks."*

---

<h2 style="color: #9C27B0; border-bottom: 2px solid #9C27B0; padding-bottom: 10px;">
  Which component(s) does this affect?
</h2>

(Please check all that apply. This helps us route the request to the right place!)

- [ ] **🧠 Detection Models** (e.g., `models/ddos_detector.py`, New Math Logic)
- [ ] **⚙️ Core Engine** (e.g., `processor.py`, `streamer`, `window_stats`)
- [ ] **💻 CLI & Interface** (e.g., `cli/main.py`, New arguments/flags)
- [ ] **📊 Reporting & Output** (e.g., `pdf_generator.py`, JSON schema)
- [ ] **📄 Documentation** (e.g., `README.md`, Architecture Guide)

---

<h2 style="color: #FF5722; border-bottom: 2px solid #FF5722; padding-bottom: 10px;">
  Additional Context
</h2>

(Add any other context, mathematical formulas, paper references, or mockups here.)
