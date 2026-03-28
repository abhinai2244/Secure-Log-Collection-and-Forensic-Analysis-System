# Secure Log Collection & Forensic Analysis System v2.0
## AI-Powered Detection, Blockchain Integrity, and Real-Time Forensics

This project is an advanced, enterprise-grade secure logging and forensic analysis system. It leverages **SHA-256 Hash Chaining** and **RSA Digital Signatures** to ensure log immutability, while using **Rule-based and ML-based engines** to detect and prevent cyber attacks in real-time.

### 🌟 Key Features

#### 🛡️ Advanced Security
- **Blockchain Chaining**: Logs are cryptographically linked, ensuring that any deletion or insertion breaks the chain.
- **RSA Digital Signatures**: Every log block is signed with an RSA-2048 private key, providing non-repudiation and proof of origin.
- **Multi-Source Collection**: Real-time ingestion from **Windows Event Logs** (via PowerShell) and **Live Network Traffic** (Deep Packet Inspection).

#### 🧠 Smart Attack Detection
- **AI/ML Engine**: Statistical anomaly detection for identifying traffic spikes (DDoS) and unusual system behavior.
- **Rule Engine**: Detects Brute Force attacks, Port Scans, and SQL Injection patterns.
- **Threat Intelligence**: Integrated reputation checks to flag known malicious IPs.

#### 📊 Forensic Dashboard
- **Real-Time Visualization**: Dynamic charts (Chart.js) for attack distribution and risk timelines.
- **Interactive Simulation Lab**: One-click triggers for DDoS, Brute Force, and Port Scans to test detection logic.
- **IPS (Intrusion Prevention)**: Automated IP blocking when high-risk threats are identified.
- **Forensic Reports**: One-click PDF generation with cryptographic evidence and incident timelines.

### 🛠️ Prerequisites

- **Python 3.10+**
- **Windows OS** (for Event Log and Firewall integration)
- **Scapy & Npcap** (Optional, for live network capture)
- **Required Libraries**: `flask`, `cryptography`, `sklearn`, `fpdf2`, `chart.js` (CDN)

### 🚀 Quick Start

1. **Install Dependencies**:
   ```bash
   pip install flask cryptography scikit-learn fpdf2 werkzeug==2.2.2
   ```

2. **Run the Application**:
   ```bash
   python app.py
   ```

3. **Access the Dashboard**:
   Open `http://localhost:5000` in your browser.

### 📁 Project Structure

- `secure_logger/`: Core forensic package.
    - `chain.py`: Blockchain logic and RSA signature management.
    - `detection.py`: Rule-based and ML anomaly detection.
    - `ips.py`: Intrusion Prevention System (IPS) for IP blocking.
    - `report.py`: PDF Forensic Report generation.
    - `threat_intel.py`: IP reputation and blacklist management.
    - `network_collector.py`: Live packet capture logic.
    - `real_collector.py`: Windows Event Log collector.
- `app.py`: Main Flask entry point and API gateway.
- `templates/index.html`: Modern, premium dark-mode dashboard.

### 🔬 Forensic Analysis Workflow

1. **Collect**: Start monitoring Windows or Network logs.
2. **Detect**: The engine flags attacks like Brute Force or DDoS in real-time.
3. **Verify**: Run a "Forensic Verification" to mathematically prove the integrity of the log chain.
4. **Export**: Generate a signed PDF report for incident response and evidence preservation.

---
**Disclaimer**: This tool is for educational and forensic analysis purposes. Ensure you have proper authorization before monitoring network or system logs.
