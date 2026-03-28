# Secure Log Collection & Forensic Analysis System
## Real-Time Prototype & Forensic Demo

This project demonstrates a secure logging system using **SHA-256 Hash Chaining** (Blockchain concepts) to ensure log integrity and detect tampering of **Real-Time Windows Logs**.

### Prerequisites

- Python 3.x installed.
- **Windows OS** (required for `Get-EventLog` PowerShell command).

### Project Structure

- `secure_logger/`: Core Python package.
    - `models.py`: Defines the `LogEntry` and `Block` structure (SHA-256).
    - `chain.py`: Manages the secure hash chain and integrity verification.
    - `real_collector.py`: **[NEW]** Connects to Windows PowerShell to fetch live System/Application events.
    - `adversary.py`: Simulates an internal theoretical attack (modifying validated logs) to demonstrate forensic capabilities.
- `demo.py`: The main script to run the real-time monitoring and forensic analysis.

### How to Run the Demo

1.  Open a terminal in this folder.
2.  Run the following command:

```bash
python demo.py
```

### What to Expect

1.  **Phase 1 & 2 (Real Data Collection)**: 
    - The system connects to your **Windows Event Viewer**. 
    - You will see actual 'Application' events (e.g., Chrome, Updater, System Services) being captured and secured in real-time.
    - Each log is cryptographically chained to the previous one immediately upon arrival.

2.  **Phase 3 (The Attack Simulation)**: 
    - You will be prompted to simulate a tamper event. 
    - The `Adversary` script will modify one of the *actual* log entries we just captured in memory to simulate a database intrusion.

3.  **Phase 4 (Forensic Analysis)**: 
    - The system recalculates the SHA-256 hashes.
    - It **mathematically proves** that the log was altered.
    - It identifies specifically *which* block was broken, preserving the chain of custody for all previous records.

### Key Concepts for Your Review
- **Immutability**: Once a log is hashed, changing it invalidates the hash.
- **Traceability**: The "Previous Hash" link ensures that deleting or inserting logs breaks the chain.
- **Forensics**: We can detect "Silent Failures" where logs are altered without anyone noticing.
