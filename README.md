# Secure Log Collection & Forensic Analysis System
## Simulation Demo

This project demonstrates a secure logging system using **SHA-256 Hash Chaining** (Blockchain concepts) to ensure log integrity and detect tampering.

### Prerequisites

- Python 3.x installed.

### Project Structure

- `secure_logger/`: Core Python package.
    - `models.py`: Defines the `LogEntry` and `Block` structure.
    - `chain.py`: Manages the secure hash chain and verification logic.
    - `simulator.py`: Generates realistic network traffic (WebServer, Firewall, Auth).
    - `adversary.py`: Simulates an attack (modifying logs) to test security.
- `demo.py`: The main script to run the simulation.

### How to Run the Demo

1.  Open a terminal in this folder.
2.  Run the following command:

```bash
python demo.py
```

### What to Expect

1.  **Phase 1 & 2**: You will see logs being generated in real-time. The system creates a "Chain" where each log is cryptographically linked to the previous one.
2.  **Phase 3**: You will be prompted to simulating an **ATTACK**. The system will use the `Adversary` module to secretly modify a past log entry (e.g., changing a "Login Failed" to "Success").
3.  **Phase 4**: The system performs a **Forensic Verification**. It will recount the hashes and detect that the chain has been broken, identifying exactly which block was tampered with.

### Key Concepts for Your Review
- **Immutability**: Once a log is hashed, changing it invalidates the hash.
- **Traceability**: The "Previous Hash" link ensures that deleting or inserting logs breaks the chain.
- **Forensics**: We can mathematically prove *when* and *where* a breach occurred.
