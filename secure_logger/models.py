import hashlib
import json
import time
from datetime import datetime

class LogEntry:
    """
    Represents a raw log entry from a source (e.g., Firewall, Web Server).
    """
    def __init__(self, source: str, event_type: str, message: str, severity: str = "INFO"):
        self.timestamp = datetime.now().isoformat()
        self.source = source
        self.event_type = event_type
        self.message = message
        self.severity = severity
    
    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "source": self.source,
            "event_type": self.event_type,
            "message": self.message,
            "severity": self.severity
        }

    def to_string(self):
        """Returns a string representation for display."""
        return f"[{self.timestamp}] [{self.severity}] {self.source}: {self.message}"

class Block:
    """
    A Secure Block containing a LogEntry and cryptographic proofs.
    """
    def __init__(self, index: int, previous_hash: str, log_entry: LogEntry):
        self.index = index
        self.timestamp = time.time()
        self.log_entry = log_entry
        self.previous_hash = previous_hash
        self.nonce = 0 # For potential Proof of Work (optional, using 0 for now)
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        """
        SHA-256 Hashing of the block content.
        This provides the 'Immutability' property. Use this explanation for your review.
        """
        block_string = json.dumps({
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "log": self.log_entry.to_dict(),
            "nonce": self.nonce
        }, sort_keys=True).encode()
        
        return hashlib.sha256(block_string).hexdigest()

    def to_dict(self):
        return {
            "index": self.index,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "log": self.log_entry.to_dict(),
            "hash": self.hash
        }
