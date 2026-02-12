from typing import List
from .models import Block, LogEntry

class LogChain:
    """
    Manages the Blockchain-like structure for logs.
    """
    def __init__(self):
        self.chain: List[Block] = []
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Creates the first block in the chain. 
        It has no previous hash (arbitrary '0's).
        """
        genesis_log = LogEntry("System", "BOOT", "Secure Log System Initialized", "SYSTEM")
        genesis_block = Block(0, "0" * 64, genesis_log)
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_log(self, source: str, event_type: str, message: str, severity: str = "INFO"):
        """
        Adds a new log to the secure chain.
        """
        new_log = LogEntry(source, event_type, message, severity)
        previous_block = self.get_latest_block()
        
        # Link to the previous hash - This creates the 'Chain'
        new_block = Block(len(self.chain), previous_block.hash, new_log)
        self.chain.append(new_block)
        return new_block

    def verify_integrity(self) -> dict:
        """
        Checks the entire chain for tampering.
        Returns: {'valid': bool, 'broken_index': int}
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check 1: Is the data still the same? (Hash Check)
            if current_block.hash != current_block.calculate_hash():
                return {"valid": False, "reason": "Data Modification Detected", "broken_index": i}

            # Check 2: Is the chain broken? (Link Check)
            if current_block.previous_hash != previous_block.hash:
                return {"valid": False, "reason": "Chain Link Broken", "broken_index": i}

        return {"valid": True, "reason": "Integrity Verified", "broken_index": None}

    def get_all_blocks(self):
        return [b.to_dict() for b in self.chain]
