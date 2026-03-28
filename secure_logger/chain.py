from typing import List
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from .models import Block, LogEntry

class LogChain:
    """
    Manages the Blockchain-like structure for logs.
    """
    def __init__(self):
        self.chain: List[Block] = []
        # Generate RSA Key Pair for digital signatures
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        
        self.create_genesis_block()

    def create_genesis_block(self):
        """
        Creates the first block in the chain. 
        It has no previous hash (arbitrary '0's).
        """
        genesis_log = LogEntry("System", "BOOT", "Secure Log System Initialized", "SYSTEM")
        # Genesis block is also signed
        signature = self._sign_data(genesis_log.to_dict())
        genesis_block = Block(0, "0" * 64, genesis_log, signature, self.public_key_pem)
        self.chain.append(genesis_block)

    def get_latest_block(self) -> Block:
        return self.chain[-1]

    def add_log(self, source: str, event_type: str, message: str, severity: str = "INFO", src_ip: str = None, dst_port: int = None):
        """
        Adds a new log to the secure chain.
        """
        new_log = LogEntry(source, event_type, message, severity, src_ip, dst_port)
        previous_block = self.get_latest_block()
        
        # Sign the log entry
        signature = self._sign_data(new_log.to_dict())
        
        # Link to the previous hash - This creates the 'Chain'
        new_block = Block(len(self.chain), previous_block.hash, new_log, signature, self.public_key_pem)
        self.chain.append(new_block)
        return new_block

    def _sign_data(self, data: dict) -> str:
        """Signs the data dictionary using the private key."""
        message = json.dumps(data, sort_keys=True).encode()
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature).decode()

    def _verify_signature(self, data: dict, signature_b64: str, public_key_pem: str) -> bool:
        """Verifies the digital signature using the provided public key."""
        try:
            public_key = serialization.load_pem_public_key(public_key_pem.encode())
            signature = base64.b64decode(signature_b64)
            message = json.dumps(data, sort_keys=True).encode()
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

    def verify_integrity(self) -> dict:
        """
        Checks the entire chain for tampering.
        Returns: {'valid': bool, 'broken_index': int, 'reason': str}
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i - 1]

            # Check 1: Is the data still the same? (Hash Check)
            if current_block.hash != current_block.calculate_hash():
                return {"valid": False, "reason": "Data Modification Detected (Hash Mismatch)", "broken_index": i}

            # Check 2: Is the chain broken? (Link Check)
            if current_block.previous_hash != previous_block.hash:
                return {"valid": False, "reason": "Chain Link Broken", "broken_index": i}
            
            # Check 3: Digital Signature Check (Non-repudiation)
            if not self._verify_signature(current_block.log_entry.to_dict(), current_block.signature, current_block.public_key):
                 return {"valid": False, "reason": "Digital Signature Invalid", "broken_index": i}

        return {"valid": True, "reason": "Integrity & Signatures Verified", "broken_index": None}

    def get_all_blocks(self):
        return [b.to_dict() for b in self.chain]
