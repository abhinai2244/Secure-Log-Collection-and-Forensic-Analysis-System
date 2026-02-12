from .chain import LogChain

class Adversary:
    """
    Simulates an attacker trying to tamper with the existing logs.
    """
    def __init__(self, log_chain: LogChain):
        self.chain = log_chain

    def attack_modify_content(self, block_index: int, new_message: str):
        """
        Attack 1: Modify a log's content after it has been hashed.
        This invalidates the hash of the block.
        """
        if block_index >= len(self.chain.chain):
            print("[-] Attack Failed: Index out of range")
            return

        print(f"[!] ATTACK: Modifying Block {block_index}...")
        # Direct modification of the object (Simulating DB intrusion)
        self.chain.chain[block_index].log_entry.message = new_message
        self.chain.chain[block_index].log_entry.event_type = "HACKED_EVENT"
        # The adversary does NOT re-calculate the hash (because they can't sign it properly or just clumsy)
        # Or even if they updated the hash, the NEXT block would break.

    def attack_chain_break(self, block_index: int):
        """
        Attack 2: Forcefully deleting a block to hide evidence.
        """
        if block_index >= len(self.chain.chain):
            return
        
        print(f"[!] ATTACK: Deleting Block {block_index}...")
        del self.chain.chain[block_index] 
        # Now Index N's previous_hash won't match Index N-1's hash because N-1 changed (it's a different block now)
