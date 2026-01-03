import os
import time
import sys
from secure_logger.chain import LogChain
from secure_logger.real_collector import RealLogCollector
from secure_logger.adversary import Adversary

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    print("="*60)
    print("   SECURE LOG COLLECTION & FORENSIC ANALYSIS SYSTEM")
    print("   REAL-TIME WINDOWS EVENT MONITORING")
    print("="*60)

def show_chain_status(chain):
    print("\n[Current Chain State]")
    if not chain.chain:
        print(" Chain is empty.")
        return

    for block in chain.chain:
        short_hash = block.hash[:8] + "..."
        prev_hash = block.previous_hash[:8] + "..."
        # Displaying Source to prove it's real
        print(f" Block {block.index} | {block.log_entry.source[:15].ljust(15)} | {block.log_entry.severity} | {block.log_entry.message[:40]}...")
    
    verify_result = chain.verify_integrity()
    print("-" * 60)
    if verify_result['valid']:
        print(f" STATUS: [SECURE] Integrity Verified. Chain is unbroken.")
    else:
        print(f" STATUS: [CRITICAL FAILURE] TAMPERING DETECTED!")
        print(f" Reason: {verify_result['reason']}")
        print(f" Block Index: {verify_result['broken_index']}")
    print("="*60)

def main():
    clear_screen()
    print_header()
    print("\n[Phase 1] Initializing Secure Chain...")
    my_chain = LogChain()
    collector = RealLogCollector(my_chain)
    adversary = Adversary(my_chain)
    time.sleep(1)

    print("\n[Phase 2] Capturing LIVE Windows 'Application' Logs...")
    print("Listening for events... (Try opening an app or doing something to generate logs)")
    
    # Run for 15 seconds or until we have at least 3 logs
    try:
        collector.run_live_monitoring(duration_seconds=15, poll_interval=1.5)
    except KeyboardInterrupt:
        pass
    
    if len(my_chain.chain) <= 1:
        print("\n[!] Not enough real logs captured in time.")
        print("Generating one dummy log to ensure demo continues...")
        my_chain.add_log("ManualTrigger", "TEST_EVENT", "Fallback log for demo purposes", "INFO")

    show_chain_status(my_chain)
    input("\nPress Enter to simulate an ATTACK on these REAL logs...")

    clear_screen()
    print_header()
    print("\n[Phase 3] ADVERSARY ACTIVE: Tampering with captured data...")
    
    # Attack: Tamper with the last real log
    target_index = len(my_chain.chain) - 1
    if target_index > 0:
        adversary.attack_modify_content(target_index, "MALICIOUS_PAYLOAD_INSERTED_HERE")
        time.sleep(1)
        print(f"Details: Adversary injected fake data into Block {target_index} (which was a real Windows Event).")
    else:
        print("Not enough blocks to attack.")

    input("\nPress Enter to run FORENSIC VERIFICATION...")
    
    print("\n[Phase 4] Running Forensic Analysis...")
    time.sleep(1)
    show_chain_status(my_chain)

    print("\n[Simulation Complete]")

if __name__ == "__main__":
    main()
