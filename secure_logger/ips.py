import os
import subprocess
import time

class IPSManager:
    """
    Intrusion Prevention System (IPS) Manager.
    Handles automated blocking of malicious IPs.
    """
    def __init__(self, simulation_mode=True):
        self.simulation_mode = simulation_mode
        self.blocked_ips = set()
        self.ip_block_expiry = {}

    def block_ip(self, ip, duration=3600):
        """Blocks an IP for a specific duration (seconds)."""
        if ip in self.blocked_ips:
            return False

        print(f"[IPS MANAGER] 🛡 BLOCKING IP: {ip} for {duration}s")
        self.blocked_ips.add(ip)
        self.ip_block_expiry[ip] = time.time() + duration

        if not self.simulation_mode:
            self._real_block(ip)
            
        return True

    def is_blocked(self, ip):
        """Checks if an IP is currently blocked."""
        if ip in self.blocked_ips:
            # Check for expiry
            if time.time() > self.ip_block_expiry.get(ip, 0):
                self._unblock_ip(ip)
                return False
            return True
        return False

    def _real_block(self, ip):
        """Actually blocks an IP on Windows using netsh."""
        try:
            # Requires Admin privileges
            cmd = f'netsh advfirewall firewall add rule name="Block-IPS-{ip}" dir=in action=block remoteip={ip}'
            subprocess.run(cmd, shell=True, check=True, capture_output=True)
            print(f"[IPS] Successfully added Windows Firewall rule for {ip}")
        except Exception as e:
            print(f"[IPS] Failed to add firewall rule: {e}")

    def _unblock_ip(self, ip):
        """Unblocks an IP."""
        if ip in self.blocked_ips:
            print(f"[IPS MANAGER] 🔓 UNBLOCKING IP: {ip}")
            self.blocked_ips.remove(ip)
            if ip in self.ip_block_expiry:
                del self.ip_block_expiry[ip]

            if not self.simulation_mode:
                try:
                    cmd = f'netsh advfirewall firewall delete rule name="Block-IPS-{ip}"'
                    subprocess.run(cmd, shell=True, check=True, capture_output=True)
                except:
                    pass

    def get_status(self):
        return {
            "blocked_count": len(self.blocked_ips),
            "blocked_ips": list(self.blocked_ips)
        }
