import requests

class ThreatIntel:
    """
    Checks IP reputation and known malicious domains using public blacklists.
    (Simulated/Mocked for this prototype, but extensible to OTX/AbuseIPDB)
    """
    def __init__(self):
        # Sample malicious IP database
        self.malicious_ips = {
            "185.123.45.67": "Known Cobalt Strike C2",
            "45.33.22.11": "Active Brute Forcer",
            "103.1.2.3": "Known Tor Exit Node",
            "192.168.1.10": "Internal Malicious Simulator" # For testing
        }
        self.malicious_domains = [
            "evil-c2-server.xyz",
            "phish-login-bank.com",
            "cryptominer-pool.org"
        ]

    def check_ip(self, ip):
        """Returns (is_malicious, description)"""
        if ip in self.malicious_ips:
            return True, self.malicious_ips[ip]
        return False, None

    def check_domain(self, domain):
        """Returns (is_malicious)"""
        for mal_domain in self.malicious_domains:
            if mal_domain in domain:
                return True
        return False

    def get_blacklist_stats(self):
        return {
            "total_ips": len(self.malicious_ips),
            "total_domains": len(self.malicious_domains)
        }
