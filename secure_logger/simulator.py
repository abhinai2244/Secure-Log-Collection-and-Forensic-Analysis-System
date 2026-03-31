import random
import time
from .chain import LogChain

class Simulator:
    """
    Simulates a network environment generating logs.
    """
    def __init__(self, log_chain: LogChain, detector=None, ips=None):
        self.chain = log_chain
        self.detector = detector
        self.ips = ips
        self.captured_count = 0
        self.alerts = []

    def _process_added_block(self, block):
        self.captured_count += 1
        if self.detector:
            is_attack, attack_type, confidence, score = self.detector.analyze(block.log_entry)
            if is_attack:
                self.alerts.append({
                    "type": attack_type,
                    "details": block.log_entry.message,
                    "risk_score": score,
                    "block_index": block.index
                })
                if score > 0.8 and self.ips and block.log_entry.src_ip:
                    self.ips.block_ip(block.log_entry.src_ip)

    def generate_random_log(self):
        """
        Generates a single random log entry and adds it to the chain.
        """
        scenarios = [
            self._web_traffic,
            self._web_traffic, # Higher probability
            self._firewall_event,
            self._auth_event,
            self._system_event
        ]
        
        event_func = random.choice(scenarios)
        source, event_type, message, severity = event_func()
        
        block = self.chain.add_log(source, event_type, message, severity)
        self._process_added_block(block)
        return block

    def _web_traffic(self):
        methods = ["GET", "POST", "PUT"]
        endpoints = ["/index.html", "/api/login", "/images/logo.png", "/admin", "/contact"]
        status = random.choices([200, 304, 404, 500], weights=[70, 10, 15, 5])[0]
        ip = f"192.168.1.{random.randint(2, 254)}"
        
        message = f"{random.choice(methods)} {random.choice(endpoints)} HTTP/1.1 {status} from {ip}"
        severity = "INFO" if status < 400 else "ERROR"
        return "WebServer01", "WEB_ACCESS", message, severity

    def _firewall_event(self):
        action = random.choice(["ALLOW", "BLOCK", "DROP"])
        src_ip = f"10.0.0.{random.randint(50, 150)}"
        dst_port = random.choice([80, 443, 22, 3389])
        
        message = f"{action} packet from {src_ip} on port {dst_port}"
        severity = "INFO" if action == "ALLOW" else "WARNING"
        return "FirewallMain", "PACKET_FILTER", message, severity

    def _auth_event(self):
        user = random.choice(["admin", "guest", "user101", "jdoe"])
        status = random.choice(["Success", "Failed", "Locked Out"])
        
        message = f"Login {status} for user '{user}'"
        severity = "INFO" if status == "Success" else "CRITICAL"
        return "AuthServer", "LOGIN", message, severity

    def _system_event(self):
        service = random.choice(["cron", "sshd", "docker", "apache2"])
        action = random.choice(["Started", "Stopped", "Restarting", "Crashed"])
        
        message = f"Service {service} {action}"
        severity = "INFO" if action != "Crashed" else "CRITICAL"
        return "SysLog", "SERVICE_STATUS", message, severity

    # New Attack Simulations
    def simulate_brute_force(self):
        """Simulates a sequence of failed logins from a single IP."""
        ip = "185.99.11.22"
        user = "admin"
        print(f"[SIMULATOR] Starting Brute Force Attack from {ip}...")
        for i in range(10):
            msg = f"Failed password for {user} from {ip} port 54321 ssh2"
            block = self.chain.add_log(f"AuthServer", "LOGIN_FAILURE", msg, "CRITICAL", src_ip=ip)
            self._process_added_block(block)
            time.sleep(0.5)

    def simulate_ddos(self):
        """Simulates a rapid burst of packets (DDoS)."""
        target = "192.168.1.1"
        source = "45.33.22.11" # Malicious IP from ThreatIntel
        print(f"[SIMULATOR] Starting DDoS Traffic Spike from {source}...")
        for _ in range(30):
            msg = f"TCP {source} -> {target}:80 Flags=SYN [FLOOD]"
            block = self.chain.add_log(f"NetCapture:{source}", "NETWORK_PACKET", msg, "INFO", src_ip=source, dst_port=80)
            self._process_added_block(block)
            time.sleep(0.1)

    def simulate_port_scan(self):
        """Simulates scanning multiple ports on a target."""
        ip = "10.0.0.99"
        target = "192.168.1.5"
        print(f"[SIMULATOR] Starting Port Scan from {ip}...")
        for port in range(20, 100, 5):
            msg = f"TCP {ip} -> {target}:{port} Flags=SYN"
            block = self.chain.add_log(f"NetCapture:{ip}", "NETWORK_PACKET", msg, "WARNING", src_ip=ip, dst_port=port)
            self._process_added_block(block)
            time.sleep(0.3)

    def run_simulation(self, count=5, delay=0.5):
        """Runs a burst of log generation."""
        print(f"--- Simulating {count} Events ---")
        for _ in range(count):
            block = self.generate_random_log()
            print(f"[+] New Log: {block.log_entry.to_string()}")
            time.sleep(delay)
