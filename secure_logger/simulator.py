import random
import time
from .chain import LogChain

class Simulator:
    """
    Simulates a network environment generating logs.
    """
    def __init__(self, log_chain: LogChain):
        self.chain = log_chain

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
        
        return self.chain.add_log(source, event_type, message, severity)

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

    def run_simulation(self, count=5, delay=0.5):
        """Runs a burst of log generation."""
        print(f"--- Simulating {count} Events ---")
        for _ in range(count):
            block = self.generate_random_log()
            print(f"[+] New Log: {block.log_entry.to_string()}")
            time.sleep(delay)
