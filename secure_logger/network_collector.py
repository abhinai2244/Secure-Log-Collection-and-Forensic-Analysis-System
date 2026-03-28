import threading
import time
import random
from datetime import datetime
from .chain import LogChain

# Try importing scapy; fall back to simulation if unavailable
try:
    from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("[!] Scapy not available. Using simulated network packets.")

class NetworkCollector:
    """
    Captures real-time network packets and stores them in the secure log chain.
    Falls back to simulated network traffic if scapy/Npcap is not installed.
    """
    def __init__(self, log_chain: LogChain, detection_engine=None, ips_manager=None, threat_intel=None):
        self.chain = log_chain
        self.detector = detection_engine
        self.ips = ips_manager
        self.intel = threat_intel
        self._running = False
        self._thread = None
        self.packets_captured = 0
        self.alerts = []

    def start(self, duration=60):
        """Start packet capture in a background thread."""
        if self._running:
            return
        self._running = True
        self.packets_captured = 0
        if SCAPY_AVAILABLE:
            self._thread = threading.Thread(target=self._sniff_live, args=(duration,), daemon=True)
        else:
            self._thread = threading.Thread(target=self._simulate_traffic, args=(duration,), daemon=True)
        self._thread.start()

    def stop(self):
        """Stop the packet capture."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=3)
            self._thread = None

    def _sniff_live(self, duration):
        """Use scapy to sniff real network packets."""
        start = time.time()
        try:
            sniff(
                prn=self._process_packet,
                store=False,
                timeout=duration,
                stop_filter=lambda _: not self._running
            )
        except Exception as e:
            print(f"[!] Scapy sniff error: {e}. Falling back to simulation.")
            self._simulate_traffic(duration - (time.time() - start))

    def _process_packet(self, pkt):
        """Process a single captured packet and add to chain."""
        if not self._running:
            return

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            proto = "OTHER"
            port = "-"
            detail = ""

            if TCP in pkt:
                proto = "TCP"
                port = str(pkt[TCP].dport)
                flags = str(pkt[TCP].flags)
                detail = f"Flags={flags}"
            elif UDP in pkt:
                proto = "UDP"
                port = str(pkt[UDP].dport)
                if DNS in pkt and pkt.haslayer(DNSQR):
                    proto = "DNS"
                    try:
                        detail = f"Query={pkt[DNSQR].qname.decode()}"
                    except:
                        detail = "DNS Query"

            message = f"{proto} {src_ip} -> {dst_ip}:{port} {detail}"
            severity = "INFO"

            # Check if source is blocked
            if self.ips and self.ips.is_blocked(src_ip):
                return # Drop packet from blocked IP

            # Threat Intel Check
            if self.intel:
                is_mal, intel_desc = self.intel.check_ip(src_ip)
                if is_mal:
                    severity = "CRITICAL"
                    message += f" [THREAT INTEL: {intel_desc}]"

            # Add to chain
            block = self.chain.add_log(f"NetCapture:{src_ip}", "NETWORK_PACKET", message[:150], severity, src_ip=src_ip, dst_port=int(port) if port.isdigit() else None)
            self.packets_captured += 1

            # Analyze for attacks
            if self.detector:
                is_attack, attack_type, confidence, score = self.detector.analyze(block.log_entry)
                if is_attack:
                    alert = {"type": attack_type, "details": message, "risk_score": score, "block_index": block.index}
                    self.alerts.append(alert)
                    # Block if high risk and IPS active
                    if score > 0.8 and self.ips:
                        self.ips.block_ip(src_ip)

    def _simulate_traffic(self, duration):
        """Fallback: Generate realistic simulated network traffic."""
        start = time.time()
        while self._running and (time.time() - start) < duration:
            scenario = random.choice([
                self._sim_http, self._sim_dns, self._sim_ssh,
                self._sim_https, self._sim_suspicious
            ])
            source, event_type, message, severity = scenario()
            self.chain.add_log(source, event_type, message, severity)
            self.packets_captured += 1
            time.sleep(random.uniform(0.5, 2.0))

    def _sim_http(self):
        ip = f"192.168.1.{random.randint(2, 254)}"
        dst = random.choice(["93.184.216.34", "142.250.80.46", "151.101.1.69"])
        method = random.choice(["GET", "POST"])
        path = random.choice(["/index.html", "/api/data", "/login", "/search?q=test"])
        return (f"NetCapture:{ip}", "NETWORK_PACKET",
                f"TCP {ip} -> {dst}:80 {method} {path}", "INFO")

    def _sim_dns(self):
        ip = f"192.168.1.{random.randint(2, 254)}"
        domain = random.choice(["google.com", "github.com", "stackoverflow.com", "evil-c2-server.xyz"])
        severity = "WARNING" if "evil" in domain else "INFO"
        return (f"NetCapture:{ip}", "NETWORK_PACKET",
                f"DNS {ip} -> 8.8.8.8:53 Query={domain}", severity)

    def _sim_ssh(self):
        ip = f"10.0.0.{random.randint(50, 150)}"
        dst = f"192.168.1.{random.randint(2, 10)}"
        status = random.choice(["SYN", "SYN-ACK", "RST"])
        severity = "WARNING" if status == "RST" else "INFO"
        return (f"NetCapture:{ip}", "NETWORK_PACKET",
                f"TCP {ip} -> {dst}:22 Flags={status}", severity)

    def _sim_https(self):
        ip = f"192.168.1.{random.randint(2, 254)}"
        dst = random.choice(["172.217.14.206", "31.13.65.36", "52.94.236.248"])
        return (f"NetCapture:{ip}", "NETWORK_PACKET",
                f"TCP {ip} -> {dst}:443 TLS Handshake", "INFO")

    def _sim_suspicious(self):
        ip = f"10.0.0.{random.randint(200, 250)}"
        dst = f"192.168.1.{random.randint(2, 10)}"
        port = random.choice([4444, 5555, 31337, 1337])
        return (f"NetCapture:{ip}", "NETWORK_PACKET",
                f"TCP {ip} -> {dst}:{port} Flags=SYN [SUSPICIOUS PORT]", "CRITICAL")
