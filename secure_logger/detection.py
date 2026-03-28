import re
import time
from collections import deque, Counter
import numpy as np
from sklearn.ensemble import IsolationForest

class AttackDetectionEngine:
    """
    Combines rule-based detection and ML-based anomaly detection.
    """
    def __init__(self, threshold_failed_logins=5, time_window=60):
        self.rules = RuleEngine(threshold_failed_logins, time_window)
        self.ml_engine = MLEngine()
        self.recent_events = deque(maxlen=1000)

    def analyze(self, log_entry):
        """Analyzes a log entry and returns (is_attack, attack_type, confidence, risk_score)."""
        # 1. Rule-based checks
        found_attack, attack_type, risk_score = self.rules.evaluate(log_entry)
        
        if found_attack:
            return True, attack_type, "High", risk_score

        # 2. ML Anomaly Detection (Statistical)
        is_anomaly, risk_score = self.ml_engine.predict(log_entry)
        if is_anomaly:
            return True, "Anomaly Detected", "Medium", risk_score

        return False, None, "Low", 0.0

class RuleEngine:
    def __init__(self, threshold_failed_logins=5, time_window=60):
        self.threshold_failed_logins = threshold_failed_logins
        self.time_window = time_window
        # Track failed logins: {ip: [timestamps]}
        self.auth_failures = {}
        # Track port scans: {ip: set(ports)}
        self.port_scans = {}

    def evaluate(self, log_entry):
        src_ip = log_entry.src_ip or "unknown"
        msg = log_entry.message.lower()

        # Brute Force Detection
        if "login failed" in msg or "authentication failure" in msg or "failed password" in msg:
            now = time.time()
            if src_ip not in self.auth_failures:
                self.auth_failures[src_ip] = []
            self.auth_failures[src_ip].append(now)
            
            # Cleanup old entries
            self.auth_failures[src_ip] = [t for t in self.auth_failures[src_ip] if now - t < self.time_window]
            
            if len(self.auth_failures[src_ip]) >= self.threshold_failed_logins:
                return True, "Brute Force Attack", 0.9

        # Port Scan Detection
        if log_entry.event_type == "NETWORK_PACKET" and log_entry.dst_port:
            if src_ip not in self.port_scans:
                self.port_scans[src_ip] = set()
            self.port_scans[src_ip].add(log_entry.dst_port)
            
            if len(self.port_scans[src_ip]) > 10: # More than 10 unique ports from same IP
                return True, "Port Scan", 0.7

        # DDoS Pattern (Simpler rule for high frequency)
        # Note: True DDoS detection is better handled by ML traffic spikes

        # Specific Signatures
        if "sql injection" in msg or "union select" in msg:
            return True, "SQL Injection", 1.0
        if "nmap" in msg or "masscan" in msg:
            return True, "Reconnaissance (Tool Detected)", 0.8
            
        return False, None, 0.0

class MLEngine:
    """
    A simple statistical anomaly detector.
    In a real system, this would be trained on historical normal data.
    """
    def __init__(self):
        self.traffic_history = deque(maxlen=100)
        self.is_trained = False
        
    def predict(self, log_entry):
        # We model "normal" as the frequency of events over time
        now = time.time()
        self.traffic_history.append(now)
        
        if len(self.traffic_history) < 20:
            return False, 0.0
            
        # Calculate event rate (events per second)
        intervals = [self.traffic_history[i] - self.traffic_history[i-1] for i in range(1, len(self.traffic_history))]
        avg_interval = np.mean(intervals)
        
        # If interval is significantly smaller than average (burst), flag as anomaly
        if avg_interval > 0 and (now - self.traffic_history[-2]) < (avg_interval * 0.1): # 10x faster than normal
            return True, 0.6
            
        return False, 0.0
