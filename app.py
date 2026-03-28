"""
Secure Log Collection & Forensic Analysis System
Flask Web Application - Main Entry Point
"""
import json
import threading
from flask import Flask, render_template, jsonify, request

from secure_logger.chain import LogChain
from secure_logger.real_collector import RealLogCollector
from secure_logger.network_collector import NetworkCollector
from secure_logger.adversary import Adversary
from secure_logger.detection import AttackDetectionEngine
from secure_logger.ips import IPSManager
from secure_logger.alerts import AlertManager
from secure_logger.threat_intel import ThreatIntel
from secure_logger.report import ForensicReportGenerator
from secure_logger.simulator import Simulator

app = Flask(__name__)

# ── Shared State ──────────────────────────────────────────────
log_chain = LogChain()
adversary = Adversary(log_chain)
detector = AttackDetectionEngine()
ips_manager = IPSManager(simulation_mode=True)
alert_manager = AlertManager() # Placeholders for Telegram/Email
intel = ThreatIntel()
reporter = ForensicReportGenerator()
simulator = Simulator(log_chain)

# Collectors
win_collector = None
net_collector = None

# System state
system_state = {
    "collecting": False,
    "mode": None,        # "windows" or "network"
    "ips_enabled": True
}
collection_lock = threading.Lock()




# ── Routes ────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/start", methods=["POST"])
def start_collection():
    global win_collector, net_collector

    data = request.get_json(force=True)
    mode = data.get("mode", "network")

    with collection_lock:
        if system_state["collecting"]:
            return jsonify({"status": "error", "message": "Collection already running. Stop it first."}), 400

        system_state["mode"] = mode
        system_state["collecting"] = True

        if mode == "windows":
            win_collector = RealLogCollector(log_chain, detector, ips_manager)
            win_collector.start(duration=300)
            return jsonify({"status": "ok", "message": "Windows Event Log + Process collection started."})
        else:
            net_collector = NetworkCollector(log_chain, detector, ips_manager, intel)
            net_collector.start(duration=300)
            return jsonify({"status": "ok", "message": "Network packet capture started."})


@app.route("/api/stop", methods=["POST"])
def stop_collection():
    global win_collector, net_collector

    with collection_lock:
        system_state["collecting"] = False
        if net_collector:
            net_collector.stop()
            net_collector = None
        if win_collector:
            win_collector.stop()
            win_collector = None

    return jsonify({"status": "ok", "message": "Collection stopped."})


@app.route("/api/logs", methods=["GET"])
def get_logs():
    blocks = log_chain.get_all_blocks()
    return jsonify({"blocks": blocks, "total": len(blocks)})


@app.route("/api/status", methods=["GET"])
def get_status():
    captured = 0
    alerts = []
    if net_collector:
        captured = net_collector.packets_captured
        alerts = net_collector.alerts
    elif win_collector:
        captured = win_collector.events_captured
        alerts = win_collector.alerts
        
    return jsonify({
        "collecting": system_state["collecting"],
        "mode": system_state["mode"],
        "block_count": len(log_chain.chain),
        "captured_count": captured,
        "alerts_count": len(alerts),
        "recent_alerts": alerts[-5:],
        "ips_status": ips_manager.get_status()
    })

@app.route("/api/stats", methods=["GET"])
def get_stats():
    # Generate stats for charts
    blocks = log_chain.chain
    
    # 1. Attack distribution
    all_alerts = []
    if net_collector: all_alerts = net_collector.alerts
    elif win_collector: all_alerts = win_collector.alerts
    
    attack_counts = {}
    for a in all_alerts:
        t = a['type']
        attack_counts[t] = attack_counts.get(t, 0) + 1
        
    # 2. Risk distribution
    points = []
    for b in blocks[-50:]: # Last 50 blocks
        points.append({
            "time": b.timestamp,
            "risk": b.log_entry.risk_score
        })
        
    return jsonify({
        "attacks": attack_counts,
        "timeline": points
    })

@app.route("/api/simulate/attack", methods=["POST"])
def run_sim_attack():
    data = request.get_json(force=True)
    type = data.get("type", "ddos")
    
    if type == "ddos":
        threading.Thread(target=simulator.simulate_ddos).start()
    elif type == "brute_force":
        threading.Thread(target=simulator.simulate_brute_force).start()
    elif type == "port_scan":
        threading.Thread(target=simulator.simulate_port_scan).start()
        
    return jsonify({"status": "ok", "message": f"Simulating {type}..."})

@app.route("/api/report/generate", methods=["GET"])
def generate_report():
    all_alerts = []
    if net_collector: all_alerts = net_collector.alerts
    elif win_collector: all_alerts = win_collector.alerts
    
    path = reporter.generate(log_chain, {}, all_alerts, "forensic_report.pdf")
    return jsonify({"status": "ok", "report_url": "/api/report/download"})

@app.route("/api/report/download")
def download_report():
    from flask import send_file
    return send_file("forensic_report.pdf", as_attachment=True)


@app.route("/api/attack/modify", methods=["POST"])
def attack_modify():
    data = request.get_json(force=True)
    block_index = data.get("block_index")
    new_message = data.get("new_message", "MALICIOUS_PAYLOAD_INJECTED")

    if block_index is None:
        return jsonify({"status": "error", "message": "block_index is required"}), 400

    block_index = int(block_index)
    if block_index < 0 or block_index >= len(log_chain.chain):
        return jsonify({"status": "error", "message": f"Invalid block index: {block_index}"}), 400

    adversary.attack_modify_content(block_index, new_message)

    tampered_block = log_chain.chain[block_index].to_dict()
    return jsonify({
        "status": "ok",
        "message": f"Block {block_index} tampered successfully.",
        "tampered_block": tampered_block
    })


@app.route("/api/attack/delete", methods=["POST"])
def attack_delete():
    data = request.get_json(force=True)
    block_index = data.get("block_index")

    if block_index is None:
        return jsonify({"status": "error", "message": "block_index is required"}), 400

    block_index = int(block_index)
    if block_index < 0 or block_index >= len(log_chain.chain):
        return jsonify({"status": "error", "message": f"Invalid block index: {block_index}"}), 400

    adversary.attack_chain_break(block_index)
    return jsonify({
        "status": "ok",
        "message": f"Block {block_index} deleted. Chain integrity broken."
    })


@app.route("/api/verify", methods=["GET"])
def verify_chain():
    result = log_chain.verify_integrity()
    blocks = log_chain.get_all_blocks()

    # Build per-block verification detail
    block_details = []
    for i, block in enumerate(log_chain.chain):
        recalculated = block.calculate_hash()
        hash_match = block.hash == recalculated
        link_match = True
        if i > 0:
            link_match = block.previous_hash == log_chain.chain[i - 1].hash

        block_details.append({
            "index": block.index,
            "stored_hash": block.hash[:16] + "...",
            "recalculated_hash": recalculated[:16] + "...",
            "hash_valid": hash_match,
            "link_valid": link_match,
            "source": block.log_entry.source,
            "message": block.log_entry.message[:60],
        })

    return jsonify({
        "result": result,
        "block_details": block_details,
        "total_blocks": len(log_chain.chain),
    })


@app.route("/api/reset", methods=["POST"])
def reset_chain():
    global log_chain, adversary, win_collector, net_collector

    # Stop any active collection
    system_state["collecting"] = False
    if net_collector:
        net_collector.stop()
        net_collector = None
    if win_collector:
        win_collector.stop()
        win_collector = None

    # Reset chain
    log_chain = LogChain()
    adversary = Adversary(log_chain)
    system_state["mode"] = None

    return jsonify({"status": "ok", "message": "System reset. New chain created."})


if __name__ == "__main__":
    print("=" * 60)
    print("  SECURE LOG COLLECTION & FORENSIC ANALYSIS SYSTEM")
    print("  Web Dashboard running at: http://127.0.0.1:5000")
    print("=" * 60)
    app.run(debug=True, host="127.0.0.1", port=5000)
