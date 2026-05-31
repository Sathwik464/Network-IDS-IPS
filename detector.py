from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
from collections import defaultdict
import subprocess
import time
import csv
import os

# ─── CONFIG ───────────────────────────────────────────
PORT_SCAN_THRESHOLD = 10
PACKET_SPIKE_THRESHOLD = 100
TIME_WINDOW = 30
LOG_DIR = "logs"
TRAFFIC_LOG = f"{LOG_DIR}/traffic.csv"
ALERT_LOG = f"{LOG_DIR}/alerts.log"
# ──────────────────────────────────────────────────────

# Create logs directory if it doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)

# Create CSV file with headers if it doesn't exist
if not os.path.exists(TRAFFIC_LOG):
    with open(TRAFFIC_LOG, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "src_ip", "dst_ip", "protocol", "src_port", "dst_port"])

# Trackers
port_tracker = defaultdict(list)
packet_tracker = defaultdict(list)
blocked_ips = set()

def get_time():
    return datetime.now().strftime("%H:%M:%S")

def log_traffic(src, dst, proto, sport, dport):
    """Write packet info to CSV"""
    with open(TRAFFIC_LOG, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([get_time(), src, dst, proto, sport, dport])

def log_alert(alert_type, src, detail, action):
    """Write alert to log file"""
    entry = f"[{get_time()}] ALERT | {alert_type} | src={src} | {detail} | action={action}\n"
    with open(ALERT_LOG, "a") as f:
        f.write(entry)
    # Also print to terminal
    print(f"\n{'!'*50}")
    print(f"[{get_time()}] ⚠️  ALERT: {alert_type}")
    print(f"           Source IP : {src}")
    print(f"           Detail    : {detail}")
    print(f"           Action    : {action}")
    print(f"{'!'*50}\n")

def block_ip(ip):
    """Block IP using iptables and log it"""
    try:
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
            check=True,
            capture_output=True
        )
        print(f"[{get_time()}] 🚫 BLOCKED: {ip} added to iptables")
        return "BLOCKED"
    except subprocess.CalledProcessError as e:
        print(f"[{get_time()}] ❌ Failed to block {ip}: {e}")
        return "BLOCK_FAILED"

def clean_old_entries(tracker, ip, window):
    now = time.time()
    tracker[ip] = [t for t in tracker[ip] if now - t[0] < window]

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        now = time.time()

        if src in blocked_ips:
            return

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport

            # Log to CSV
            log_traffic(src, dst, "TCP", sport, dport)
            print(f"[{get_time()}] TCP | {src}:{sport} → {dst}:{dport}")

            # Port scan detection
            port_tracker[src].append((now, dport))
            clean_old_entries(port_tracker, src, TIME_WINDOW)
            unique_ports = set(p[1] for p in port_tracker[src])

            if len(unique_ports) >= PORT_SCAN_THRESHOLD:
                action = block_ip(src) if src not in blocked_ips else "ALREADY_BLOCKED"
                blocked_ips.add(src)
                log_alert(
                    "PORT SCAN DETECTED",
                    src,
                    f"ports={len(unique_ports)}",
                    action
                )
                port_tracker[src] = []

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport

            # Log to CSV
            log_traffic(src, dst, "UDP", sport, dport)
            print(f"[{get_time()}] UDP | {src}:{sport} → {dst}:{dport}")

        # Traffic spike detection (TCP + UDP)
        if TCP in packet or UDP in packet:
            packet_tracker[src].append((now, 1))
            clean_old_entries(packet_tracker, src, TIME_WINDOW)

            if len(packet_tracker[src]) >= PACKET_SPIKE_THRESHOLD:
                action = block_ip(src) if src not in blocked_ips else "ALREADY_BLOCKED"
                blocked_ips.add(src)
                log_alert(
                    "TRAFFIC SPIKE DETECTED",
                    src,
                    f"packets={len(packet_tracker[src])}",
                    action
                )
                packet_tracker[src] = []

print("🔍 IDS/IPS Running — watching for threats...\n")
print(f"📁 Logging traffic to  : {TRAFFIC_LOG}")
print(f"📁 Logging alerts to   : {ALERT_LOG}\n")

sniff(filter="ip", prn=process_packet, count=0, store=False)
