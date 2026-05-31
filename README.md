# 🛡️ Network Intrusion Detection & Prevention System (IDS/IPS)

A real-time Network Intrusion Detection and Prevention System built from scratch using Python and Scapy on Linux. The system captures live TCP/IP traffic, detects malicious patterns using a sliding window algorithm, automatically blocks attacking IPs via iptables, and generates an auto-refreshing HTML security dashboard.

> Built as part of a Cybersecurity Internship at Exposys Data Labs, Bengaluru.

---

## 🚀 Features

- **Live Packet Capture** — Captures all inbound TCP/UDP traffic in real time using Scapy
- **Port Scan Detection** — Flags IPs hitting 10+ unique ports within a 30-second sliding window
- **Traffic Spike Detection** — Detects abnormal packet volume from a single source IP
- **Automated IP Blocking** — Dynamically inserts iptables DROP rules at the kernel level upon detection
- **Structured Logging** — Logs all traffic to `traffic.csv` and all alerts to `alerts.log`
- **Auto-Refreshing Dashboard** — HTML security report regenerated every 5 seconds showing real-time stats

---

## 🏗️ Architecture

```
Network Interface
      ↓
Scapy Packet Sniffer (detector.py)
      ↓
┌─────────────────────────────────┐
│      Detection Engine           │
│                                 │
│  Sliding Window Algorithm       │
│  ├── Port Scan Detection        │
│  └── Traffic Spike Detection    │
└─────────────────────────────────┘
      ↓
┌─────────────────────────────────┐
│      Response Layer             │
│                                 │
│  iptables DROP rule inserted    │
│  IP added to blocked_ips set    │
└─────────────────────────────────┘
      ↓
┌─────────────────────────────────┐
│      Logging & Reporting        │
│                                 │
│  traffic.csv  — all packets     │
│  alerts.log   — all threats     │
│  report.html  — dashboard       │
└─────────────────────────────────┘
```

---

## 🔍 How It Works

### Sliding Window Algorithm
The core detection logic maintains a time-stamped tracker per source IP. Every 30 seconds the window slides forward, removing stale entries. If a single IP hits 10+ unique destination ports within the window, it is flagged as a port scan.

```
port_tracker = {
    "192.168.1.5": [(t1, 22), (t2, 80), (t3, 443), ...]
}

unique_ports = {22, 80, 443, 8080, ...}
if len(unique_ports) >= 10 → ALERT + BLOCK
```

### Automated Blocking
Upon detection, Python's `subprocess` module inserts an iptables rule at the kernel level:
```bash
iptables -A INPUT -s <attacker_ip> -j DROP
```
The attacker's packets are silently dropped — no response, no connection.

### Auto-Refreshing Dashboard
`report.py` reads live log files and regenerates an HTML dashboard every 5 seconds via:
```bash
watch -n 5 python3 report.py
```
The browser refreshes every 10 seconds using an HTML meta tag.

---

## 🛠️ Tech Stack

| Component | Technology |
|---|---|
| Packet Capture | Python, Scapy |
| Detection Logic | Python, Sliding Window Algorithm |
| Firewall Blocking | Linux iptables |
| Logging | CSV, Plain text |
| Dashboard | HTML, CSS |
| OS | Linux (Ubuntu/WSL) |

---

## ⚙️ Setup & Installation

### Prerequisites
- Linux (Ubuntu/Debian) or WSL
- Python 3.x
- Root/sudo access (required for packet capture)

### Install Dependencies

```bash
# Clone the repository
git clone https://github.com/Sathwik464/Network-IDS-IPS.git
cd Network-IDS-IPS

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install required packages
pip install scapy
```

---

## ▶️ Running the Project

### Terminal 1 — Start the IDS/IPS
```bash
sudo ~/Network-IDS-IPS/venv/bin/python detector.py
```

### Terminal 2 — Auto-generate report every 5 seconds
```bash
source venv/bin/activate
watch -n 5 python3 report.py
```

### Terminal 3 — Simulate a port scan (for testing)
```bash
sudo ~/Network-IDS-IPS/venv/bin/python - <<EOF
from scapy.all import send, IP, TCP
import time

target = "YOUR_IP_HERE"  # replace with your machine's IP
ports = [20,21,22,23,25,53,80,110,143,443,445,3306,3389,8080,8443]

for port in ports:
    send(IP(dst=target)/TCP(dport=port, flags="S"), verbose=False)
    time.sleep(0.01)
