import csv
import os
from datetime import datetime

TRAFFIC_LOG = "logs/traffic.csv"
ALERT_LOG = "logs/alerts.log"
REPORT_FILE = "logs/report.html"

def read_traffic():
    packets = []
    if not os.path.exists(TRAFFIC_LOG):
        return packets
    with open(TRAFFIC_LOG, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            packets.append(row)
    return packets

def read_alerts():
    alerts = []
    if not os.path.exists(ALERT_LOG):
        return alerts
    with open(ALERT_LOG, "r") as f:
        for line in f:
            line = line.strip()
            if line:
                alerts.append(line)
    return alerts

def generate_report():
    packets = read_traffic()
    alerts = read_alerts()

    # ─── Stats ───────────────────────────────────────────
    total_packets = len(packets)
    total_alerts = len(alerts)

    # Count unique IPs
    unique_ips = set(p["src_ip"] for p in packets)

    # Count blocked IPs from alerts
    blocked_ips = set()
    for alert in alerts:
        if "action=BLOCKED" in alert:
            for part in alert.split("|"):
                if "src=" in part:
                    ip = part.strip().replace("src=", "")
                    blocked_ips.add(ip)

    # Protocol breakdown
    tcp_count = sum(1 for p in packets if p["protocol"] == "TCP")
    udp_count = sum(1 for p in packets if p["protocol"] == "UDP")

    # Top 5 source IPs
    ip_counts = {}
    for p in packets:
        ip = p["src_ip"]
        ip_counts[ip] = ip_counts.get(ip, 0) + 1
    top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # Top 5 destination ports
    port_counts = {}
    for p in packets:
        port = p["dst_port"]
        port_counts[port] = port_counts.get(port, 0) + 1
    top_ports = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    # ─── HTML ─────────────────────────────────────────────
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Build alert rows
    alert_rows = ""
    for alert in alerts:
        color = "#ff4444" if "PORT SCAN" in alert else "#ff8800"
        alert_rows += f'<tr><td style="color:{color}">{alert}</td></tr>\n'
    if not alert_rows:
        alert_rows = '<tr><td style="color:#888">No alerts recorded</td></tr>'

    # Build top IPs rows
    ip_rows = ""
    for ip, count in top_ips:
        flagged = "🚨" if ip in blocked_ips else ""
        ip_rows += f"<tr><td>{ip} {flagged}</td><td>{count}</td></tr>\n"
    if not ip_rows:
        ip_rows = '<tr><td colspan="2" style="color:#888">No data</td></tr>'

    # Build top ports rows
    port_rows = ""
    for port, count in top_ports:
        port_rows += f"<tr><td>{port}</td><td>{count}</td></tr>\n"
    if not port_rows:
        port_rows = '<tr><td colspan="2" style="color:#888">No data</td></tr>'

    # TCP/UDP bar widths
    total = tcp_count + udp_count if tcp_count + udp_count > 0 else 1
    tcp_pct = round((tcp_count / total) * 100)
    udp_pct = round((udp_count / total) * 100)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="10">
    <title>IDS/IPS Security Report</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #e0e0e0;
            padding: 30px;
        }}
        h1 {{
            color: #00ff88;
            font-size: 24px;
            margin-bottom: 5px;
        }}
        .subtitle {{
            color: #888;
            font-size: 13px;
            margin-bottom: 30px;
        }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 30px;
        }}
        .card {{
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .card .number {{
            font-size: 36px;
            font-weight: bold;
            color: #00ff88;
        }}
        .card .label {{
            font-size: 12px;
            color: #888;
            margin-top: 5px;
        }}
        .card.danger .number {{ color: #ff4444; }}
        .card.warning .number {{ color: #ff8800; }}
        .section {{
            background: #111;
            border: 1px solid #222;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .section h2 {{
            color: #00ff88;
            font-size: 14px;
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }}
        th {{
            text-align: left;
            color: #888;
            padding: 8px;
            border-bottom: 1px solid #222;
            font-size: 11px;
            text-transform: uppercase;
        }}
        td {{
            padding: 8px;
            border-bottom: 1px solid #1a1a1a;
        }}
        tr:last-child td {{ border-bottom: none; }}
        .bar-container {{
            margin: 10px 0;
        }}
        .bar-label {{
            font-size: 12px;
            color: #888;
            margin-bottom: 5px;
        }}
        .bar {{
            height: 24px;
            border-radius: 4px;
            display: flex;
            align-items: center;
            padding-left: 10px;
            font-size: 12px;
            font-weight: bold;
        }}
        .bar.tcp {{ background: #003d1f; color: #00ff88; }}
        .bar.udp {{ background: #1a1a00; color: #ffdd00; }}
        .two-col {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 15px;
        }}
        .footer {{
            text-align: center;
            color: #333;
            font-size: 11px;
            margin-top: 20px;
        }}
    </style>
</head>
<body>

    <h1>🛡️ IDS/IPS Security Report</h1>
    <div class="subtitle">Generated: {generated_at}</div>

    <!-- Stats Cards -->
    <div class="grid">
        <div class="card">
            <div class="number">{total_packets}</div>
            <div class="label">Total Packets</div>
        </div>
        <div class="card danger">
            <div class="number">{total_alerts}</div>
            <div class="label">Alerts Fired</div>
        </div>
        <div class="card warning">
            <div class="number">{len(blocked_ips)}</div>
            <div class="label">IPs Blocked</div>
        </div>
        <div class="card">
            <div class="number">{len(unique_ips)}</div>
            <div class="label">Unique IPs Seen</div>
        </div>
    </div>

    <!-- Protocol Breakdown -->
    <div class="section">
        <h2>Protocol Breakdown</h2>
        <div class="bar-container">
            <div class="bar-label">TCP — {tcp_count} packets ({tcp_pct}%)</div>
            <div class="bar tcp" style="width:{tcp_pct}%">TCP {tcp_pct}%</div>
        </div>
        <div class="bar-container">
            <div class="bar-label">UDP — {udp_count} packets ({udp_pct}%)</div>
            <div class="bar udp" style="width:{udp_pct}%">UDP {udp_pct}%</div>
        </div>
    </div>

    <!-- Two column section -->
    <div class="two-col">
        <div class="section">
            <h2>Top Source IPs</h2>
            <table>
                <tr><th>IP Address</th><th>Packets</th></tr>
                {ip_rows}
            </table>
        </div>
        <div class="section">
            <h2>Top Target Ports</h2>
            <table>
                <tr><th>Port</th><th>Hits</th></tr>
                {port_rows}
            </table>
        </div>
    </div>

    <!-- Alerts -->
    <div class="section">
        <h2>⚠️ Alert Log</h2>
        <table>
            <tr><th>Event</th></tr>
            {alert_rows}
        </table>
    </div>

    <div class="footer">
        Built with Python + Scapy — IDS/IPS Project
    </div>

</body>
</html>"""

    with open(REPORT_FILE, "w") as f:
        f.write(html)

    print(f"✅ Report generated: {REPORT_FILE}")

generate_report()
