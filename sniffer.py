from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime

def process_packet(packet):
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        time = datetime.now().strftime("%H:%M:%S")

        if TCP in packet:
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            print(f"[{time}] TCP | {src}:{sport} → {dst}:{dport}")

        elif UDP in packet:
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            print(f"[{time}] UDP | {src}:{sport} → {dst}:{dport}")

        else:
            print(f"[{time}] OTHER (proto {proto}) | {src} → {dst}")

sniff(filter="ip", prn=process_packet, count=0, store=False)
