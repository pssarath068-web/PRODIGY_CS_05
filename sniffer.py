from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime

LOG_FILE = "logs.txt"

def process_packet(packet):
    print("=" * 80)

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        print(f"[{timestamp}]")
        print(f"Source IP      : {src_ip}")
        print(f"Destination IP : {dst_ip}")
        print(f"Protocol       : {protocol}")

        sport = "-"
        dport = "-"

        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            proto_name = "TCP"

        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            proto_name = "UDP"

        else:
            proto_name = "Other"

        print(f"Protocol Name  : {proto_name}")
        print(f"Source Port    : {sport}")
        print(f"Destination Port: {dport}")

        payload = ""

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors="ignore")
            except:
                payload = str(packet[Raw].load)

        print(f"Payload:\n{payload}")

        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {src_ip} -> {dst_ip} | {proto_name} | {sport}->{dport}\n")
            f.write(f"Payload: {payload}\n")
            f.write("=" * 80 + "\n")


print("Starting Packet Sniffer...")
sniff(prn=process_packet, store=False)
