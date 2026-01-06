from scapy.all import sniff, IP, TCP, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import UDP
import socket

# Set your own internal IP range if needed
LOCAL_SUBNET_PREFIX = "192.168."

def is_external(ip):
    return not ip.startswith(LOCAL_SUBNET_PREFIX)

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Skip purely local traffic
        if not (is_external(src_ip) or is_external(dst_ip)):
            return

        print("=" * 80)
        print(f"Packet: {src_ip} --> {dst_ip}")
        print(f"Protocol: {ip_layer.proto} | Length: {len(packet)}")

        if TCP in packet:
            tcp_layer = packet[TCP]
            flags = tcp_layer.flags

            print(f"  🔗 TCP Ports: {tcp_layer.sport} -> {tcp_layer.dport}")
            print(f"  🔐 Flags: {flags}")
            print(f"  🧾 Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack}")

            if Raw in packet:
                payload = packet[Raw].load

                # Try HTTP dissection
                if packet.haslayer(HTTPRequest):
                    http = packet[HTTPRequest]
                    print(f"HTTP Request: {http.Method.decode()} {http.Host.decode()}{http.Path.decode()}")
                elif packet.haslayer(HTTPResponse):
                    print("HTTP Response Detected")
                elif b"TLS" in payload[:10] or packet[TCP].dport == 443:
                    print("TLS/SSL Packet (could include SNI in ClientHello)")
                else:
                    print(f"Raw Payload (truncated): {payload[:60]!r}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"UDP Ports: {udp_layer.sport} -> {udp_layer.dport}")
            if Raw in packet:
                print(f"Raw UDP Payload: {packet[Raw].load[:60]!r}")

        else:
            print("Non-TCP/UDP packet detected.")

# Interface: change to what you sniff on (e.g., "eth0" or "Wi-Fi")
print("Starting deep packet sniffer... (Press Ctrl+C to stop)\n")
sniff(filter="ip", prn=packet_callback, store=0)
