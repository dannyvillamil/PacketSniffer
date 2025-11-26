import socket
import struct
import textwrap

# ----------------------------
# Helper formatting functions
# ----------------------------

def get_mac_addr(bytes_addr):
    """Convert a MAC address from bytes to human-readable form."""
    return ':'.join('{:02x}'.format(b) for b in bytes_addr)

def get_ipv4_addr(bytes_addr):
    """Convert an IPv4 address from bytes to human-readable form."""
    return '.'.join(map(str, bytes_addr))

def format_multi_line(prefix, data, size=80):
    """Pretty-print multi-line data (hex or text) with a prefix."""
    if isinstance(data, bytes):
        data = '.'.join(r'\x{:02x}'.format(b) for b in data)
    lines = textwrap.wrap(data, size)
    return '\n'.join(prefix + line for line in lines)

# -------------------
# Parsing functions
# -------------------

def ethernet_head(raw_data):
    """
    Ethernet frame:
    6 bytes: dest MAC, 6 bytes src MAC, 2 bytes EtherType, then payload.
    """
    dest, src, proto = struct.unpack('! 6s 6s H', raw_data[:14])
    dest_mac = get_mac_addr(dest)
    src_mac = get_mac_addr(src)
    # Convert from network to host byte order
    eth_proto = socket.ntohs(proto)
    data = raw_data[14:]
    return dest_mac, src_mac, eth_proto, data

def ipv4_head(raw_data):
    """
    IPv4 header (no options):
    First byte = version (4 bits) + header length (4 bits).
    Then we unpack TTL, protocol, src IP, dst IP.
    """
    version_header_length = raw_data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 0x0F) * 4

    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip = get_ipv4_addr(src)
    dst_ip = get_ipv4_addr(target)

    data = raw_data[header_length:]
    return version, header_length, ttl, proto, src_ip, dst_ip, data

def icmp_head(raw_data):
    """ICMP header: Type (1), Code (1), Checksum (2), then data."""
    icmp_type, code, checksum = struct.unpack('! B B H', raw_data[:4])
    data = raw_data[4:]
    return icmp_type, code, checksum, data

def tcp_head(raw_data):
    """
    TCP header:
    src port (2), dst port (2), seq (4), ack (4),
    offset+reserved+flags (2), then options/payload.
    """
    src_port, dest_port, sequence, acknowledgement, offset_reserved_flags = \
        struct.unpack('! H H L L H', raw_data[:14])

    offset = (offset_reserved_flags >> 12) * 4

    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1

    data = raw_data[offset:]
    return (src_port, dest_port, sequence, acknowledgement,
            flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data)

def udp_head(raw_data):
    """UDP header: src port (2), dst port (2), length (2), checksum (2), then data."""
    src_port, dest_port, length = struct.unpack('! H H H 2x', raw_data[:8])
    data = raw_data[8:]
    return src_port, dest_port, length, data

# -------------------
# Main sniffer loop
# -------------------

def main():
    # AF_PACKET: capture at Ethernet/link layer (Linux only)
    # SOCK_RAW: raw packets
    # ntohs(3): "all protocols" on Linux
    conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

    while True:
        raw_data, addr = conn.recvfrom(65535)

        # --- Ethernet ---
        dest_mac, src_mac, eth_proto, data = ethernet_head(raw_data)
        print('\nEthernet Frame:')
        print(f'    Destination: {dest_mac}, Source: {src_mac}, Protocol: {eth_proto}')

        # --- IPv4 ---
        if eth_proto == 0x0800:  # IPv4 EtherType
            version, header_length, ttl, proto, src_ip, dst_ip, data = ipv4_head(data)
            print('    IPv4 Packet:')
            print(f'        Version: {version}, Header Length: {header_length}, TTL: {ttl}')
            print(f'        Protocol: {proto}, Source: {src_ip}, Target: {dst_ip}')

            # --- ICMP ---
            if proto == 1:
                icmp_type, code, checksum, icmp_data = icmp_head(data)
                print('        ICMP Packet:')
                print(f'            Type: {icmp_type}, Code: {code}, Checksum: {checksum}')
                print('            Data:')
                print(format_multi_line('                ', icmp_data))

            # --- TCP ---
            elif proto == 6:
                (src_port, dest_port, sequence, acknowledgment,
                 urg, ack, psh, rst, syn, fin, tcp_data) = tcp_head(data)

                print('        TCP Segment:')
                print(f'            Source Port: {src_port}, Destination Port: {dest_port}')
                print(f'            Sequence: {sequence}, Acknowledgment: {acknowledgment}')
                print(f'            Flags: URG={urg}, ACK={ack}, PSH={psh}, RST={rst}, SYN={syn}, FIN={fin}')

                # Try to detect HTTP on port 80
                if src_port == 80 or dest_port == 80:
                    print('            HTTP Data (best effort):')
                    try:
                        http_text = tcp_data.decode(errors="replace")
                        print(format_multi_line('                ', http_text))
                    except Exception:
                        print(format_multi_line('                ', tcp_data))
                else:
                    print('            TCP Data:')
                    print(format_multi_line('                ', tcp_data))

            # --- UDP ---
            elif proto == 17:
                src_port, dest_port, length, udp_data = udp_head(data)
                print('        UDP Segment:')
                print(f'            Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}')
                print('            Data:')
                print(format_multi_line('                ', udp_data))

            else:
                print('    Other IPv4 Protocol (not TCP/UDP/ICMP)')
                print(format_multi_line('        ', data))

        else:
            # Non-IPv4 traffic (ARP, IPv6, etc.). Comment this back in if you want to see it.
            # print('    Non-IPv4 Ethernet payload:')
            # print(format_multi_line('        ', data))
            pass

if __name__ == '__main__':
    main()
