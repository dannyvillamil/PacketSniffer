import socket

def main():
    # Get your local IP
    host = socket.gethostbyname(socket.gethostname())
    print(f"Sniffing on {host}")

    # Create raw socket on Windows (IPv4)
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # Bind to your IP
    s.bind((host, 0))

    # Include IP headers
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # Turn on promiscuous mode (Windows-specific)
    SIO_RCVALL = 0x98000001
    RCVALL_ON = 1
    s.ioctl(SIO_RCVALL, RCVALL_ON)

    print("Sniffer started (Ctrl+C to stop)...")

    try:
        while True:
            raw_data, addr = s.recvfrom(65535)
            print(f"Got packet of length {len(raw_data)} from {addr}")
    except KeyboardInterrupt:
        print("\nStopping sniffer...")
    finally:
        # Turn off promiscuous mode
        RCVALL_OFF = 0
        s.ioctl(SIO_RCVALL, RCVALL_OFF)

if __name__ == "__main__":
    main()
