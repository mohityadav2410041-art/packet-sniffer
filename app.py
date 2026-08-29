import socket
import struct
import os

def main():
    host = socket.gethostbyname(socket.gethostname())
    print(f"Initializing sniffer on {host}...")

    if os.name == 'nt':
        socket_protocol = socket.IPPROTO_IP
    else:
        socket_protocol = socket.IPPROTO_TCP 

    try:

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        
        
        sniffer.bind((host, 0))

        
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            print("Promiscuous mode enabled.")

        print("Listening for incoming packets. Press Ctrl+C to stop.\n")
        
        while True:
            # Receive a packet data buffer
            raw_buffer = sniffer.recvfrom(65535)[0]
            
            # The first 20 bytes comprise the standard IPv4 header
            ip_header = raw_buffer[0:20]
            
           
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

           
            version_ihl = iph[0]
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            
            protocol = iph[6]
            
           
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            # Map standard protocol numbers to their names
            protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
            protocol_name = protocol_map.get(protocol, str(protocol))

            print(f"[*] Source: {s_addr:<15} -> Destination: {d_addr:<15} | Protocol: {protocol_name}")
            
           
            payload = raw_buffer[iph_length:]
            
            if payload:
               
                safe_payload = "".join(chr(b) if 32 <= b < 127 else '.' for b in payload[:60])
                print(f"    Payload Snippet: {safe_payload}")

    except PermissionError:
        print("\n[!] Error: Permission denied.")
        print("Accessing raw network sockets requires elevated privileges.")
        print("Please run this script as an Administrator (Windows) or using sudo (Linux/macOS).")
    except KeyboardInterrupt:
        print("\n[*] Stopping educational packet sniffer.")
    finally:
        # Attempt to disable promiscuous mode on Windows before exiting
        if os.name == 'nt' and 'sniffer' in locals():
            try:
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass

if __name__ == "__main__":
    main()
