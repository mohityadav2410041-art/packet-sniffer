# 📡 Educational Packet Sniffer

A minimal command-line packet sniffer written in Python using raw sockets. It captures live network traffic on the host machine and displays source/destination IPs, protocol types, and a printable payload snippet — all using the Python standard library.

> ⚠️ **Legal & Ethical Notice:** Packet sniffing on networks you do not own or have **explicit written permission** to monitor is illegal in most jurisdictions under laws such as the Computer Fraud and Abuse Act (CFAA) and equivalent legislation worldwide. This tool is intended **solely for educational use** on your own systems or in controlled lab environments (e.g., virtual machines, local test networks).

---

## What This Project Demonstrates

- How raw sockets work in Python (`SOCK_RAW`)
- How IPv4 packet headers are structured and parsed using `struct`
- How to identify common protocols (TCP, UDP, ICMP) from their protocol numbers
- How promiscuous mode works on Windows vs Unix-based systems
- Cross-platform network programming with `socket` and `os`

## Features

- ✅ Captures live packets on the local host interface
- ✅ Parses IPv4 headers to extract source IP, destination IP, and protocol
- ✅ Identifies TCP, UDP, and ICMP traffic by name
- ✅ Displays a safe printable snippet of each packet's payload (non-printable bytes shown as `.`)
- ✅ Enables promiscuous mode on Windows for broader packet capture
- ✅ Gracefully disables promiscuous mode on exit (Windows)
- ✅ Clear error message if run without the required elevated privileges

## Getting Started

### Prerequisites

- Python 3.x
- **Elevated privileges** — raw socket access requires:
  - **Windows:** Run as Administrator
  - **Linux / macOS:** Run with `sudo`

No external libraries required — uses only the Python standard library.

### Installation

Clone the repository:

```bash
git clone https://github.com/mohityadav2410041-art/packet-sniffer.git
cd packet-sniffer
```

### Usage

**Windows** (run Command Prompt or PowerShell as Administrator):
```bash
python app.py
```

**Linux / macOS:**
```bash
sudo python3 app.py
```

Press **Ctrl+C** to stop the sniffer.

### Example Output

```
Initializing sniffer on 192.168.1.5...
Listening for incoming packets. Press Ctrl+C to stop.

[*] Source: 192.168.1.1     -> Destination: 192.168.1.5   | Protocol: TCP
    Payload Snippet: GET / HTTP/1.1..Host: example.com....
[*] Source: 8.8.8.8         -> Destination: 192.168.1.5   | Protocol: UDP
    Payload Snippet: .............
[*] Source: 192.168.1.5     -> Destination: 8.8.8.8       | Protocol: ICMP
    Payload Snippet: ................

[*] Stopping educational packet sniffer.
```

## How It Works

1. A raw socket is opened bound to the local host IP.
2. `IP_HDRINCL` is set so the IP header is included in the received data.
3. On Windows, `SIO_RCVALL` enables promiscuous mode to capture all packets passing through the interface.
4. Each received buffer's first 20 bytes are unpacked as a standard IPv4 header using `struct.unpack`.
5. The protocol number, source, and destination addresses are extracted and printed.
6. Up to 60 bytes of payload are displayed, with non-ASCII bytes replaced by `.` to keep output readable and safe.

## Platform Differences

| Behaviour | Windows | Linux / macOS |
|---|---|---|
| Socket protocol | `IPPROTO_IP` | `IPPROTO_TCP` |
| Promiscuous mode | Enabled via `SIO_RCVALL` | Not set (OS-level capture) |
| Required privilege | Administrator | `sudo` |

## Project Structure

```
packet-sniffer/
└── app.py   # Main script
```

## Limitations

- Captures packets on the **local host interface only** — not a full network-wide tap.
- IPv6 packets are not parsed (IPv4 only).
- Payload display is limited to the first 60 bytes and printable ASCII characters.
- On Linux/macOS, `IPPROTO_TCP` means only TCP packets are captured at the socket level; on Windows, `IPPROTO_IP` with promiscuous mode captures more broadly.
- This is a learning tool — it is not suitable for production network diagnostics.

## Ethical Use

This project is shared to help developers and students understand:
- Low-level network programming concepts
- How packet analysis tools like Wireshark operate under the hood
- IPv4 header structure and protocol identification

**Do not** use this tool on public networks, shared Wi-Fi, corporate networks, or any system without explicit authorisation from the network owner. Always use a private, isolated lab environment for testing.

## License

This project is open source and available under the [MIT License](LICENSE).
