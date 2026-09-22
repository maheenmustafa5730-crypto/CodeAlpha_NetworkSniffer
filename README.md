# CodeAlpha_NetworkSniffer
"Basic Network Sniffer built with Python and Scapy - CodeAlpha Cyber Security Internship Task 1"
## What it does
This script captures live network traffic packets and displays useful information such as:
- Source and Destination IP addresses
- Protocol (TCP/UDP/ICMP)
- Source and Destination ports
- Payload size and preview

## How it works
The script uses Scapy's `sniff()` function to capture packets on the network interface. Each captured packet is analyzed by the `process_packet()` function, which extracts the IP layer, identifies the protocol, and prints relevant details to the console.

## Requirements
- Python 3
- Scapy (`pip3 install scapy --break-system-packages`)
- Linux (run with sudo for packet capture permissions)

## How to run
```bash
sudo python3 network_sniffer.py
```

## Sample Output
[Packet #1] Time: 19:06:22
Source IP : 192.168.136.1
Destination IP : 192.168.136.130
Protocol : TCP
Source Port : 61072
Dest Port : 1514

## Note
This tool is intended for educational purposes only. Only use it on networks/devices you own or have explicit permission to monitor.
