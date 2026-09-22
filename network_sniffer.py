from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

packet_count = 0


def get_protocol_name(packet):
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def process_packet(packet):
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = get_protocol_name(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")

        print(f"\n[Packet #{packet_count}] Time: {timestamp}")
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")
        print(f"  Protocol       : {protocol}")

        if packet.haslayer(TCP):
            print(f"  Source Port    : {packet[TCP].sport}")
            print(f"  Dest Port      : {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print(f"  Source Port    : {packet[UDP].sport}")
            print(f"  Dest Port      : {packet[UDP].dport}")

        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"  Payload Size   : {len(payload)} bytes")
            try:
                preview = payload[:50].decode(errors="ignore")
                print(f"  Payload Preview: {preview}")
            except Exception:
                print(f"  Payload Preview: <binary data>")

        print("-" * 50)


def start_sniffing(interface=None, packet_limit=0, filter_str=""):
    print("=" * 50)
    print(" Basic Network Sniffer - Starting...")
    print(" Rokne ke liye Ctrl+C dabayein")
    print("=" * 50)

    try:
        sniff(
            iface=interface,
            prn=process_packet,
            count=packet_limit,
            filter=filter_str,
            store=False
        )
    except PermissionError:
        print("\n[ERROR] Permission denied! Sudo ke sath chalayein.")
    except KeyboardInterrupt:
        print(f"\n\nSniffing stop ki gayi. Total packets captured: {packet_count}")


if __name__ == "__main__":
    start_sniffing(interface=None, packet_limit=20, filter_str="ip")
