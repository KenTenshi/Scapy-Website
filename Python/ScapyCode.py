from scapy.all import rdpcap
from collections import Counter

def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    # Zählen Sie die verschiedenen Arten von Paketen
    packet_types = Counter()
    src_ips = Counter()
    dst_ips = Counter()
    src_ports = Counter()
    dst_ports = Counter()

    for packet in packets:
        packet_types[packet.__class__.__name__] += 1

        if 'IP' in packet:
            src_ips[packet['IP'].src] += 1
            dst_ips[packet['IP'].dst] += 1

        if 'TCP' in packet or 'UDP' in packet:
            src_ports[packet.sport] += 1
            dst_ports[packet.dport] += 1

    result = {
        'packet_types': packet_types,
        'src_ips': src_ips.most_common(5),
        'dst_ips': dst_ips.most_common(5),
        'src_ports': src_ports.most_common(5),
        'dst_ports': dst_ports.most_common(5),
    }

    return result