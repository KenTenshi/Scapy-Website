from scapy.all import rdpcap
from collections import Counter
from scapy.layers.dns import DNSQR, DNSRR

def analyze_ip_count(file_path):
    packets = rdpcap(file_path)

    src_ips = Counter()
    dst_ips = Counter()

    for packet in packets:
        if 'IP' in packet:
            src_ips[packet['IP'].src] += 1
            dst_ips[packet['IP'].dst] += 1

    result = {
        'src_ips': src_ips.most_common(5),
        'dst_ips': dst_ips.most_common(5),
    }

    return result


def analyze_packet_count(file_path):
    packets = rdpcap(file_path)

    packet_types = Counter()

    for packet in packets:
        packet_types[packet.__class__.__name__] += 1

    result = {
        'packet_types': packet_types,
    }

    return result


def analyze_dns(file_path):
    packets = rdpcap(file_path)

    dns_queries = Counter()
    dns_responses = Counter()

    for packet in packets:
        if 'DNS' in packet:
            if isinstance(packet.an, DNSQR):
                dns_queries[packet.qd.qname] += 1
            elif isinstance(packet.an, DNSRR):
                dns_responses[packet.an.rrname] += 1

    result = {
        'dns_queries': dns_queries,
        'dns_responses': dns_responses,
    }

    return result


def analyze_ping(file_path):
    packets = rdpcap(file_path)

    ping_requests = Counter()
    ping_responses = Counter()

    for packet in packets:
        if 'ICMP' in packet:
            if packet['ICMP'].type == 8:  # Echo request
                ping_requests[packet['IP'].src] += 1
            elif packet['ICMP'].type == 0:  # Echo reply
                ping_responses[packet['IP'].src] += 1

    result = {
        'ping_requests': ping_requests,
        'ping_responses': ping_responses,
    }

    return result


def analyze_dhcp(file_path):
    packets = rdpcap(file_path)

    dhcp_messages = Counter()
    op_code_translation = {
        1: "DHCP Request",
        2: "DHCP Reply"
    }

    for packet in packets:
        if 'BOOTP' in packet:
            dhcp_messages[op_code_translation[packet['BOOTP'].op]] += 1

    result = {
        'dhcp_messages': dhcp_messages,
    }

    return result

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