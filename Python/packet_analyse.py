from scapy.all import rdpcap
from collections import Counter
from scapy.layers.dns import DNSQR, DNSRR

def analyze_ip_count(file_path):
    packets = rdpcap(file_path)

    src_ips = Counter()  # Zählt die Quell-IP-Adressen
    dst_ips = Counter()  # Zählt die Ziel-IP-Adressen

    for packet in packets:
        if 'IP' in packet:  # Prüft, ob das Paket das IP-Protokoll enthält
            src_ips[packet['IP'].src] += 1  # Zählt die Quell-IP
            dst_ips[packet['IP'].dst] += 1  # Zählt die Ziel-IP

    result = {
        'src_ips': src_ips.most_common(5),  # Gibt die Top 5 Quell-IP-Adressen zurück
        'dst_ips': dst_ips.most_common(5),  # Gibt die Top 5 Ziel-IP-Adressen zurück
    }

    return result


def analyze_packet_count(file_path):
    packets = rdpcap(file_path)

    packet_types = Counter()  # Zählt die verschiedenen Pakettypen

    for packet in packets:
        packet_types[packet.__class__.__name__] += 1  # Zählt den Pakettyp

    result = {
        'packet_types': packet_types,  # Gibt die Anzahl der verschiedenen Pakettypen zurück
    }

    return result


def analyze_dns(file_path):
    packets = rdpcap(file_path)

    dns_queries = Counter()  # Zählt die DNS-Anfragen
    dns_responses = Counter()  # Zählt die DNS-Antworten

    for packet in packets:
        if 'DNS' in packet:  # Prüft, ob das Paket das DNS-Protokoll enthält
            if isinstance(packet.an, DNSQR):  # Prüft, ob es sich um eine DNS-Anfrage handelt
                dns_queries[packet.qd.qname] += 1  # Zählt die DNS-Anfrage
            elif isinstance(packet.an, DNSRR):  # Prüft, ob es sich um eine DNS-Antwort handelt
                dns_responses[packet.an.rrname] += 1  # Zählt die DNS-Antwort

    result = {
        'dns_queries': dns_queries,  # Gibt die Anzahl der DNS-Anfragen zurück
        'dns_responses': dns_responses,  # Gibt die Anzahl der DNS-Antworten zurück
    }

    return result


def analyze_ping(file_path):
    packets = rdpcap(file_path)

    ping_requests = Counter()  # Zählt die Ping-Anfragen
    ping_responses = Counter()  # Zählt die Ping-Antworten

    for packet in packets:
        if 'ICMP' in packet:  # Prüft, ob das Paket das ICMP-Protokoll enthält
            if packet['ICMP'].type == 8:  # Prüft, ob es sich um eine ICMP Echo-Anfrage handelt
                ping_requests[packet['IP'].src] += 1  # Zählt die Ping-Anfrage
            elif packet['ICMP'].type == 0:  # Prüft, ob es sich um eine ICMP Echo-Antwort handelt
                ping_responses[packet['IP'].src] += 1  # Zählt die Ping-Antwort

    result = {
        'ping_requests': ping_requests,  # Gibt die Anzahl der Ping-Anfragen zurück
        'ping_responses': ping_responses,  # Gibt die Anzahl der Ping-Antworten zurück
    }

    return result


def analyze_dhcp(file_path):
    packets = rdpcap(file_path)

    dhcp_messages = Counter()  # Zählt die DHCP-Nachrichten
    op_code_translation = {
        1: "DHCP Request",  # Übersetzung des DHCP-Op-Codes 1 zu "DHCP Request"
        2: "DHCP Reply"  # Übersetzung des DHCP-Op-Codes 2 zu "DHCP Reply"
    }

    for packet in packets:
        if 'BOOTP' in packet:  # Prüft, ob das Paket das BOOTP-Protokoll enthält
            dhcp_messages[op_code_translation[packet['BOOTP'].op]] += 1  # Zählt die DHCP-Nachricht

    result = {
        'dhcp_messages': dhcp_messages,  # Gibt die Anzahl der DHCP-Nachrichten zurück
    }

    return result

def analyze_pcap(file_path):
    packets = rdpcap(file_path)

    packet_types = Counter()  # Zählt die verschiedenen Pakettypen
    src_ips = Counter()  # Zählt die Quell-IP-Adressen
    dst_ips = Counter()  # Zählt die Ziel-IP-Adressen
    src_ports = Counter()  # Zählt die Quell-Ports
    dst_ports = Counter()  # Zählt die Ziel-Ports

    for packet in packets:
        packet_types[packet.__class__.__name__] += 1  # Zählt den Pakettyp

        if 'IP' in packet:  # Prüft, ob das Paket das IP-Protokoll enthält
            src_ips[packet['IP'].src] += 1  # Zählt die Quell-IP
            dst_ips[packet['IP'].dst] += 1  # Zählt die Ziel-IP

        if 'TCP' in packet or 'UDP' in packet:  # Prüft, ob das Paket das TCP- oder UDP-Protokoll enthält
            src_ports[packet.sport] += 1  # Zählt den Quell-Port
            dst_ports[packet.dport] += 1  # Zählt den Ziel-Port

    result = {
        'packet_types': packet_types,  # Gibt die Anzahl der verschiedenen Pakettypen zurück
        'src_ips': src_ips.most_common(5),  # Gibt die Top 5 Quell-IP-Adressen zurück
        'dst_ips': dst_ips.most_common(5),  # Gibt die Top 5 Ziel-IP-Adressen zurück
        'src_ports': src_ports.most_common(5),  # Gibt die Top 5 Quell-Ports zurück
        'dst_ports': dst_ports.most_common(5),  # Gibt die Top 5 Ziel-Ports zurück
    }

    return result