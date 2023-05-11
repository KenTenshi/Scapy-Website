from scapy.all import *
from collections import Counter
import matplotlib.pyplot as plt

# Lies die pcap-Datei ein
packets = rdpcap('file.pcap')

# Zähle die IP-Adressen
ip_counts = Counter()
for packet in packets:
    if 'IP' in packet:
        ip_counts[packet['IP'].src] += 1

# Erstelle ein Balkendiagramm mit den Zählungen
plt.bar(ip_counts.keys(), ip_counts.values())
plt.show()
