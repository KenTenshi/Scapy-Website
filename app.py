from flask import Flask, render_template, request, redirect, url_for
from scapy.all import rdpcap
from scapy.layers.inet import IP, ICMP
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

def analyze_pcap(file_path, packet_type):
    packets = rdpcap(file_path)

    if packet_type == 'icmp':
        packets = [pkt for pkt in packets if ICMP in pkt]

    # Hier können Sie Ihre Analyse-Logik hinzufügen
    return f"Anzahl der Pakete: {len(packets)}"

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        packet_type = request.form['packet_type']  # Stellen Sie sicher, dass dieser Code korrekt ist
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            result = analyze_pcap(file_path, packet_type)
            return render_template('result.html', result=result)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)