# Import der erforderlichen Module und Funktionen
from flask import Flask, render_template, request, redirect, url_for
from scapy.all import rdpcap
from collections import Counter
from Python.packet_analyse import analyze_pcap, analyze_ip_count, analyze_packet_count, analyze_dns, analyze_ping, analyze_dhcp
import os

# Flask-Webanwendung initialisieren
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

# Route für die Startseite der Webanwendung
@app.route('/', methods=['GET', 'POST'])
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            analysis_type = request.form.get('analyse_type')  # Holen Sie sich den Analysetyp aus dem Formular
            if analysis_type == 'top':
                analysis_results = analyze_pcap(file_path)
                return render_template('result_standard.html', result=analysis_results)
            elif analysis_type == 'ip_count':
                analysis_results = analyze_ip_count(file_path)
                return render_template('result_ip_count.html', result=analysis_results)
            elif analysis_type == 'packet_count':
                analysis_results = analyze_packet_count(file_path)
                return render_template('result_packet_count.html', result=analysis_results)
            elif analysis_type == 'dns':
                analysis_results = analyze_dns(file_path)
                return render_template('result_dns.html', result=analysis_results)
            elif analysis_type == 'ping':
                analysis_results = analyze_ping(file_path)
                return render_template('result_ping.html', result=analysis_results)
            elif analysis_type == 'dhcp':
                analysis_results = analyze_dhcp(file_path)
                return render_template('result_dhcp.html', result=analysis_results)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)
