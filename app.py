# Import der erforderlichen Module und Funktionen
from flask import Flask, render_template, request, redirect, url_for
from scapy.all import rdpcap
from collections import Counter
from Python.packet_analyse import analyze_pcap, analyze_ip_count, analyze_packet_count, analyze_dns, analyze_ping, analyze_dhcp
import os

# Flask-Webanwendung initialisieren
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Konfiguration des Upload-Ordners

# Route für die Startseite der Webanwendung
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':  # Überprüfen, ob eine POST-Anfrage gesendet wurde
        file = request.files['file']  # Zugriff auf die hochgeladene Datei
        if file:  # Überprüfen, ob eine Datei hochgeladen wurde
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)  # Erstellen des Dateipfads zum Speichern der Datei
            file.save(file_path)  # Speichern der hochgeladenen Datei am angegebenen Pfad
            
            analysis_type = request.form.get('analyse_type')  # Abrufen des Analysetyps aus dem Formular
            
            # Überprüfen des Analysetyps und Aufrufen der entsprechenden Analysefunktion
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
    
    # Falls keine POST-Anfrage, wird die Startseite zum Hochladen der Datei gerendert
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)  # Starten der Flask-Webanwendung im Debug-Modus