from flask import Flask, render_template, request, redirect, url_for
from scapy.all import rdpcap
import os

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'

def analyze_pcap(file_path):
    packets = rdpcap(file_path)
    # Hier können Sie Ihre Analyse-Logik hinzufügen
    return f"Anzahl der Pakete: {len(packets)}"

@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
            file.save(file_path)
            result = analyze_pcap(file_path)
            return render_template('result.html', result=result)
    return render_template('upload.html')

if __name__ == '__main__':
    app.run(debug=True)