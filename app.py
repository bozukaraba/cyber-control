from flask import Flask, render_template, request, jsonify, send_file
import os
from scanner.scanner import SecurityScanner
from report.report_generator import ReportGenerator
import json
from scanner.main import main as scanner_main

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target_url = data.get('targetUrl')
    
    try:
        # Tarama işlemini başlat
        scanner_main(target_url)
        
        # Sonuçları oku
        with open('scan_results.json', 'r', encoding='utf-8') as f:
            results = json.load(f)
            
        return jsonify({
            'status': 'success',
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/download/<filename>')
def download_report(filename):
    report_dir = os.path.join(os.getcwd(), 'reports')
    return send_file(os.path.join(report_dir, filename), as_attachment=True)

if __name__ == '__main__':
    # Rapor klasörünü oluştur
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True) 