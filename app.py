from flask import Flask, render_template, request, jsonify, send_file
import os
from scanner.scanner import SecurityScanner
from report.report_generator import ReportGenerator

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url')
    if not url:
        return jsonify({'error': 'URL gerekli'}), 400
    
    scanner = SecurityScanner(url)
    scan_results = scanner.run_all_scans()
    
    report_generator = ReportGenerator(url, scan_results)
    report_path = report_generator.generate_pdf()
    
    return jsonify({
        'success': True,
        'report_url': f'/download/{os.path.basename(report_path)}'
    })

@app.route('/download/<filename>')
def download_report(filename):
    report_dir = os.path.join(os.getcwd(), 'reports')
    return send_file(os.path.join(report_dir, filename), as_attachment=True)

if __name__ == '__main__':
    # Rapor klasörünü oluştur
    os.makedirs('reports', exist_ok=True)
    app.run(debug=True) 