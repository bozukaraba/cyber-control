import ssl
import socket
import requests
import nmap
from urllib.parse import urlparse
from datetime import datetime
from .modules.ssl_tls_scanner import SSLTLSScanner
from .modules.port_scanner import PortScanner
from .modules.http_header_scanner import HTTPHeaderScanner
from .modules.sql_injection_scanner import SQLInjectionScanner
from .modules.xss_scanner import XSSScanner
from .modules.server_info_scanner import ServerInfoScanner
from .modules.admin_panel_scanner import AdminPanelScanner
from .modules.cms_scanner import CMSScanner
from .modules.file_upload_scanner import FileUploadScanner
from .modules.brute_force_scanner import BruteForceScanner

class SecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.netloc
        self.scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.results = {}
        
    def run_all_scans(self):
        """Tüm güvenlik taramalarını çalıştırır ve sonuçları döndürür."""
        self.results = {
            "target_url": self.target_url,
            "scan_date": self.scan_date,
            "scan_results": {}
        }
        
        # SSL/TLS Taraması
        ssl_scanner = SSLTLSScanner(self.target_url)
        self.results["scan_results"]["ssl_tls"] = ssl_scanner.scan()
        
        # Port Taraması
        port_scanner = PortScanner(self.hostname)
        self.results["scan_results"]["ports"] = port_scanner.scan()
        
        # HTTP Başlık Taraması
        header_scanner = HTTPHeaderScanner(self.target_url)
        self.results["scan_results"]["http_headers"] = header_scanner.scan()
        
        # SQL Injection Taraması
        sql_scanner = SQLInjectionScanner(self.target_url)
        self.results["scan_results"]["sql_injection"] = sql_scanner.scan()
        
        # XSS Taraması
        xss_scanner = XSSScanner(self.target_url)
        self.results["scan_results"]["xss"] = xss_scanner.scan()
        
        # Sunucu Bilgi Sızıntısı Taraması
        server_scanner = ServerInfoScanner(self.target_url)
        self.results["scan_results"]["server_info"] = server_scanner.scan()
        
        # Admin Panel Taraması
        admin_scanner = AdminPanelScanner(self.target_url)
        self.results["scan_results"]["admin_panel"] = admin_scanner.scan()
        
        # CMS Taraması
        cms_scanner = CMSScanner(self.target_url)
        self.results["scan_results"]["cms"] = cms_scanner.scan()
        
        # Dosya Yükleme Zafiyeti Taraması
        upload_scanner = FileUploadScanner(self.target_url)
        self.results["scan_results"]["file_upload"] = upload_scanner.scan()
        
        # Brute Force Taraması
        brute_scanner = BruteForceScanner(self.target_url)
        self.results["scan_results"]["brute_force"] = brute_scanner.scan()
        
        return self.results 