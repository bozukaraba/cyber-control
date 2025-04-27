import asyncio
from datetime import datetime
from .modules.ssl_tls_scanner import SSLTLSScanner
from .modules.port_scanner import PortScanner
from .modules.http_security_scanner import HTTPSecurityScanner
from .modules.sql_injection_scanner import SQLInjectionScanner
from .modules.xss_scanner import XSSScanner
from .modules.server_info_scanner import ServerInfoScanner
from .modules.admin_panel_scanner import AdminPanelScanner
from .modules.cms_scanner import CMSScanner
from .modules.file_upload_scanner import FileUploadScanner
from .modules.brute_force_scanner import BruteForceScanner

class SecurityScanner:
    def __init__(self, target_url):
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
            
        self.target_url = target_url
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None
        
    async def run_scan(self):
        """Tüm güvenlik taramalarını asenkron olarak çalıştırır"""
        self.scan_start_time = datetime.now()
        
        # Tarayıcı modüllerini başlat
        scanners = [
            SSLTLSScanner(self.target_url),
            PortScanner(self.target_url),
            HTTPSecurityScanner(self.target_url),
            SQLInjectionScanner(self.target_url),
            XSSScanner(self.target_url),
            ServerInfoScanner(self.target_url),
            AdminPanelScanner(self.target_url),
            CMSScanner(self.target_url),
            FileUploadScanner(self.target_url),
            BruteForceScanner(self.target_url)
        ]
        
        # Asenkron tarama görevlerini oluştur
        tasks = []
        for scanner in scanners:
            if hasattr(scanner, 'async_scan'):
                tasks.append(asyncio.create_task(scanner.async_scan()))
            else:
                # Senkron tarayıcıları ThreadPoolExecutor ile çalıştır
                tasks.append(asyncio.create_task(self._run_sync_scanner(scanner)))
        
        # Tüm taramaları paralel çalıştır
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Sonuçları işle
        for result in scan_results:
            if isinstance(result, Exception):
                self.results.append({
                    "title": "Tarama Hatası",
                    "findings": [{
                        "name": "Beklenmeyen Hata",
                        "description": str(result),
                        "risk_level": "Hata",
                        "impact": "Tarama tamamlanamadı",
                        "recommendation": "Sistem yöneticinize başvurun"
                    }]
                })
            else:
                self.results.append(result)
        
        self.scan_end_time = datetime.now()
        return self._generate_report()
    
    async def _run_sync_scanner(self, scanner):
        """Senkron tarayıcıları asenkron çalıştırmak için yardımcı metod"""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, scanner.scan)
    
    def _generate_report(self):
        """Tarama sonuçlarından detaylı bir rapor oluşturur"""
        total_findings = sum(len(result["findings"]) for result in self.results)
        risk_levels = {
            "Kritik": 0,
            "Yüksek": 0,
            "Orta": 0,
            "Düşük": 0,
            "Bilgi": 0,
            "Hata": 0
        }
        
        # Risk seviyelerini say
        for result in self.results:
            for finding in result["findings"]:
                if finding["risk_level"] in risk_levels:
                    risk_levels[finding["risk_level"]] += 1
        
        report = {
            "summary": {
                "target_url": self.target_url,
                "scan_start_time": self.scan_start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "scan_end_time": self.scan_end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": str(self.scan_end_time - self.scan_start_time),
                "total_findings": total_findings,
                "risk_summary": risk_levels
            },
            "detailed_results": self.results
        }
        
        return report 