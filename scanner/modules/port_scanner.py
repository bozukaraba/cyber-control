import socket
import threading
import queue
import time
from urllib.parse import urlparse

class PortScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        parsed_url = urlparse(target_url)
        self.target_host = parsed_url.netloc.split(':')[0]
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1521: "Oracle",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
            27017: "MongoDB"
        }
        
    def scan_port(self, port, timeout=1):
        """Belirli bir portu tarar"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((self.target_host, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = self.common_ports.get(port, "Unknown")
                return (port, True, service)
            return (port, False, None)
        except:
            return (port, False, None)
        finally:
            sock.close()
            
    def worker(self, port_queue, results):
        """Port tarama işçisi"""
        while True:
            try:
                port = port_queue.get_nowait()
                results.append(self.scan_port(port))
            except queue.Empty:
                break
            finally:
                port_queue.task_done()
                
    def scan(self):
        """Port taraması yapar"""
        result = {
            "title": "Port Tarama Testi",
            "findings": []
        }
        
        try:
            # Port kuyruğunu oluştur
            port_queue = queue.Queue()
            
            # İlk 1000 portu kuyruğa ekle
            for port in range(1, 1001):
                port_queue.put(port)
            
            # Sonuçlar listesi
            results = []
            
            # Thread havuzu oluştur
            threads = []
            for _ in range(100):  # 100 eşzamanlı thread
                t = threading.Thread(target=self.worker, args=(port_queue, results))
                t.daemon = True
                t.start()
                threads.append(t)
            
            # Tüm threadlerin bitmesini bekle
            for t in threads:
                t.join()
            
            # Açık portları grupla
            open_ports = []
            for port, is_open, service in results:
                if is_open:
                    open_ports.append({
                        'port': port,
                        'service': service
                    })
            
            if open_ports:
                # Portları sırala
                open_ports.sort(key=lambda x: x['port'])
                
                # Açık port bulgusu ekle
                port_list = "\n".join([f"Port {p['port']}: {p['service']}" for p in open_ports])
                result["findings"].append({
                    "name": "Açık Portlar Tespit Edildi",
                    "description": f"Hedef: {self.target_host}\n\nAçık Portlar:\n{port_list}",
                    "risk_level": "Orta",
                    "impact": "Açık portlar üzerinden sistemlere yetkisiz erişim sağlanabilir",
                    "recommendation": "\n".join([
                        "1. Gereksiz servisleri kapatın",
                        "2. Güvenlik duvarı kurallarını sıkılaştırın",
                        "3. Sadece gerekli portları açık tutun",
                        "4. Açık portlardaki servisleri güncel tutun",
                        "5. Güçlü kimlik doğrulama mekanizmaları kullanın",
                        "6. Port bazlı erişim kontrolü uygulayın",
                        "7. Düzenli port taraması yapın"
                    ])
                })
                
                # Her açık port için detaylı bulgu ekle
                for port_info in open_ports:
                    port = port_info['port']
                    service = port_info['service']
                    
                    # Yaygın güvenlik riskleri
                    risks = {
                        'FTP': 'Şifresiz kimlik bilgileri, dosya sistemi erişimi',
                        'SSH': 'Brute force saldırıları, eski protokol versiyonları',
                        'Telnet': 'Şifresiz iletişim, man-in-the-middle saldırıları',
                        'SMTP': 'Spam, relay saldırıları',
                        'DNS': 'DNS amplification, zone transfer',
                        'HTTP': 'Web uygulama açıkları, bilgi ifşası',
                        'POP3': 'Şifresiz e-posta iletişimi',
                        'NetBIOS': 'Dosya paylaşım açıkları',
                        'SMB': 'Uzaktan kod çalıştırma, dosya paylaşım açıkları',
                        'RDP': 'Brute force, BlueKeep tarzı açıklar',
                        'MySQL': 'SQL injection, yetki yükseltme',
                        'PostgreSQL': 'SQL injection, yetki yükseltme',
                        'MongoDB': 'NoSQL injection, yetki yükseltme',
                        'Redis': 'Kimlik doğrulama bypass, veri sızıntısı',
                        'Oracle': 'SQL injection, yetki yükseltme'
                    }
                    
                    if service in risks:
                        result["findings"].append({
                            "name": f"Riskli Port: {port} ({service})",
                            "description": f"Port {port} üzerinde {service} servisi çalışıyor",
                            "risk_level": "Yüksek" if service in ['Telnet', 'FTP', 'SMB'] else "Orta",
                            "impact": f"Olası riskler: {risks[service]}",
                            "recommendation": "\n".join([
                                f"1. {service} servisini güncel tutun",
                                "2. Güçlü şifreleme ve kimlik doğrulama kullanın",
                                "3. Gerekli değilse servisi kapatın",
                                "4. Güvenlik duvarı kurallarını sıkılaştırın",
                                "5. Erişimi güvenli ağlarla sınırlayın"
                            ])
                        })
            else:
                result["findings"].append({
                    "name": "Açık Port Bulunamadı",
                    "description": f"Hedef: {self.target_host}\n\nİlk 1000 portta açık port tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli port taramalarına devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Port taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Port durumları belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 