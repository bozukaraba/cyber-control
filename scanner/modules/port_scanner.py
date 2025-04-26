import socket
import threading
import queue
import nmap

class PortScanner:
    def __init__(self, hostname):
        self.hostname = hostname
        self.ports = []
        self.port_queue = queue.Queue()
        self.results = {
            "title": "Açık Port Taraması",
            "findings": []
        }
        
    def scan(self):
        """Açık port taraması gerçekleştirir"""
        try:
            # Nmap kullanarak en yaygın 1000 portu tara
            self._scan_common_ports()
            
            # Açık portlar varsa raporla
            if not self.results["findings"]:
                self.results["findings"].append({
                    "name": "Açık Port Taraması",
                    "description": "Açık port tespit edilmedi",
                    "risk_level": "Düşük",
                    "impact": "Herhangi bir sorun tespit edilmedi",
                    "recommendation": "Düzenli güvenlik taramaları yapın"
                })
                
        except Exception as e:
            self.results["findings"].append({
                "name": "Port Tarama Hatası",
                "description": f"Port tarama sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "Port taraması tamamlanamadı",
                "recommendation": "Tarama yeniden deneyin veya başka bir araç kullanın"
            })
            
        return self.results
    
    def _scan_common_ports(self):
        """Nmap kullanarak en yaygın 1000 portu tarar"""
        try:
            scanner = nmap.PortScanner()
            # -F parametresi ile 100 yaygın port taraması (-Pn ile host discovery atlanır)
            scanner.scan(self.hostname, arguments='-F -Pn')
            
            open_ports = []
            
            for host in scanner.all_hosts():
                for proto in scanner[host].all_protocols():
                    lport = scanner[host][proto].keys()
                    for port in lport:
                        if scanner[host][proto][port]['state'] == 'open':
                            service = scanner[host][proto][port]['name'] if 'name' in scanner[host][proto][port] else 'bilinmeyen'
                            open_ports.append({
                                'port': port,
                                'protocol': proto,
                                'service': service,
                                'state': 'open'
                            })
                            
            if open_ports:
                # Yaygın portları ve ilgili hizmetleri raporla
                port_list = ", ".join([f"{p['port']}/{p['protocol']} ({p['service']})" for p in open_ports])
                self.results["findings"].append({
                    "name": "Açık Portlar",
                    "description": f"Taramada açık portlar bulundu: {port_list}",
                    "risk_level": "Orta",
                    "impact": "Açık portlar yetkisiz erişim için potansiyel noktalar oluşturabilir",
                    "recommendation": "Gereksiz açık portları kapatın ve gerekli portlarda güvenlik duvarı kurallarını yapılandırın"
                })
                
            # Yaygın hassas portları kontrol et (21, 22, 23, 3389 gibi)
            sensitive_ports = {
                21: "FTP", 
                22: "SSH", 
                23: "Telnet", 
                3389: "RDP"
            }
            
            for p in open_ports:
                port_num = int(p['port'])
                if port_num in sensitive_ports:
                    self.results["findings"].append({
                        "name": f"Hassas Port: {port_num} ({sensitive_ports[port_num]})",
                        "description": f"Hassas olarak kabul edilen {port_num} portu açık",
                        "risk_level": "Yüksek",
                        "impact": f"{sensitive_ports[port_num]} servisi yetkisiz erişime açık olabilir",
                        "recommendation": f"Port {port_num}'i güvenlik duvarında kısıtlayın veya kapatın"
                    })
                
        except Exception as e:
            self.results["findings"].append({
                "name": "Nmap Tarama Hatası",
                "description": f"Nmap taraması sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "Nmap taraması tamamlanamadı",
                "recommendation": "Nmap kurulumunu kontrol edin veya manuel port taraması yapın"
            }) 