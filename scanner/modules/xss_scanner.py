import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
import re

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.xss_payloads = [
            '<script>alert(1)</script>',
            '"><script>alert(1)</script>',
            '"><img src=x onerror=alert(1)>',
            '"><svg onload=alert(1)>',
            '"onmouseover="alert(1)',
            '"><iframe src="javascript:alert(1)">',
            '`-alert(1)-`',
            '\';alert(1);//',
            '${alert(1)}',
            '<img src=x onerror=alert(1)>',
            '<body onload=alert(1)>',
            '<details open ontoggle=alert(1)>',
            '<svg><script>alert(1)</script>',
            '"><script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>'
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
        """XSS payload'ını test eder"""
        try:
            url = input_data['url']
            method = input_data['method']
            test_data = {}
            
            # Her input için payload'ı dene
            for input_name in input_data['inputs']:
                test_data[input_name] = payload
            
            # İsteği gönder
            if method == 'get':
                response = requests.get(url, params=test_data, verify=False)
            else:
                response = requests.post(url, data=test_data, verify=False)
            
            # Payload yanıtta var mı kontrol et
            content = response.text.lower()
            payload_lower = payload.lower()
            
            # HTML encode edilmiş karakterleri kontrol et
            payload_encoded = payload.replace('<', '&lt;').replace('>', '&gt;').lower()
            
            # JavaScript encode edilmiş karakterleri kontrol et
            payload_js = payload.replace('"', '\\"').replace("'", "\\'").lower()
            
            if (payload_lower in content and not payload_encoded in content) or \
               (payload_js in content and 'string' not in content):
                return True
                
            return False
            
        except Exception as e:
            return False
            
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
        """XSS zafiyetlerini test eder"""
        result = {
            "title": "XSS (Cross Site Scripting) Testi",
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
                    "impact": "XSS saldırıları WAF tarafından engellenebilir",
                    "recommendation": "WAF kurallarını güncel ve aktif tutun"
                })
            
            # Input noktalarını bul
            inputs = self.find_inputs(self.target_url)
            
            if not inputs:
                result["findings"].append({
                    "name": "Test Edilebilir Input Bulunamadı",
                    "description": "XSS testi için uygun form veya URL parametresi bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Test yapılamadı",
                    "recommendation": "Dinamik içerik barındıran sayfaları kontrol edin"
                })
                return result
            
            # Her input için XSS testleri yap
            vulnerable_inputs = []
            
            for input_data in inputs:
                for payload in self.xss_payloads:
                    if self.test_input(input_data, payload):
                        input_url = input_data['url']
                        input_method = input_data['method']
                        input_names = ', '.join(input_data['inputs'])
                        
                        finding = {
                            'url': input_url,
                            'method': input_method,
                            'inputs': input_names,
                            'payload': payload
                        }
                        
                        if finding not in vulnerable_inputs:
                            vulnerable_inputs.append(finding)
            
            # Bulunan zafiyetleri raporla
            if vulnerable_inputs:
                for vuln in vulnerable_inputs:
                    result["findings"].append({
                        "name": "XSS Zafiyeti Tespit Edildi",
                        "description": f"URL: {vuln['url']}\n" + \
                                     f"Method: {vuln['method'].upper()}\n" + \
                                     f"Inputs: {vuln['inputs']}\n" + \
                                     f"Payload: {vuln['payload']}",
                        "risk_level": "Yüksek",
                        "impact": "Saldırganlar kullanıcı tarayıcısında JavaScript kodu çalıştırabilir",
                        "recommendation": "\n".join([
                            "1. Tüm kullanıcı girdilerini doğrulayın ve temizleyin",
                            "2. HTML özel karakterlerini encode edin",
                            "3. Content Security Policy (CSP) uygulayın",
                            "4. HttpOnly flag kullanın",
                            "5. X-XSS-Protection header ekleyin"
                        ])
                    })
            else:
                result["findings"].append({
                    "name": "XSS Zafiyeti Tespit Edilmedi",
                    "description": "Test edilen noktalarda XSS zafiyeti bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"XSS taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "XSS zafiyetleri belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 