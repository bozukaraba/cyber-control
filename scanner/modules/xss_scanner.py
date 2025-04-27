import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
import html

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = {
            'reflected': [
                '<script>alert("xss")</script>',
                '"><script>alert("xss")</script>',
                '"><img src=x onerror=alert("xss")>',
                '"><svg onload=alert("xss")>',
                '"onmouseover="alert(\'xss\')"',
                'javascript:alert("xss")//',
                '<img src=x onerror=alert("xss")>',
                '<svg/onload=alert("xss")>',
                '<iframe/onload=alert("xss")>',
                '<body/onload=alert("xss")>',
                '<input/onfocus=alert("xss")>',
                '<select/onchange=alert("xss")>',
                '<textarea/onselect=alert("xss")>',
                '<a/onclick=alert("xss")>',
                '<div/onmouseover=alert("xss")>',
                '<button/onclick=alert("xss")>',
                '<form/onsubmit=alert("xss")>',
                '<object/onerror=alert("xss")>',
                '<embed/onerror=alert("xss")>',
                '<audio/onerror=alert("xss")>',
                '<video/onerror=alert("xss")>'
            ],
            'stored': [
                '<script>alert("xss")</script>',
                '<img src=x onerror=alert("xss")>',
                '<svg onload=alert("xss")>',
                '<iframe src="javascript:alert(\'xss\')"></iframe>',
                '<body onload=alert("xss")>',
                '<input autofocus onfocus=alert("xss")>',
                '<select onchange=alert("xss")><option>1</option><option>2</option></select>',
                '<textarea onselect=alert("xss")>Select me</textarea>',
                '<a href="javascript:alert(\'xss\')">Click me</a>',
                '<div onmouseover=alert("xss")>Hover me</div>'
            ],
            'dom': [
                'javascript:alert("xss")',
                'data:text/html;base64,PHNjcmlwdD5hbGVydCgneHNzJyk8L3NjcmlwdD4=',
                '#<script>alert("xss")</script>',
                '#"><img src=x onerror=alert("xss")>',
                'javascript:void(alert("xss"))',
                'about:<script>alert("xss")</script>'
            ]
        }
        
    def scan(self):
        """XSS (Cross-Site Scripting) zafiyetlerini test eder"""
        result = {
            "title": "XSS (Cross-Site Scripting) Testi",
            "findings": []
        }
        
        try:
            # Ana sayfayı tara
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Test noktalarını topla
            injection_points = []
            
            # URL parametrelerini kontrol et
            parsed_url = urlparse(self.target_url)
            if parsed_url.query:
                params = parse_qs(parsed_url.query)
                for param in params:
                    injection_points.append({
                        'type': 'get',
                        'param': param,
                        'url': self.target_url,
                        'context': 'url'
                    })
            
            # Formları kontrol et
            for form in soup.find_all('form'):
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                form_url = urljoin(self.target_url, action) if action else self.target_url
                
                # Input alanlarını topla
                for input_tag in form.find_all(['input', 'textarea']):
                    if input_tag.get('type') not in ['submit', 'button', 'file', 'hidden']:
                        context = 'attribute' if input_tag.get('value') else 'text'
                        injection_points.append({
                            'type': method,
                            'param': input_tag.get('name', ''),
                            'url': form_url,
                            'context': context
                        })
            
            if not injection_points:
                result["findings"].append({
                    "name": "XSS Test Noktası Bulunamadı",
                    "description": "Test edilebilecek form veya parametre bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Uygulama giriş noktalarını gözden geçirin"
                })
                return result
            
            # Her nokta için XSS testleri yap
            for point in injection_points:
                vulnerabilities = []
                
                # Reflected XSS testleri
                for payload in self.payloads['reflected']:
                    try:
                        if point['type'] == 'get':
                            params = {point['param']: payload}
                            response = requests.get(point['url'], params=params, verify=False)
                        else:
                            data = {point['param']: payload}
                            response = requests.post(point['url'], data=data, verify=False)
                        
                        # Payload yanıtta var mı kontrol et
                        if payload in response.text and not html.escape(payload) in response.text:
                            vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'payload': payload,
                                'evidence': 'Payload yanıtta escape edilmeden görüntülendi'
                            })
                            break
                            
                    except:
                        continue
                
                # Stored XSS testleri
                if point['type'] == 'post':
                    for payload in self.payloads['stored']:
                        try:
                            # Payload'ı gönder
                            data = {point['param']: payload}
                            requests.post(point['url'], data=data, verify=False)
                            
                            # Ana sayfayı tekrar kontrol et
                            response = requests.get(self.target_url, verify=False)
                            if payload in response.text and not html.escape(payload) in response.text:
                                vulnerabilities.append({
                                    'type': 'Stored XSS',
                                    'payload': payload,
                                    'evidence': 'Payload kalıcı olarak saklandı ve escape edilmeden görüntülendi'
                                })
                                break
                                
                        except:
                            continue
                
                # DOM-based XSS testleri
                if point['context'] == 'url':
                    for payload in self.payloads['dom']:
                        try:
                            if '#' in payload:
                                test_url = point['url'] + payload
                            else:
                                params = {point['param']: payload}
                                test_url = requests.Request('GET', point['url'], params=params).prepare().url
                            
                            response = requests.get(test_url, verify=False)
                            
                            # JavaScript kodunda payload var mı kontrol et
                            soup = BeautifulSoup(response.text, 'html.parser')
                            scripts = soup.find_all('script')
                            
                            for script in scripts:
                                if payload in str(script):
                                    vulnerabilities.append({
                                        'type': 'DOM-based XSS',
                                        'payload': payload,
                                        'evidence': 'Payload JavaScript kodunda işlendi'
                                    })
                                    break
                            
                            if vulnerabilities:
                                break
                                
                        except:
                            continue
                
                # Zafiyet bulunduysa raporla
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        result["findings"].append({
                            "name": f"XSS Açığı: {vuln['type']}",
                            "description": f"URL: {point['url']}\n" + \
                                         f"Parametre: {point['param']}\n" + \
                                         f"Metod: {point['type'].upper()}\n" + \
                                         f"Bağlam: {point['context']}\n" + \
                                         f"Payload: {vuln['payload']}\n" + \
                                         f"Kanıt: {vuln['evidence']}",
                            "risk_level": "Yüksek",
                            "impact": "Kullanıcı oturumlarının çalınması ve zararlı kod çalıştırılması mümkün",
                            "recommendation": "\n".join([
                                "1. Tüm kullanıcı girdilerini HTML encode edin",
                                "2. Content Security Policy (CSP) uygulayın",
                                "3. HttpOnly flag kullanın",
                                "4. X-XSS-Protection header kullanın",
                                "5. Input validasyonu yapın",
                                "6. Güvenli JavaScript framework'leri kullanın",
                                "7. Regular expression ile tehlikeli karakterleri filtreleyin"
                            ])
                        })
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "XSS Açığı Bulunamadı",
                    "description": "Test edilen noktalarda XSS açığı tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"XSS taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "XSS açıkları belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 