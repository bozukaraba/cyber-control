import requests
import time
import urllib.parse
from bs4 import BeautifulSoup

class SQLInjectionScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.payloads = {
            "error_based": [
                "' OR 1=1 --",
                "\" OR 1=1 --",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "') OR ('1'='1",
                "\") OR (\"1\"=\"1",
                "' OR '1'='1' --",
                "\" OR \"1\"=\"1\" --",
                "' OR 1=1#",
                "\" OR 1=1#",
                "' OR 1=1/*",
                "\" OR 1=1/*",
                "' UNION SELECT 1,2,3 --",
                "\" UNION SELECT 1,2,3 --"
            ],
            "time_based": [
                "'; WAITFOR DELAY '0:0:5' --",
                "\"; WAITFOR DELAY '0:0:5' --",
                "' OR SLEEP(5) --",
                "\" OR SLEEP(5) --",
                "' AND SLEEP(5) --",
                "\" AND SLEEP(5) --",
                "'; SELECT SLEEP(5) --",
                "\"; SELECT SLEEP(5) --"
            ]
        }
        self.error_messages = [
            "SQL syntax",
            "mysql_fetch",
            "mysqli_fetch",
            "mysql_num_rows",
            "mysql_query",
            "pg_query",
            "sqlite_query",
            "ORA-",
            "Microsoft SQL Native Client error",
            "Microsoft OLE DB Provider for SQL Server error",
            "Microsoft OLE DB Provider for ODBC Drivers error",
            "Microsoft JET Database Engine error",
            "ODBC Microsoft Access Driver",
            "ODBC SQL Server Driver",
            "SQLite3::",
            "Warning: pg_",
            "Warning: mysql_",
            "Warning: mysqli_",
            "PostgreSQL query failed"
        ]
    
    def scan(self):
        """SQL Injection zafiyeti taraması gerçekleştirir"""
        result = {
            "title": "SQL Injection Testi",
            "findings": []
        }
        
        try:
            # URL parametrelerini analiz et
            parsed_url = urllib.parse.urlparse(self.target_url)
            query_params = urllib.parse.parse_qs(parsed_url.query)
            
            # URL parametreleri varsa SQL injection denemeleri yap
            if query_params:
                for param in query_params:
                    # Error-based SQL Injection
                    if self._test_error_based_sqli(param):
                        result["findings"].append({
                            "name": "Error-Based SQL Injection",
                            "description": f"URL parametresi '{param}' için SQL Injection zafiyeti tespit edildi",
                            "risk_level": "Kritik",
                            "impact": "Veritabanına yetkisiz erişim, veri sızıntısı ve/veya düzenleme riski",
                            "recommendation": "Tüm kullanıcı girdilerini doğrulayın ve parametreli sorgular kullanın"
                        })
                        break
                        
                    # Time-based SQL Injection
                    if self._test_time_based_sqli(param):
                        result["findings"].append({
                            "name": "Time-Based SQL Injection",
                            "description": f"URL parametresi '{param}' için Time-based SQL Injection zafiyeti tespit edildi",
                            "risk_level": "Kritik",
                            "impact": "Veritabanına yetkisiz erişim, veri sızıntısı ve/veya düzenleme riski",
                            "recommendation": "Tüm kullanıcı girdilerini doğrulayın ve parametreli sorgular kullanın"
                        })
                        break
            else:
                # Form alanlarını bul ve test et
                forms = self._find_forms()
                if forms:
                    for form in forms:
                        for field in form['fields']:
                            # Error-based SQL Injection (form)
                            if self._test_form_error_based_sqli(form, field):
                                result["findings"].append({
                                    "name": "Form SQL Injection",
                                    "description": f"Form alanı '{field}' için SQL Injection zafiyeti tespit edildi",
                                    "risk_level": "Kritik",
                                    "impact": "Veritabanına yetkisiz erişim, veri sızıntısı ve/veya düzenleme riski",
                                    "recommendation": "Tüm kullanıcı girdilerini doğrulayın ve parametreli sorgular kullanın"
                                })
                                break
        
        except Exception as e:
            result["findings"].append({
                "name": "SQL Injection Tarama Hatası",
                "description": f"SQL Injection testi sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "SQL Injection taraması tamamlanamadı",
                "recommendation": "Taramayı yeniden deneyin veya manuel olarak test edin"
            })
        
        if not result["findings"]:
            result["findings"].append({
                "name": "SQL Injection",
                "description": "SQL Injection zafiyeti tespit edilmedi",
                "risk_level": "Düşük",
                "impact": "Herhangi bir sorun tespit edilmedi",
                "recommendation": "Güvenli kodlama pratiklerine devam edin ve düzenli olarak güvenlik taramaları yapın"
            })
            
        return result
    
    def _test_error_based_sqli(self, param):
        """URL parametresi için error-based SQL Injection testi yapar"""
        parsed_url = urllib.parse.urlparse(self.target_url)
        
        for payload in self.payloads["error_based"]:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            query_params[param] = [payload]
            
            # Yeni sorgu oluştur
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
            
            try:
                response = requests.get(test_url, timeout=10, verify=False)
                
                # Hata mesajları için yanıtı kontrol et
                for error in self.error_messages:
                    if error in response.text:
                        return True
                        
            except requests.exceptions.RequestException:
                continue
                
        return False
    
    def _test_time_based_sqli(self, param):
        """URL parametresi için time-based SQL Injection testi yapar"""
        parsed_url = urllib.parse.urlparse(self.target_url)
        
        for payload in self.payloads["time_based"]:
            query_params = urllib.parse.parse_qs(parsed_url.query)
            query_params[param] = [payload]
            
            # Yeni sorgu oluştur
            new_query = urllib.parse.urlencode(query_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed_url._replace(query=new_query))
            
            try:
                start_time = time.time()
                response = requests.get(test_url, timeout=10, verify=False)
                elapsed_time = time.time() - start_time
                
                # Gecikme durumunu kontrol et (eşik değeri 4 saniye)
                if elapsed_time > 4:
                    return True
                    
            except requests.exceptions.Timeout:
                # Zaman aşımı da bir time-based SQLi göstergesi olabilir
                return True
            except requests.exceptions.RequestException:
                continue
                
        return False
    
    def _find_forms(self):
        """Hedef URL'deki formları bulur"""
        forms = []
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for form in soup.find_all('form'):
                form_info = {
                    'action': form.get('action', ''),
                    'method': form.get('method', 'get').lower(),
                    'fields': []
                }
                
                for input_field in form.find_all(['input', 'textarea']):
                    field_name = input_field.get('name')
                    if field_name:
                        form_info['fields'].append(field_name)
                        
                if form_info['fields']:
                    forms.append(form_info)
                    
        except requests.exceptions.RequestException:
            pass
            
        return forms
    
    def _test_form_error_based_sqli(self, form, field):
        """Form alanı için error-based SQL Injection testi yapar"""
        form_url = form['action']
        if not form_url.startswith('http'):
            # Göreceli URL ise mutlak URL oluştur
            parsed_url = urllib.parse.urlparse(self.target_url)
            base_url = urllib.parse.urlunparse((parsed_url.scheme, parsed_url.netloc, '', '', '', ''))
            form_url = urllib.parse.urljoin(base_url, form_url)
            
        for payload in self.payloads["error_based"]:
            form_data = {field: payload}
            
            try:
                if form['method'] == 'post':
                    response = requests.post(form_url, data=form_data, timeout=10, verify=False)
                else:
                    response = requests.get(form_url, params=form_data, timeout=10, verify=False)
                    
                # Hata mesajları için yanıtı kontrol et
                for error in self.error_messages:
                    if error in response.text:
                        return True
                        
            except requests.exceptions.RequestException:
                continue
                
        return False 