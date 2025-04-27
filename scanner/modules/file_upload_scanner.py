import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import mimetypes
import os
import random
import string

class FileUploadScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_files = [
            {
                'name': 'test.php',
                'content': '<?php echo "test"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.php.jpg',
                'content': '<?php echo "test"; ?>',
                'type': 'image/jpeg'
            },
            {
                'name': 'test.php%00.jpg',
                'content': '<?php echo "test"; ?>',
                'type': 'image/jpeg'
            },
            {
                'name': 'test.php.',
                'content': '<?php echo "test"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.PHP',
                'content': '<?php echo "test"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.phtml',
                'content': '<?php echo "test"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.phps',
                'content': '<?php echo "test"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.pht',
                'content': '<?php echo "test"; ?>',
                'type': 'application/x-php'
            },
            {
                'name': 'test.asp',
                'content': '<%Response.Write("test")%>',
                'type': 'application/x-asp'
            },
            {
                'name': 'test.aspx',
                'content': '<%Response.Write("test")%>',
                'type': 'application/x-aspx'
            },
            {
                'name': 'test.jsp',
                'content': '<%out.println("test");%>',
                'type': 'application/x-jsp'
            },
            {
                'name': 'test.html',
                'content': '<script>alert("test")</script>',
                'type': 'text/html'
            },
            {
                'name': 'test.htaccess',
                'content': 'AddType application/x-httpd-php .jpg',
                'type': 'application/x-htaccess'
            }
        ]
        
    def find_upload_forms(self):
        """Dosya yükleme formlarını bulur"""
        forms = []
        try:
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form elementlerini bul
            for form in soup.find_all('form'):
                # Multipart form kontrolü
                if form.get('enctype') == 'multipart/form-data':
                    action = form.get('action', '')
                    if not action:
                        action = self.target_url
                    else:
                        action = urljoin(self.target_url, action)
                        
                    method = form.get('method', 'post').lower()
                    file_inputs = []
                    
                    # File input'ları bul
                    for input_tag in form.find_all('input', type='file'):
                        input_name = input_tag.get('name', '')
                        if input_name:
                            file_inputs.append(input_name)
                            
                    if file_inputs:
                        forms.append({
                            'url': action,
                            'method': method,
                            'inputs': file_inputs
                        })
                        
            return forms
            
        except Exception as e:
            return []
            
    def generate_random_string(self, length=10):
        """Rastgele string üretir"""
        return ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        
    def test_upload(self, form, test_file):
        """Dosya yükleme denemesi yapar"""
        try:
            url = form['url']
            method = form['method']
            
            # Rastgele içerik ekle
            content = test_file['content'] + f'<!-- {self.generate_random_string()} -->'
            
            # Dosyayı hazırla
            files = {}
            for input_name in form['inputs']:
                files[input_name] = (
                    test_file['name'],
                    content,
                    test_file['type']
                )
            
            # İsteği gönder
            response = requests.post(url, files=files, verify=False)
            
            # Yanıtı analiz et
            uploaded_url = None
            
            # Yanıtta dosya yolu var mı kontrol et
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Link ve img taglerini kontrol et
            for tag in soup.find_all(['a', 'img']):
                href = tag.get('href') or tag.get('src')
                if href and (test_file['name'] in href or content in href):
                    uploaded_url = urljoin(url, href)
                    break
            
            # JavaScript içinde dosya yolu var mı kontrol et
            if not uploaded_url:
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string and (test_file['name'] in script.string or content in script.string):
                        matches = re.findall(r'["\'](\/[^"\']*?' + test_file['name'] + '[^"\']*?)["\']', script.string)
                        if matches:
                            uploaded_url = urljoin(url, matches[0])
                            break
            
            if uploaded_url:
                # Yüklenen dosyaya erişmeyi dene
                file_response = requests.get(uploaded_url, verify=False)
                if file_response.status_code == 200 and content in file_response.text:
                    return {
                        'url': uploaded_url,
                        'content_type': file_response.headers.get('Content-Type'),
                        'size': len(file_response.content),
                        'executable': self.is_file_executable(file_response)
                    }
            
            return None
            
        except Exception as e:
            return None
            
    def is_file_executable(self, response):
        """Dosyanın çalıştırılabilir olup olmadığını kontrol eder"""
        content_type = response.headers.get('Content-Type', '').lower()
        executable_types = [
            'application/x-php',
            'application/x-httpd-php',
            'application/x-asp',
            'application/x-aspx',
            'application/x-jsp',
            'text/html'
        ]
        
        # Content-Type kontrolü
        if any(t in content_type for t in executable_types):
            return True
            
        # PHP error kontrolü
        if 'php' in content_type or \
           'fatal error' in response.text.lower() or \
           'parse error' in response.text.lower() or \
           '<?php' in response.text:
            return True
            
        # ASP/ASPX error kontrolü
        if 'asp' in content_type or \
           'server error' in response.text.lower() or \
           'compilation error' in response.text.lower():
            return True
            
        # JSP error kontrolü
        if 'jsp' in content_type or \
           'java.lang' in response.text or \
           'javax.servlet' in response.text:
            return True
            
        return False
        
    def scan(self):
        """Dosya yükleme zafiyetlerini test eder"""
        result = {
            "title": "Dosya Yükleme Zafiyeti Testi",
            "findings": []
        }
        
        try:
            # Upload formlarını bul
            forms = self.find_upload_forms()
            
            if not forms:
                result["findings"].append({
                    "name": "Upload Formu Bulunamadı",
                    "description": "Dosya yükleme testi için uygun form bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Test yapılamadı",
                    "recommendation": "Dosya yükleme özelliği olan sayfaları kontrol edin"
                })
                return result
            
            # Her form için dosya yükleme testleri yap
            vulnerable_forms = []
            
            for form in forms:
                for test_file in self.test_files:
                    finding = self.test_upload(form, test_file)
                    if finding:
                        vuln = {
                            'form_url': form['url'],
                            'file_name': test_file['name'],
                            'uploaded_url': finding['url'],
                            'content_type': finding['content_type'],
                            'size': finding['size'],
                            'executable': finding['executable']
                        }
                        
                        if vuln not in vulnerable_forms:
                            vulnerable_forms.append(vuln)
            
            # Bulunan zafiyetleri raporla
            if vulnerable_forms:
                for vuln in vulnerable_forms:
                    risk_level = "Kritik" if vuln['executable'] else "Yüksek"
                    
                    result["findings"].append({
                        "name": "Dosya Yükleme Zafiyeti",
                        "description": f"Form URL: {vuln['form_url']}\n" + \
                                     f"Yüklenen Dosya: {vuln['file_name']}\n" + \
                                     f"Erişim URL: {vuln['uploaded_url']}\n" + \
                                     f"Content-Type: {vuln['content_type']}\n" + \
                                     f"Boyut: {vuln['size']} bytes\n" + \
                                     f"Çalıştırılabilir: {'Evet' if vuln['executable'] else 'Hayır'}",
                        "risk_level": risk_level,
                        "impact": "Saldırganlar zararlı dosyalar yükleyebilir ve çalıştırabilir",
                        "recommendation": "\n".join([
                            "1. Dosya türü kontrolü yapın (whitelist)",
                            "2. Dosya uzantısı kontrolü yapın",
                            "3. MIME type kontrolü yapın",
                            "4. Dosya içeriği kontrolü yapın",
                            "5. Dosya boyutu sınırlaması koyun",
                            "6. Yüklenen dosyaları farklı bir domaine kaydedin",
                            "7. Dosya isimlerini rastgele oluşturun",
                            "8. Dosyaları web kökü dışında saklayın",
                            "9. Dosya izinlerini sınırlayın (chmod)",
                            "10. Upload dizininde kod çalıştırmayı engelleyin"
                        ])
                    })
            else:
                result["findings"].append({
                    "name": "Dosya Yükleme Zafiyeti Tespit Edilmedi",
                    "description": "Test edilen formlarda dosya yükleme zafiyeti bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Dosya yükleme taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Dosya yükleme zafiyetleri belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 