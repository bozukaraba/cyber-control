import requests
import urllib.parse
from bs4 import BeautifulSoup
import os
import random
import string

class FileUploadScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.upload_forms = []
        # Test edilecek dosya uzantıları ve içerikleri
        self.test_files = [
            {
                "name": "test_malicious.php",
                "content": "<?php echo 'FileUploadScanner Test'; ?>",
                "mime": "application/x-php",
                "type": "php"
            },
            {
                "name": "test_malicious.php.jpg",
                "content": "<?php echo 'FileUploadScanner Test'; ?>",
                "mime": "image/jpeg",
                "type": "php_jpg"
            },
            {
                "name": "test_malicious.jpg",
                "content": "GIF89a<?php echo 'FileUploadScanner Test'; ?>",
                "mime": "image/jpeg", 
                "type": "jpg_shell"
            },
            {
                "name": "test_malicious.html",
                "content": "<script>alert('XSS Test')</script>",
                "mime": "text/html",
                "type": "html"
            }
        ]
        
    def scan(self):
        """Dosya yükleme zafiyeti taraması gerçekleştirir"""
        result = {
            "title": "Dosya Yükleme Zafiyeti Testi",
            "findings": []
        }
        
        try:
            # Upload formlarını bul
            self._find_upload_forms()
            
            if not self.upload_forms:
                result["findings"].append({
                    "name": "Dosya Yükleme Formu",
                    "description": "Herhangi bir dosya yükleme formu tespit edilmedi",
                    "risk_level": "Düşük",
                    "impact": "Herhangi bir sorun tespit edilmedi",
                    "recommendation": "Uygulanabilir değil"
                })
                return result
                
            # Her form için test gerçekleştir
            for form in self.upload_forms:
                vulns = self._test_upload_form(form)
                
                if vulns:
                    for vuln in vulns:
                        result["findings"].append(vuln)
                else:
                    # Güvenli form
                    result["findings"].append({
                        "name": "Güvenli Dosya Yükleme",
                        "description": f"Dosya yükleme formu ({form['action']}) güvenli görünüyor",
                        "risk_level": "Düşük",
                        "impact": "Herhangi bir sorun tespit edilmedi",
                        "recommendation": "Dosya tiplerini ve MIME kontrollerini yapmaya devam edin"
                    })
                    
        except Exception as e:
            result["findings"].append({
                "name": "Dosya Yükleme Testi Hatası",
                "description": f"Dosya yükleme testi sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "Dosya yükleme güvenlik testi tamamlanamadı",
                "recommendation": "Dosya yükleme fonksiyonlarını manuel olarak test edin"
            })
            
        return result
    
    def _find_upload_forms(self):
        """Site içerisindeki dosya yükleme formlarını tespit eder"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Dosya yükleme formu içeren form etiketlerini ara
            forms = soup.find_all('form', enctype="multipart/form-data")
            forms = forms or soup.find_all('form')  # Enctype belirtilmemiş formları da kontrol et
            
            for form in forms:
                # Form içerisinde file input alanı var mı?
                file_inputs = form.find_all('input', {'type': 'file'})
                
                if file_inputs:
                    # Form bilgilerini topla
                    action = form.get('action', '')
                    method = form.get('method', 'post').lower()
                    
                    # Form action URL'sini oluştur
                    if not action.startswith(('http://', 'https://')):
                        # Göreceli URL'yi mutlak URL'ye çevir
                        parsed_url = urllib.parse.urlparse(self.target_url)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        action = urllib.parse.urljoin(base_url, action)
                    
                    # Form verilerini topla
                    inputs = []
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        input_name = input_tag.get('name')
                        input_type = input_tag.get('type', '')
                        
                        if input_name and input_type != 'file':
                            input_value = input_tag.get('value', '')
                            inputs.append({
                                'name': input_name,
                                'value': input_value
                            })
                    
                    # Dosya input alanlarını topla
                    file_fields = []
                    for file_input in file_inputs:
                        file_name = file_input.get('name')
                        if file_name:
                            file_fields.append(file_name)
                    
                    # Form bilgilerini kaydet
                    self.upload_forms.append({
                        'action': action,
                        'method': method,
                        'inputs': inputs,
                        'file_fields': file_fields
                    })
            
            # Sayfa içinde başka bağlantıları da kontrol et
            self._check_additional_pages(soup)
            
        except requests.exceptions.RequestException:
            pass
            
    def _check_additional_pages(self, soup):
        """Upload alanlarını bulmak için ek sayfaları kontrol et"""
        upload_keywords = ['upload', 'dosya', 'yükle', 'file', 'attach', 'ekle']
        
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            link_text = link.text.lower()
            
            # Upload ile ilgili bir bağlantı mı?
            is_upload_link = False
            for keyword in upload_keywords:
                if keyword in link_text or keyword in href.lower():
                    is_upload_link = True
                    break
                    
            if is_upload_link:
                # Bağlantı URL'sini oluştur
                if not href.startswith(('http://', 'https://')):
                    parsed_url = urllib.parse.urlparse(self.target_url)
                    base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    href = urllib.parse.urljoin(base_url, href)
                
                # Bağlantıdaki sayfayı kontrol et
                try:
                    page_response = requests.get(href, timeout=5, verify=False)
                    page_soup = BeautifulSoup(page_response.text, 'html.parser')
                    
                    # Bu sayfadaki upload formlarını bul
                    forms = page_soup.find_all('form', enctype="multipart/form-data")
                    forms = forms or page_soup.find_all('form')
                    
                    for form in forms:
                        file_inputs = form.find_all('input', {'type': 'file'})
                        
                        if file_inputs:
                            action = form.get('action', '')
                            method = form.get('method', 'post').lower()
                            
                            if not action.startswith(('http://', 'https://')):
                                parsed_url = urllib.parse.urlparse(href)
                                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                                action = urllib.parse.urljoin(base_url, action)
                            
                            # Form verilerini topla
                            inputs = []
                            for input_tag in form.find_all(['input', 'textarea', 'select']):
                                input_name = input_tag.get('name')
                                input_type = input_tag.get('type', '')
                                
                                if input_name and input_type != 'file':
                                    input_value = input_tag.get('value', '')
                                    inputs.append({
                                        'name': input_name,
                                        'value': input_value
                                    })
                            
                            file_fields = []
                            for file_input in file_inputs:
                                file_name = file_input.get('name')
                                if file_name:
                                    file_fields.append(file_name)
                            
                            # Benzersiz formları ekle
                            form_exists = False
                            for existing_form in self.upload_forms:
                                if existing_form['action'] == action:
                                    form_exists = True
                                    break
                                    
                            if not form_exists:
                                self.upload_forms.append({
                                    'action': action,
                                    'method': method,
                                    'inputs': inputs,
                                    'file_fields': file_fields
                                })
                            
                except requests.exceptions.RequestException:
                    continue
            
    def _test_upload_form(self, form):
        """Tespit edilen dosya yükleme formlarını test eder"""
        vulnerabilities = []
        
        # Her dosya alanı için test et
        for file_field in form['file_fields']:
            # Farklı dosya türlerini test et
            for test_file in self.test_files:
                # Rastgele dosya adı oluştur (aynı dosya tespitinden kaçınmak için)
                random_suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
                filename = f"{os.path.splitext(test_file['name'])[0]}_{random_suffix}{os.path.splitext(test_file['name'])[1]}"
                
                # Form verilerini hazırla
                form_data = {}
                files = {}
                
                # Diğer form alanlarını doldur
                for input_field in form['inputs']:
                    form_data[input_field['name']] = input_field['value'] or 'test'
                
                # Dosya ekle
                files[file_field] = (filename, test_file['content'], test_file['mime'])
                
                try:
                    # Formu gönder
                    if form['method'] == 'post':
                        response = requests.post(form['action'], data=form_data, files=files, timeout=10, verify=False, allow_redirects=True)
                    else:
                        response = requests.get(form['action'], params=form_data, files=files, timeout=10, verify=False, allow_redirects=True)
                    
                    # Yanıtı kontrol et
                    upload_success = self._check_upload_result(response, filename, test_file)
                    
                    if upload_success:
                        vuln_type = test_file['type']
                        
                        if vuln_type == 'php':
                            vulnerabilities.append({
                                "name": "PHP Dosyası Yükleme",
                                "description": f"Form ({form['action']}) PHP dosyasının yüklenmesine izin veriyor",
                                "risk_level": "Kritik",
                                "impact": "Saldırganlar web shell yükleyebilir ve sunucuya erişim sağlayabilir",
                                "recommendation": "PHP gibi çalıştırılabilir dosya türlerini engelleyin ve dosya uzantılarını kontrol edin"
                            })
                        elif vuln_type == 'php_jpg':
                            vulnerabilities.append({
                                "name": "PHP Uzantılı Dosya Bypass",
                                "description": f"Form ({form['action']}) çift uzantılı PHP dosyasının (.php.jpg) yüklenmesine izin veriyor",
                                "risk_level": "Kritik",
                                "impact": "Saldırganlar uzantı filtrelerini atlatarak zararlı kod yükleyebilir",
                                "recommendation": "Tüm dosya uzantılarını kontrol edin ve çift uzantılı dosyaları reddedin"
                            })
                        elif vuln_type == 'jpg_shell':
                            vulnerabilities.append({
                                "name": "Görüntü İçinde Kod",
                                "description": f"Form ({form['action']}) içerisinde PHP kodu bulunan sahte resim dosyasının yüklenmesine izin veriyor",
                                "risk_level": "Yüksek",
                                "impact": "Saldırganlar görüntü dosyalarının içine gizlenmiş zararlı kod çalıştırabilir",
                                "recommendation": "Dosya içeriğini tam olarak kontrol edin ve dosya türünü doğrulayın"
                            })
                        elif vuln_type == 'html':
                            vulnerabilities.append({
                                "name": "HTML/Script Dosyası Yükleme",
                                "description": f"Form ({form['action']}) HTML veya script dosyalarının yüklenmesine izin veriyor",
                                "risk_level": "Orta",
                                "impact": "Saldırganlar XSS saldırıları gerçekleştirebilir",
                                "recommendation": "İzin verilen dosya türlerini kısıtlayın ve HTML/JS dosyalarını engelleyin"
                            })
                    
                except requests.exceptions.RequestException:
                    continue
        
        return vulnerabilities
                    
    def _check_upload_result(self, response, filename, test_file):
        """Yükleme işleminin başarılı olup olmadığını kontrol eder"""
        # Başarı göstergeleri
        success_indicators = [
            "success", "başarılı", "uploaded", "yüklendi", "complete", "tamamlandı"
        ]
        
        # Hata göstergeleri
        error_indicators = [
            "error", "hata", "invalid", "geçersiz", "failed", "başarısız", 
            "not allowed", "izin verilmiyor", "invalid file", "geçersiz dosya"
        ]
        
        # Yanıt içinde başarı göstergesi var mı?
        response_text_lower = response.text.lower()
        
        for indicator in success_indicators:
            if indicator in response_text_lower:
                # Başarı mesajı varsa
                return True
                
        # Hata mesajı var mı kontrol et
        for indicator in error_indicators:
            if indicator in response_text_lower:
                # Hata mesajı varsa
                return False
                
        # Dosya adı yanıtta görünüyor mu?
        if filename.lower() in response_text_lower:
            return True
            
        # Eğer yanıt durum kodu 200 OK ise ve hata mesajı yoksa
        # Bu muhtemelen başarılı bir yüklemedir
        if response.status_code == 200 and not any(err in response_text_lower for err in error_indicators):
            return True
            
        return False 