import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import mimetypes
import os

class FileUploadScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_files = {
            'php': {
                'content': '<?php echo "test"; ?>',
                'filename': 'test.php',
                'mime': 'application/x-php'
            },
            'php_img': {
                'content': 'GIF89a1\x001\x000\x000\x00\xff\xff\xff!\xf9\x004\x001\x000\x00,\x000\x000\x001\x001\x000\x00\x002\x002\x0044,\x001\x000\x000\x000\x000\x000\x00,\x001\x001\x000\x00<?php echo "test"; ?>',
                'filename': 'test.gif.php',
                'mime': 'image/gif'
            },
            'js': {
                'content': 'alert("test");',
                'filename': 'test.js',
                'mime': 'application/javascript'
            },
            'html': {
                'content': '<script>alert("test");</script>',
                'filename': 'test.html',
                'mime': 'text/html'
            },
            'svg': {
                'content': '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd"><svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg"><script>alert("test");</script></svg>',
                'filename': 'test.svg',
                'mime': 'image/svg+xml'
            }
        }
        
    def scan(self):
        """Dosya yükleme zafiyetlerini test eder"""
        result = {
            "title": "Dosya Yükleme Testi",
            "findings": []
        }
        
        try:
            # Ana sayfayı tara
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Dosya yükleme formlarını bul
            upload_forms = []
            for form in soup.find_all('form', enctype='multipart/form-data'):
                file_inputs = form.find_all('input', type='file')
                if file_inputs:
                    upload_forms.append({
                        'form': form,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'post').lower(),
                        'file_inputs': file_inputs
                    })
            
            if not upload_forms:
                result["findings"].append({
                    "name": "Dosya Yükleme Formu Bulunamadı",
                    "description": "Sayfada dosya yükleme formu tespit edilemedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Dosya yükleme özelliği varsa, güvenli dosya yükleme pratiklerini uygulayın"
                })
                return result
            
            # Her form için test yap
            for upload_form in upload_forms:
                form_url = urljoin(self.target_url, upload_form['action']) if upload_form['action'] else self.target_url
                
                # Form verilerini hazırla
                form_data = {}
                for input_tag in upload_form['form'].find_all('input'):
                    if input_tag.get('name'):
                        if input_tag.get('type') == 'file':
                            continue
                        form_data[input_tag['name']] = input_tag.get('value', '')
                
                # Her dosya input'u için test
                for file_input in upload_form['file_inputs']:
                    input_name = file_input.get('name', 'file')
                    
                    # Her test dosyası için deneme yap
                    for test_type, test_file in self.test_files.items():
                        files = {
                            input_name: (
                                test_file['filename'],
                                test_file['content'],
                                test_file['mime']
                            )
                        }
                        
                        try:
                            if upload_form['method'] == 'post':
                                response = requests.post(form_url, files=files, data=form_data, verify=False, allow_redirects=True)
                            else:
                                response = requests.get(form_url, params={**form_data, input_name: files[input_name]}, verify=False, allow_redirects=True)
                            
                            # Yükleme başarılı mı kontrol et
                            if response.status_code in [200, 201]:
                                # Yüklenen dosyaya erişilebiliyor mu kontrol et
                                uploaded_url = None
                                
                                # Yanıtta dosya URL'i var mı kontrol et
                                soup = BeautifulSoup(response.text, 'html.parser')
                                for img in soup.find_all('img'):
                                    src = img.get('src', '')
                                    if test_file['filename'] in src:
                                        uploaded_url = urljoin(self.target_url, src)
                                        break
                                
                                for a in soup.find_all('a'):
                                    href = a.get('href', '')
                                    if test_file['filename'] in href:
                                        uploaded_url = urljoin(self.target_url, href)
                                        break
                                
                                if uploaded_url:
                                    # Dosyaya erişmeyi dene
                                    file_response = requests.get(uploaded_url, verify=False)
                                    if file_response.status_code == 200:
                                        # Dosya içeriği yürütülebiliyor mu kontrol et
                                        if test_file['content'] in file_response.text:
                                            result["findings"].append({
                                                "name": f"Tehlikeli Dosya Yükleme Açığı ({test_type.upper()})",
                                                "description": f"Form: {form_url}\nInput: {input_name}\nDosya: {test_file['filename']}\nURL: {uploaded_url}",
                                                "risk_level": "Kritik",
                                                "impact": "Zararlı dosyalar yüklenebilir ve çalıştırılabilir",
                                                "recommendation": "\n".join([
                                                    "1. Dosya türü kısıtlaması uygulayın",
                                                    "2. Dosya uzantılarını beyaz liste ile kontrol edin",
                                                    "3. Dosya içeriğini MIME türü ile doğrulayın",
                                                    "4. Yüklenen dosyaları farklı bir domaine veya CDN'e yükleyin",
                                                    "5. Dosya isimlerini rastgele oluşturun",
                                                    "6. Dosya boyutu sınırlaması uygulayın",
                                                    "7. Antivirüs taraması yapın"
                                                ])
                                            })
                
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "Dosya Yükleme Güvenliği Yeterli",
                    "description": "Test edilen dosya yükleme formlarında güvenlik açığı tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Dosya yükleme taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Dosya yükleme açıkları belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 