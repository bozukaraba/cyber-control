import requests
import urllib.parse
from bs4 import BeautifulSoup
import time
import re

class BruteForceScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.login_forms = []
        self.test_credentials = [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "123456"},
            {"username": "administrator", "password": "administrator"},
            {"username": "root", "password": "root"},
            {"username": "test", "password": "test"}
        ]
        self.login_keywords = [
            'login', 'sign in', 'signin', 'log in', 'username', 'password', 
            'user name', 'kullanıcı adı', 'şifre', 'giriş', 'oturum aç'
        ]
        
    def scan(self):
        """Brute Force saldırısı zafiyeti testi yapar"""
        result = {
            "title": "Brute Force Saldırı Testi",
            "findings": []
        }
        
        try:
            # Login formlarını bul
            self._find_login_forms()
            
            if not self.login_forms:
                result["findings"].append({
                    "name": "Login Formu",
                    "description": "Herhangi bir login formu tespit edilmedi",
                    "risk_level": "Düşük",
                    "impact": "Herhangi bir sorun tespit edilmedi",
                    "recommendation": "Uygulanabilir değil"
                })
                return result
                
            # CAPTCHA kontrolü yap
            captcha_forms = self._check_captcha()
            
            if captcha_forms:
                captcha_urls = ", ".join([form['url'] for form in captcha_forms])
                result["findings"].append({
                    "name": "CAPTCHA Koruması",
                    "description": f"Login formlarında CAPTCHA koruması tespit edildi: {captcha_urls}",
                    "risk_level": "Düşük",
                    "impact": "CAPTCHA koruması brute force saldırılarına karşı koruma sağlar",
                    "recommendation": "CAPTCHA korumasını sürdürün ve güncel tutun"
                })
            
            # Rate limiting kontrolü yap
            rate_limited_forms = self._check_rate_limiting()
            
            if rate_limited_forms:
                limited_urls = ", ".join([form['url'] for form in rate_limited_forms])
                result["findings"].append({
                    "name": "Rate Limiting Koruması",
                    "description": f"Login formlarında istek sınırlaması (rate limiting) tespit edildi: {limited_urls}",
                    "risk_level": "Düşük",
                    "impact": "İstek sınırlaması brute force saldırılarını yavaşlatır",
                    "recommendation": "Rate limiting korumasını sürdürün ve güçlendirin"
                })
            
            # Güvenli olmayan formları bul
            vulnerable_forms = []
            
            for form in self.login_forms:
                # Bu form CAPTCHA veya rate limiting koruması var mı?
                form_url = form['url']
                is_protected = False
                
                for captcha_form in captcha_forms:
                    if captcha_form['url'] == form_url:
                        is_protected = True
                        break
                        
                if not is_protected:
                    for rate_limited_form in rate_limited_forms:
                        if rate_limited_form['url'] == form_url:
                            is_protected = True
                            break
                
                if not is_protected:
                    vulnerable_forms.append(form)
            
            # Güvenli olmayan formları raporla
            if vulnerable_forms:
                vuln_urls = ", ".join([form['url'] for form in vulnerable_forms])
                result["findings"].append({
                    "name": "Brute Force Zafiyeti",
                    "description": f"Login formları brute force saldırılarına karşı korumasız: {vuln_urls}",
                    "risk_level": "Yüksek",
                    "impact": "Saldırganlar şifre tahmin saldırıları ile hesaplara erişebilir",
                    "recommendation": "CAPTCHA, rate limiting, geçici hesap kilitleme gibi koruma mekanizmaları ekleyin"
                })
            else:
                if self.login_forms and (captcha_forms or rate_limited_forms):
                    result["findings"].append({
                        "name": "Brute Force Koruması",
                        "description": "Login formları brute force saldırılarına karşı korumalı görünüyor",
                        "risk_level": "Düşük",
                        "impact": "Herhangi bir sorun tespit edilmedi",
                        "recommendation": "Güvenlik önlemlerini sürdürün ve güncel tutun"
                    })
                
        except Exception as e:
            result["findings"].append({
                "name": "Brute Force Testi Hatası",
                "description": f"Brute force testi sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "Brute force saldırı testi tamamlanamadı",
                "recommendation": "Login formlarını manuel olarak kontrol edin"
            })
            
        return result
    
    def _find_login_forms(self):
        """Site içerisindeki login formlarını tespit eder"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Tüm formları bul
            forms = soup.find_all('form')
            
            for form in forms:
                # Bu bir login formu mu?
                if self._is_login_form(form):
                    # Form bilgilerini topla
                    action = form.get('action', '')
                    method = form.get('method', 'post').lower()
                    
                    # Form action URL'sini oluştur
                    if not action.startswith(('http://', 'https://')):
                        # Göreceli URL'yi mutlak URL'ye çevir
                        parsed_url = urllib.parse.urlparse(self.target_url)
                        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                        action = urllib.parse.urljoin(base_url, action)
                    
                    # Form alanlarını topla
                    username_field = None
                    password_field = None
                    other_fields = []
                    
                    # Username ve password alanlarını bul
                    for input_tag in form.find_all('input'):
                        input_type = input_tag.get('type', '')
                        input_name = input_tag.get('name')
                        
                        if input_name:
                            input_value = input_tag.get('value', '')
                            
                            # Username alanı
                            if (input_type == 'text' or input_type == 'email') and username_field is None:
                                username_field = input_name
                            # Password alanı
                            elif input_type == 'password':
                                password_field = input_name
                            # Diğer alanlar
                            elif input_type != 'submit' and input_type != 'button':
                                other_fields.append({
                                    'name': input_name,
                                    'value': input_value
                                })
                    
                    # En az bir username ve password alanı varsa
                    if username_field and password_field:
                        self.login_forms.append({
                            'url': action,
                            'method': method,
                            'username_field': username_field,
                            'password_field': password_field,
                            'other_fields': other_fields
                        })
            
            # Sayfa içinde login bağlantıları ara ve takip et
            self._follow_login_links(soup)
            
        except requests.exceptions.RequestException:
            pass
            
    def _follow_login_links(self, soup):
        """Login sayfalarını bulmak için bağlantıları takip eder"""
        
        login_links = []
        
        # Login bağlantılarını ara
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            link_text = link.text.lower()
            
            # Login ile ilgili bir bağlantı mı?
            is_login_link = False
            for keyword in self.login_keywords:
                if keyword in link_text or keyword in href.lower():
                    is_login_link = True
                    break
                    
            if is_login_link:
                login_links.append(href)
                
        # Bulunan bağlantıları takip et
        for href in login_links:
            # Tam URL oluştur
            if not href.startswith(('http://', 'https://')):
                parsed_url = urllib.parse.urlparse(self.target_url)
                base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                href = urllib.parse.urljoin(base_url, href)
                
            # Bu sayfayı ziyaret et
            try:
                login_page_response = requests.get(href, timeout=10, verify=False)
                login_page_soup = BeautifulSoup(login_page_response.text, 'html.parser')
                
                # Login formlarını ara
                forms = login_page_soup.find_all('form')
                
                for form in forms:
                    if self._is_login_form(form):
                        action = form.get('action', '')
                        method = form.get('method', 'post').lower()
                        
                        # Form action URL'sini oluştur
                        if not action.startswith(('http://', 'https://')):
                            parsed_url = urllib.parse.urlparse(href)
                            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                            action = urllib.parse.urljoin(base_url, action)
                        
                        # Form alanlarını topla
                        username_field = None
                        password_field = None
                        other_fields = []
                        
                        for input_tag in form.find_all('input'):
                            input_type = input_tag.get('type', '')
                            input_name = input_tag.get('name')
                            
                            if input_name:
                                input_value = input_tag.get('value', '')
                                
                                if (input_type == 'text' or input_type == 'email') and username_field is None:
                                    username_field = input_name
                                elif input_type == 'password':
                                    password_field = input_name
                                elif input_type != 'submit' and input_type != 'button':
                                    other_fields.append({
                                        'name': input_name,
                                        'value': input_value
                                    })
                        
                        # Bu form zaten eklendi mi?
                        form_exists = False
                        for existing_form in self.login_forms:
                            if existing_form['url'] == action:
                                form_exists = True
                                break
                                
                        # En az bir username ve password alanı varsa ve form daha önce eklenmemişse
                        if username_field and password_field and not form_exists:
                            self.login_forms.append({
                                'url': action,
                                'method': method,
                                'username_field': username_field,
                                'password_field': password_field,
                                'other_fields': other_fields
                            })
                                
            except requests.exceptions.RequestException:
                continue
                
    def _is_login_form(self, form):
        """Bir formun login formu olup olmadığını kontrol eder"""
        
        # Form içeriğini kontrol et
        form_html = str(form).lower()
        
        # Password input kontrolü
        password_input = form.find('input', {'type': 'password'})
        if not password_input:
            return False
            
        # Login anahtar kelimeleri var mı?
        has_login_keyword = False
        for keyword in self.login_keywords:
            if keyword in form_html:
                has_login_keyword = True
                break
                
        return has_login_keyword
        
    def _check_captcha(self):
        """Login formlarında CAPTCHA kontrolü yapar"""
        captcha_forms = []
        
        for form_data in self.login_forms:
            try:
                form_url = form_data['url']
                
                # Sayfayı kontrol et
                response = requests.get(form_url, timeout=10, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # CAPTCHA göstergeleri
                captcha_indicators = [
                    # Google reCAPTCHA
                    'grecaptcha', 'g-recaptcha', 'recaptcha',
                    # hCaptcha
                    'hcaptcha', 'h-captcha',
                    # Genel CAPTCHA göstergeleri
                    'captcha', 'security code', 'güvenlik kodu', 'doğrulama kodu'
                ]
                
                has_captcha = False
                
                # HTML içinde CAPTCHA göstergelerini ara
                html_lower = response.text.lower()
                for indicator in captcha_indicators:
                    if indicator in html_lower:
                        has_captcha = True
                        break
                        
                # Görüntü elementleri içinde CAPTCHA ara
                if not has_captcha:
                    img_tags = soup.find_all('img')
                    for img in img_tags:
                        img_src = img.get('src', '')
                        img_alt = img.get('alt', '')
                        
                        if 'captcha' in img_src.lower() or 'captcha' in img_alt.lower():
                            has_captcha = True
                            break
                            
                # CAPTCHA içeren formlar listesine ekle
                if has_captcha:
                    captcha_forms.append({
                        'url': form_url
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
        return captcha_forms
        
    def _check_rate_limiting(self):
        """Login formlarında istek sınırlaması (rate limiting) kontrolü yapar"""
        rate_limited_forms = []
        
        for form_data in self.login_forms:
            form_url = form_data['url']
            form_method = form_data['method']
            username_field = form_data['username_field']
            password_field = form_data['password_field']
            other_fields = form_data['other_fields']
            
            # Başarısız login denemesi yap
            try:
                # Form verilerini hazırla
                form_data = {}
                for field in other_fields:
                    form_data[field['name']] = field['value']
                    
                form_data[username_field] = 'test_user_' + str(int(time.time()))
                form_data[password_field] = 'wrong_password_' + str(int(time.time()))
                
                # Art arda 5 başarısız deneme yap
                has_rate_limiting = False
                
                for i in range(5):
                    if form_method == 'post':
                        response = requests.post(form_url, data=form_data, timeout=10, verify=False, allow_redirects=True)
                    else:
                        response = requests.get(form_url, params=form_data, timeout=10, verify=False, allow_redirects=True)
                    
                    # Yanıtı kontrol et
                    if i > 2:  # 3. denemeden sonra
                        # Rate limiting göstergeleri
                        rate_limit_indicators = [
                            'too many', 'too many attempts', 'çok fazla deneme',
                            'try again later', 'daha sonra tekrar deneyin',
                            'rate limit', 'limit exceeded', 'limit aşıldı',
                            'account locked', 'hesap kilitlendi',
                            'locked out', 'wait', 'bekleyin'
                        ]
                        
                        # HTML içinde rate limiting göstergelerini ara
                        html_lower = response.text.lower()
                        for indicator in rate_limit_indicators:
                            if indicator in html_lower:
                                has_rate_limiting = True
                                break
                                
                        # Yanıt koduna göre kontrol (429 Too Many Requests, 403 Forbidden)
                        if response.status_code in [429, 403]:
                            has_rate_limiting = True
                            break
                            
                    # İstekler arasında kısa beklemeler ekle
                    time.sleep(1)
                
                # Rate limiting varsa listeye ekle
                if has_rate_limiting:
                    rate_limited_forms.append({
                        'url': form_url
                    })
                    
            except requests.exceptions.RequestException:
                continue
                
        return rate_limited_forms 