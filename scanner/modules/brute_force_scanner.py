import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time
import re

class BruteForceScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.common_usernames = [
            'admin',
            'administrator',
            'root',
            'user',
            'test',
            'guest',
            'demo',
            'manager',
            'webmaster',
            'support'
        ]
        self.common_passwords = [
            'admin',
            'password',
            '123456',
            'admin123',
            'pass123',
            'password123',
            'qwerty',
            '12345678',
            '111111',
            'test123'
        ]
        
    def find_login_forms(self):
        """Login formlarını bulur"""
        forms = []
        try:
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Form elementlerini bul
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if not action:
                    action = self.target_url
                else:
                    action = urljoin(self.target_url, action)
                    
                method = form.get('method', 'post').lower()
                username_field = None
                password_field = None
                
                # Input alanlarını kontrol et
                for input_tag in form.find_all('input'):
                    input_type = input_tag.get('type', '').lower()
                    input_name = input_tag.get('name', '')
                    input_id = input_tag.get('id', '')
                    
                    # Kullanıcı adı alanını bul
                    if input_type == 'text' and any(keyword in input_name.lower() or keyword in input_id.lower() 
                                                  for keyword in ['user', 'email', 'login', 'name']):
                        username_field = input_name
                        
                    # Şifre alanını bul
                    elif input_type == 'password':
                        password_field = input_name
                
                if username_field and password_field:
                    forms.append({
                        'url': action,
                        'method': method,
                        'username_field': username_field,
                        'password_field': password_field
                    })
                    
            return forms
            
        except Exception as e:
            return []
            
    def test_credentials(self, form, username, password):
        """Kullanıcı adı ve şifre kombinasyonunu test eder"""
        try:
            data = {
                form['username_field']: username,
                form['password_field']: password
            }
            
            # İsteği gönder
            if form['method'] == 'post':
                response = requests.post(form['url'], data=data, verify=False, allow_redirects=True)
            else:
                response = requests.get(form['url'], params=data, verify=False, allow_redirects=True)
            
            # Başarılı giriş belirtilerini kontrol et
            content = response.text.lower()
            
            # Başarısız giriş belirtileri
            failure_indicators = [
                'invalid',
                'incorrect',
                'failed',
                'error',
                'wrong',
                'try again',
                'geçersiz',
                'hatalı',
                'başarısız',
                'yanlış'
            ]
            
            # Başarılı giriş belirtileri
            success_indicators = [
                'welcome',
                'dashboard',
                'profile',
                'logout',
                'account',
                'hoşgeldin',
                'panel',
                'profil',
                'çıkış',
                'hesap'
            ]
            
            # Başarısız giriş kontrolü
            if any(indicator in content for indicator in failure_indicators):
                return False
                
            # Başarılı giriş kontrolü
            if any(indicator in content for indicator in success_indicators):
                return True
                
            # URL değişikliği kontrolü
            if response.url != form['url']:
                return True
                
            return False
            
        except Exception as e:
            return False
            
    def check_rate_limiting(self, form):
        """Rate limiting kontrolü yapar"""
        try:
            # Hızlı ardışık istekler gönder
            for i in range(5):
                data = {
                    form['username_field']: f'test{i}',
                    form['password_field']: f'test{i}'
                }
                
                if form['method'] == 'post':
                    response = requests.post(form['url'], data=data, verify=False)
                else:
                    response = requests.get(form['url'], params=data, verify=False)
                    
                # Rate limit başlıklarını kontrol et
                rate_limit_headers = [
                    'x-ratelimit-limit',
                    'x-ratelimit-remaining',
                    'retry-after',
                    'x-rate-limit-limit',
                    'x-rate-limit-remaining'
                ]
                
                if any(header in response.headers.keys() for header in rate_limit_headers):
                    return True
                    
                # HTTP 429 (Too Many Requests) kontrolü
                if response.status_code == 429:
                    return True
                    
                time.sleep(0.1)
                
            return False
            
        except Exception as e:
            return False
            
    def check_captcha(self, form_html):
        """CAPTCHA kontrolü yapar"""
        captcha_indicators = [
            'captcha',
            'recaptcha',
            'g-recaptcha',
            'h-captcha',
            'doğrulama kodu',
            'güvenlik kodu'
        ]
        
        return any(indicator in form_html.lower() for indicator in captcha_indicators)
        
    def scan(self):
        """Brute force saldırı testi yapar"""
        result = {
            "title": "Brute Force Saldırı Testi",
            "findings": []
        }
        
        try:
            # Login formlarını bul
            forms = self.find_login_forms()
            
            if not forms:
                result["findings"].append({
                    "name": "Login Formu Bulunamadı",
                    "description": "Test için uygun login formu bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Test yapılamadı",
                    "recommendation": "Login sayfasını kontrol edin"
                })
                return result
            
            # Her form için test yap
            for form in forms:
                form_html = requests.get(form['url'], verify=False).text
                
                # CAPTCHA kontrolü
                has_captcha = self.check_captcha(form_html)
                if has_captcha:
                    result["findings"].append({
                        "name": "CAPTCHA Koruması Tespit Edildi",
                        "description": f"URL: {form['url']}\nCAPTCHA koruması aktif",
                        "risk_level": "Düşük",
                        "impact": "Brute force saldırıları CAPTCHA ile engellenebilir",
                        "recommendation": "CAPTCHA korumasını aktif tutun"
                    })
                    continue
                
                # Rate limiting kontrolü
                has_rate_limit = self.check_rate_limiting(form)
                if has_rate_limit:
                    result["findings"].append({
                        "name": "Rate Limiting Tespit Edildi",
                        "description": f"URL: {form['url']}\nRate limiting koruması aktif",
                        "risk_level": "Düşük",
                        "impact": "Brute force saldırıları rate limiting ile yavaşlatılabilir",
                        "recommendation": "Rate limiting korumasını aktif tutun"
                    })
                    continue
                
                # Brute force testi
                successful_logins = []
                max_attempts = 3  # Test için sınırlı sayıda deneme
                
                for username in self.common_usernames[:max_attempts]:
                    for password in self.common_passwords[:max_attempts]:
                        if self.test_credentials(form, username, password):
                            successful_logins.append({
                                'username': username,
                                'password': password
                            })
                            
                        time.sleep(0.5)  # Rate limiting'i tetiklememek için bekle
                
                # Sonuçları raporla
                if successful_logins:
                    result["findings"].append({
                        "name": "Zayıf Kimlik Bilgileri Tespit Edildi",
                        "description": f"URL: {form['url']}\n" + \
                                     "Başarılı Girişler:\n" + \
                                     "\n".join(f"- Kullanıcı: {login['username']}, Şifre: {login['password']}" 
                                             for login in successful_logins),
                        "risk_level": "Kritik",
                        "impact": "Saldırganlar yaygın kullanıcı adı ve şifrelerle giriş yapabilir",
                        "recommendation": "\n".join([
                            "1. Güçlü parola politikası uygulayın",
                            "2. CAPTCHA koruması ekleyin",
                            "3. Rate limiting uygulayın",
                            "4. Başarısız giriş denemelerini sınırlayın",
                            "5. İki faktörlü kimlik doğrulama (2FA) ekleyin",
                            "6. Başarısız girişleri loglayın ve alarm kurun",
                            "7. IP tabanlı engelleme uygulayın"
                        ])
                    })
                else:
                    result["findings"].append({
                        "name": "Brute Force Testi Başarısız",
                        "description": f"URL: {form['url']}\nTest edilen yaygın kimlik bilgileriyle giriş yapılamadı",
                        "risk_level": "Bilgi",
                        "impact": "Yok",
                        "recommendation": "Güvenlik önlemlerini sürdürün"
                    })
                    
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Brute force taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Brute force zafiyetleri belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 