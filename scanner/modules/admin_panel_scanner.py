import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import time

class AdminPanelScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.admin_paths = [
            '/admin',
            '/administrator',
            '/admin.php',
            '/admin.html',
            '/admin.asp',
            '/admin.aspx',
            '/admin.jsp',
            '/admin/login',
            '/admin/login.php',
            '/admin/login.html',
            '/admin/login.asp',
            '/admin/login.aspx',
            '/admin/login.jsp',
            '/admin/index.php',
            '/admin/home',
            '/admin/controlpanel',
            '/admin/cp',
            '/administrator/login',
            '/administrator/admin',
            '/administrator/account',
            '/administrator.php',
            '/administrator.html',
            '/administrator.asp',
            '/administrator.aspx',
            '/administrator.jsp',
            '/admincp',
            '/admincp/login',
            '/admincp/index',
            '/adminpanel',
            '/adminpanel/login',
            '/adminpanel/index',
            '/webadmin',
            '/webadmin/login',
            '/webadmin/admin',
            '/webadmin/index',
            '/wp-admin',
            '/wp-login',
            '/wp-login.php',
            '/panel',
            '/panel/login',
            '/cpanel',
            '/cpanel/login',
            '/dashboard',
            '/dashboard/login',
            '/moderator',
            '/moderator/login',
            '/moderator/admin',
            '/controlpanel',
            '/controlpanel/login',
            '/fileadmin',
            '/fileadmin/login',
            '/sysadmin',
            '/sysadmin/login',
            '/phpmyadmin',
            '/myadmin',
            '/sql',
            '/mysql',
            '/pma',
            '/dbadmin',
            '/db',
            '/websql',
            '/webdb',
            '/mysqladmin',
            '/mysql-admin',
            '/phpadmin',
            '/phpMyAdmin',
            '/pgadmin',
            '/postgres',
            '/postgresql',
            '/adminer',
            '/logon',
            '/authenticate',
            '/authentication',
            '/auth',
            '/authuser',
            '/authadmin',
            '/administration',
            '/cms',
            '/cms/login',
            '/cms/admin',
            '/system',
            '/system/admin',
            '/management',
            '/manage',
            '/management/admin',
            '/members',
            '/members/login',
            '/user/admin',
            '/utility',
            '/staff',
            '/staff/login',
            '/customer/admin',
            '/customer/login',
            '/acct/login',
            '/users/admin',
            '/users/login',
            '/manager',
            '/manager/login',
            '/adm',
            '/admin1',
            '/admin2',
            '/admin3',
            '/admin4',
            '/users/administrator',
            '/access',
            '/access/login',
            '/administer',
            '/moderator',
            '/moderator/login',
            '/moderator/admin',
            '/webmaster',
            '/webmaster/login',
            '/configuration',
            '/configure',
            '/supervise',
            '/supervise/Login',
            '/superviseur',
            '/superviser',
            '/chief',
            '/master',
            '/master/login',
            '/master/admin',
            '/root',
            '/root/login',
            '/root/admin'
        ]
        self.login_keywords = [
            'login',
            'sign in',
            'signin',
            'log in',
            'username',
            'password',
            'user name',
            'admin',
            'administrator',
            'auth',
            'authentication',
            'giriş',
            'oturum aç',
            'kullanıcı adı',
            'şifre',
            'yönetici',
            'yönetim'
        ]
        
    def check_url(self, url):
        """URL'i kontrol eder"""
        try:
            response = requests.get(url, verify=False, allow_redirects=True)
            
            # Yanıt kodunu kontrol et
            if response.status_code in [200, 301, 302, 401, 403]:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Title'da admin kelimesi var mı?
                title = soup.title.string.lower() if soup.title else ''
                if any(keyword in title for keyword in self.login_keywords):
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'title': title,
                        'type': 'title'
                    }
                
                # Form var mı?
                forms = soup.find_all('form')
                for form in forms:
                    form_html = str(form).lower()
                    if any(keyword in form_html for keyword in self.login_keywords):
                        return {
                            'url': url,
                            'status_code': response.status_code,
                            'title': title,
                            'type': 'form'
                        }
                
                # HTTP Basic Auth var mı?
                if response.status_code == 401 and 'www-authenticate' in response.headers:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'title': title,
                        'type': 'basic_auth'
                    }
                
                # Erişim engeli var mı?
                if response.status_code == 403:
                    return {
                        'url': url,
                        'status_code': response.status_code,
                        'title': title,
                        'type': 'forbidden'
                    }
                    
            return None
            
        except Exception as e:
            return None
            
    def scan(self):
        """Admin paneli tespit etmeye çalışır"""
        result = {
            "title": "Admin Panel Testi",
            "findings": []
        }
        
        try:
            found_panels = []
            
            # Her muhtemel yolu dene
            for path in self.admin_paths:
                url = urljoin(self.target_url, path)
                finding = self.check_url(url)
                
                if finding:
                    found_panels.append(finding)
                
                # Rate limiting
                time.sleep(0.1)
            
            # Bulunan panelleri raporla
            if found_panels:
                for panel in found_panels:
                    status_text = {
                        200: 'Erişilebilir',
                        301: 'Kalıcı Yönlendirme',
                        302: 'Geçici Yönlendirme',
                        401: 'Kimlik Doğrulama Gerekli',
                        403: 'Erişim Engellendi'
                    }.get(panel['status_code'], str(panel['status_code']))
                    
                    panel_type = {
                        'title': 'Başlıkta admin kelimesi tespit edildi',
                        'form': 'Login formu tespit edildi',
                        'basic_auth': 'HTTP Basic Auth koruması var',
                        'forbidden': 'Erişim engellendi'
                    }.get(panel['type'], 'Bilinmeyen tip')
                    
                    risk_level = {
                        200: 'Kritik',
                        301: 'Yüksek',
                        302: 'Yüksek',
                        401: 'Orta',
                        403: 'Düşük'
                    }.get(panel['status_code'], 'Orta')
                    
                    result["findings"].append({
                        "name": "Admin Panel Tespit Edildi",
                        "description": f"URL: {panel['url']}\n" + \
                                     f"Durum: {status_text}\n" + \
                                     f"Başlık: {panel['title']}\n" + \
                                     f"Tip: {panel_type}",
                        "risk_level": risk_level,
                        "impact": "Saldırganlar admin paneline erişmeye çalışabilir",
                        "recommendation": "\n".join([
                            "1. Admin panelinin URL'sini tahmin edilemez yapın",
                            "2. Güçlü parola politikası uygulayın",
                            "3. İki faktörlü kimlik doğrulama (2FA) ekleyin",
                            "4. IP tabanlı erişim kısıtlaması uygulayın",
                            "5. Brute force koruması ekleyin",
                            "6. Admin panelini farklı bir domaine taşıyın",
                            "7. VPN veya özel ağ üzerinden erişim zorunluluğu getirin",
                            "8. Web Application Firewall (WAF) kullanın",
                            "9. Başarısız giriş denemelerini loglamayı aktifleştirin",
                            "10. Düzenli güvenlik denetimleri yapın"
                        ])
                    })
            else:
                result["findings"].append({
                    "name": "Admin Panel Tespit Edilmedi",
                    "description": "Bilinen admin panel yollarında panel tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Admin panel taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Admin panelleri belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 