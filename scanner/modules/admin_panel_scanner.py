import requests
import urllib.parse

class AdminPanelScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.admin_paths = [
            "admin/", "administrator/", "admin1/", "admin2/", "admin/login.php",
            "admin/admin.php", "admin/cp.php", "cp.php", "admincp/", "admincp.php",
            "admin/adminLogin.php", "adminLogin.php", "admin/login.html", "admin/index.php",
            "wp-login.php", "wp-admin/", "admin/login.html", "admin/admin-login.html",
            "admin-login.html", "login.html", "adm/", "login/", "login.php", "panel/",
            "control/", "control.php", "admincontrol.php", "adminpanel.php", "admin/account.php",
            "admin/admin_login.php", "admin_login.php", "panel-administracion/login.php",
            "adm.php", "adm/index.php", "moderator.php", "moderator/login.php", "moderator/admin.php",
            "account.php", "pages/admin/admin-login.php", "admin/admin-login.php", "admin-login.php",
            "administrator/account.php", "administrator.php", "customer/account.php", "customer.php",
            "moderator/", "webadmin/", "webadmin.php", "webadmin/index.php", "webadmin/login.php",
            "webadmin/admin.php", "admin/controlpanel.php", "admincp/", "admincp.html", "admincp/login.php",
            "admincp/index.php", "administrator/", "administrator/index.php", "administrator/login.php",
            "administrator/account.php", "administratorlogin.php", "administrator/index.html",
            "admin/", "admin/cp.php", "cp.php", "administrator/account.php", "administrator.php",
            "login.php", "modelsearch/login.php", "moderator.php", "moderator/login.php",
            "moderator/admin.php", "account.php", "controlpanel/", "controlpanel.php", "admincontrol.php",
            "adminpanel.php", "fileadmin/", "fileadmin.php", "sysadmin.php", "admin1.php", "admin1.html",
            "admin2.php", "admin2.html", "yonetim.php", "yonetim.html", "yonetici.php", "yonetici.html",
            "admin/index.html", "admin/login.html", "admin/admin.html", "admin/index.html",
            "admin_area/login.html", "panel-administracion/index.html", "panel-administracion/admin.html",
            "modelsearch/index.html", "modelsearch/admin.html", "admincontrol/login.html",
            "adm/index.html", "adm.html", "moderator/admin.html", "user.php", "account.html", "controlpanel.html",
            "admincontrol.html", "panel-administracion/login.html", "typo3/", "cpanel/", "phpmyadmin/"
        ]
        
    def scan(self):
        """Admin panel tespiti yapar"""
        result = {
            "title": "Admin Panel Tespiti",
            "findings": []
        }
        
        try:
            # Hedef URL'nin temel kısmını al
            parsed_url = urllib.parse.urlparse(self.target_url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
            
            found_panels = []
            
            # Admin paneli yollarını kontrol et
            for path in self.admin_paths:
                admin_url = urllib.parse.urljoin(base_url, path)
                
                try:
                    response = requests.get(admin_url, timeout=5, verify=False, allow_redirects=False)
                    
                    # HTTP 200 OK, 302 Found veya 401 Unauthorized kodları admin panel olabileceğini gösterir
                    if response.status_code in [200, 302, 401, 403]:
                        # Login sayfası mı kontrol et
                        if self._is_login_page(response):
                            found_panels.append({
                                "url": admin_url,
                                "status_code": response.status_code
                            })
                except requests.exceptions.RequestException:
                    continue
            
            # Bulunan admin panellerini raporla
            if found_panels:
                for panel in found_panels:
                    result["findings"].append({
                        "name": "Admin Panel Bulundu",
                        "description": f"Potansiyel bir admin paneli tespit edildi: {panel['url']} (Status: {panel['status_code']})",
                        "risk_level": "Yüksek",
                        "impact": "Yetkisiz erişim riski, admin panelleri brute-force saldırılarının hedefi olabilir",
                        "recommendation": "Admin panelini özel bir URL'ye taşıyın, güçlü şifre politikaları uygulayın ve erişimi IP bazlı kısıtlayın"
                    })
            else:
                result["findings"].append({
                    "name": "Admin Panel Tespiti",
                    "description": "Herhangi bir admin paneli tespit edilmedi",
                    "risk_level": "Düşük",
                    "impact": "Herhangi bir sorun tespit edilmedi",
                    "recommendation": "Admin panellerinizi standart olmayan yollarda tutmaya devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Admin Panel Tarama Hatası",
                "description": f"Admin panel taraması sırasında hata oluştu: {str(e)}",
                "risk_level": "Düşük",
                "impact": "Admin panel taraması tamamlanamadı",
                "recommendation": "Taramayı yeniden deneyin"
            })
            
        return result
    
    def _is_login_page(self, response):
        """Yanıtın bir login sayfası olup olmadığını kontrol eder"""
        # Login formları için basit bir kontrol
        login_keywords = [
            'login', 'sign in', 'signin', 'log in', 'username', 'password',
            'user name', 'kullanıcı adı', 'şifre', 'giriş', 'oturum aç'
        ]
        
        if response.text:
            content_lower = response.text.lower()
            
            # HTML içinde <form> etiketi var mı?
            if '<form' in content_lower:
                # Login anahtar kelimeleri var mı?
                for keyword in login_keywords:
                    if keyword in content_lower:
                        return True
            
            # Başlıkta login kelimesi var mı?
            if response.headers.get('Content-Type', '').startswith('text/html'):
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(response.text, 'html.parser')
                page_title = soup.title.string if soup.title else ""
                
                if page_title:
                    for keyword in login_keywords:
                        if keyword in page_title.lower():
                            return True
        
        return False 