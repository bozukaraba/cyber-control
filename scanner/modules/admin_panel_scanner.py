import requests
from urllib.parse import urljoin
import asyncio
import aiohttp

class AdminPanelScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.paths = [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/admin.php',
            '/admin.html',
            '/admin/index.php',
            '/admin/login.php',
            '/admin/admin.php',
            '/admin/dashboard',
            '/admin/home',
            '/admin/cp',
            '/admin/controlpanel',
            '/admin/control',
            '/admincp',
            '/adminpanel',
            '/webadmin',
            '/websiteadmin',
            '/sysadmin',
            '/administrator/login.php',
            '/administrator/admin.php',
            '/administrator/account.php',
            '/administrator.php',
            '/moderator',
            '/moderator.php',
            '/moderator/login.php',
            '/moderator/admin.php',
            '/user',
            '/cp',
            '/cpanel',
            '/dashboard',
            '/manage',
            '/management',
            '/control',
            '/member',
            '/members',
            '/memberadmin',
            '/panel',
            '/paneldecontrol',
            '/netadmin',
            '/yonetim',
            '/yonetici',
            '/auth/login',
            '/auth/signin',
            '/login',
            '/login.php',
            '/login.html',
            '/signin',
            '/signin.php',
            '/signin.html'
        ]
        
    async def _check_path(self, session, path):
        """Belirli bir yolu kontrol eder"""
        url = urljoin(self.target_url, path)
        try:
            async with session.get(url, allow_redirects=True, verify_ssl=False) as response:
                if response.status in [200, 301, 302, 403]:
                    content = await response.text()
                    
                    # Login formunu kontrol et
                    login_indicators = [
                        'login',
                        'signin',
                        'sign in',
                        'giriş',
                        'username',
                        'password',
                        'kullanıcı adı',
                        'şifre',
                        'parola'
                    ]
                    
                    # Başlık ve meta etiketlerini kontrol et
                    admin_indicators = [
                        'admin',
                        'yönetici',
                        'yönetim',
                        'dashboard',
                        'panel',
                        'control'
                    ]
                    
                    content_lower = content.lower()
                    
                    # Login formu veya admin paneli göstergeleri varsa
                    if any(indicator in content_lower for indicator in login_indicators) or \
                       any(indicator in content_lower for indicator in admin_indicators):
                        return {
                            'path': path,
                            'url': url,
                            'status': response.status,
                            'type': 'Login Form' if any(indicator in content_lower for indicator in login_indicators) else 'Admin Panel'
                        }
            
            return None
        except:
            return None
    
    async def scan(self):
        """Admin paneli ve login sayfalarını tespit eder"""
        result = {
            "title": "Admin Panel Testi",
            "findings": []
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                tasks = []
                for path in self.paths:
                    tasks.append(self._check_path(session, path))
                
                findings = await asyncio.gather(*tasks)
                findings = [f for f in findings if f is not None]
                
                if findings:
                    # Her bulunan panel için detay ekle
                    for finding in findings:
                        result["findings"].append({
                            "name": f"{finding['type']} Tespit Edildi",
                            "description": f"URL: {finding['url']}\nHTTP Durum Kodu: {finding['status']}",
                            "risk_level": "Yüksek" if finding['status'] != 403 else "Orta",
                            "impact": "Yetkisiz erişim ve yönetici hesabı ele geçirme girişimleri mümkün",
                            "recommendation": "\n".join([
                                "1. Admin panelini özel bir URL'e taşıyın",
                                "2. Güçlü parola politikası uygulayın",
                                "3. İki faktörlü kimlik doğrulama ekleyin",
                                "4. IP tabanlı erişim kısıtlaması uygulayın",
                                "5. Brute force koruması ekleyin",
                                "6. Başarısız giriş denemelerini sınırlayın"
                            ])
                        })
                else:
                    result["findings"].append({
                        "name": "Admin Panel Bulunamadı",
                        "description": "Yaygın admin panel yollarında erişilebilir bir panel tespit edilmedi",
                        "risk_level": "Bilgi",
                        "impact": "Yok",
                        "recommendation": "Admin panelini özel ve tahmin edilemez bir URL'de tutmaya devam edin"
                    })
                    
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Admin panel taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Admin panel varlığı belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 