import requests
from urllib.parse import urlparse
import json

class HTTPSecurityScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        
    def scan(self):
        """HTTP güvenlik başlıklarını ve yapılandırmasını kontrol eder"""
        result = {
            "title": "HTTP Güvenlik Testi",
            "findings": []
        }
        
        try:
            response = requests.get(self.target_url, verify=False, allow_redirects=True)
            headers = response.headers
            
            # HSTS Kontrolü
            if 'Strict-Transport-Security' not in headers:
                result["findings"].append({
                    "name": "HSTS Eksik",
                    "description": "HTTP Strict Transport Security (HSTS) başlığı bulunamadı",
                    "risk_level": "Yüksek",
                    "impact": "SSL stripping saldırılarına karşı savunmasız",
                    "recommendation": "Strict-Transport-Security başlığını ekleyin"
                })
            
            # X-Frame-Options Kontrolü
            if 'X-Frame-Options' not in headers:
                result["findings"].append({
                    "name": "X-Frame-Options Eksik",
                    "description": "Clickjacking koruması eksik",
                    "risk_level": "Orta",
                    "impact": "Site iframe içinde açılarak kullanıcı kandırılabilir",
                    "recommendation": "X-Frame-Options: DENY veya SAMEORIGIN başlığını ekleyin"
                })
            
            # Content-Security-Policy Kontrolü
            if 'Content-Security-Policy' not in headers:
                result["findings"].append({
                    "name": "CSP Eksik",
                    "description": "Content Security Policy (CSP) başlığı bulunamadı",
                    "risk_level": "Yüksek",
                    "impact": "XSS ve diğer içerik enjeksiyon saldırılarına karşı savunmasız",
                    "recommendation": "Uygun CSP politikası tanımlayın"
                })
            
            # X-Content-Type-Options Kontrolü
            if 'X-Content-Type-Options' not in headers:
                result["findings"].append({
                    "name": "X-Content-Type-Options Eksik",
                    "description": "MIME-sniffing koruması eksik",
                    "risk_level": "Düşük",
                    "impact": "Tarayıcılar dosya tiplerini yanlış yorumlayabilir",
                    "recommendation": "X-Content-Type-Options: nosniff başlığını ekleyin"
                })
            
            # X-XSS-Protection Kontrolü
            if 'X-XSS-Protection' not in headers:
                result["findings"].append({
                    "name": "X-XSS-Protection Eksik",
                    "description": "Tarayıcı XSS koruması devre dışı",
                    "risk_level": "Orta",
                    "impact": "XSS saldırılarına karşı ek koruma katmanı eksik",
                    "recommendation": "X-XSS-Protection: 1; mode=block başlığını ekleyin"
                })
            
            # Referrer-Policy Kontrolü
            if 'Referrer-Policy' not in headers:
                result["findings"].append({
                    "name": "Referrer-Policy Eksik",
                    "description": "Referrer bilgisi kontrolü eksik",
                    "risk_level": "Düşük",
                    "impact": "Hassas URL'ler diğer sitelere sızabilir",
                    "recommendation": "Uygun Referrer-Policy başlığını ekleyin"
                })
            
            # Server Header Kontrolü
            if 'Server' in headers:
                result["findings"].append({
                    "name": "Server Bilgisi Açık",
                    "description": f"Sunucu yazılım bilgisi açıkta: {headers['Server']}",
                    "risk_level": "Düşük",
                    "impact": "Saldırganlar sunucu yazılımına özel saldırılar planlayabilir",
                    "recommendation": "Server başlığını kaldırın veya gizleyin"
                })
            
            # X-Powered-By Kontrolü
            if 'X-Powered-By' in headers:
                result["findings"].append({
                    "name": "X-Powered-By Bilgisi Açık",
                    "description": f"Uygulama altyapı bilgisi açıkta: {headers['X-Powered-By']}",
                    "risk_level": "Düşük",
                    "impact": "Saldırganlar uygulamaya özel saldırılar planlayabilir",
                    "recommendation": "X-Powered-By başlığını kaldırın"
                })
            
            # Cookie Güvenlik Kontrolü
            if 'Set-Cookie' in headers:
                cookies = response.cookies
                for cookie in cookies:
                    if not cookie.secure:
                        result["findings"].append({
                            "name": "Güvensiz Cookie",
                            "description": f"'{cookie.name}' çerezi Secure bayrağı olmadan ayarlanıyor",
                            "risk_level": "Orta",
                            "impact": "Çerez HTTP üzerinden gönderilebilir",
                            "recommendation": "Tüm çerezler için Secure bayrağını etkinleştirin"
                        })
                    if not cookie.has_nonstandard_attr('HttpOnly'):
                        result["findings"].append({
                            "name": "HttpOnly Eksik Cookie",
                            "description": f"'{cookie.name}' çerezi HttpOnly bayrağı olmadan ayarlanıyor",
                            "risk_level": "Orta",
                            "impact": "JavaScript ile çerez çalınabilir",
                            "recommendation": "Tüm çerezler için HttpOnly bayrağını etkinleştirin"
                        })
            
            # HTTP Metodları Kontrolü
            allowed_methods = []
            for method in ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'CONNECT']:
                try:
                    r = requests.request(method, self.target_url, timeout=5)
                    if r.status_code != 405:  # Method Not Allowed
                        allowed_methods.append(method)
                except:
                    continue
            
            if allowed_methods:
                result["findings"].append({
                    "name": "Tehlikeli HTTP Metodları",
                    "description": f"Tehlikeli HTTP metodları aktif: {', '.join(allowed_methods)}",
                    "risk_level": "Yüksek",
                    "impact": "Sunucu üzerinde yetkisiz değişiklikler yapılabilir",
                    "recommendation": "Gereksiz HTTP metodlarını devre dışı bırakın"
                })
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "HTTP Güvenliği Yeterli",
                    "description": "HTTP güvenlik başlıkları ve yapılandırması uygun durumda",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except requests.exceptions.SSLError:
            result["findings"].append({
                "name": "SSL Hatası",
                "description": "SSL sertifikası doğrulanamadı",
                "risk_level": "Kritik",
                "impact": "Güvenli bağlantı kurulamıyor",
                "recommendation": "SSL sertifika yapılandırmasını kontrol edin"
            })
        except requests.exceptions.RequestException as e:
            result["findings"].append({
                "name": "Bağlantı Hatası",
                "description": f"HTTP istekleri başarısız: {str(e)}",
                "risk_level": "Hata",
                "impact": "HTTP güvenlik durumu belirlenemedi",
                "recommendation": "Sunucu erişilebilirliğini kontrol edin"
            })
            
        return result 