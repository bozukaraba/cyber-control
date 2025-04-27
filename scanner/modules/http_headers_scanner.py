import requests
import json

class HTTPHeadersScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'HSTS başlığı, tarayıcıyı sadece HTTPS kullanmaya zorlar',
                'recommended': 'max-age=31536000; includeSubDomains',
                'risk_level': 'Yüksek'
            },
            'X-Frame-Options': {
                'description': 'Clickjacking saldırılarını önler',
                'recommended': 'SAMEORIGIN',
                'risk_level': 'Orta'
            },
            'X-Content-Type-Options': {
                'description': 'MIME-sniffing saldırılarını önler',
                'recommended': 'nosniff',
                'risk_level': 'Orta'
            },
            'X-XSS-Protection': {
                'description': 'XSS saldırılarına karşı tarayıcı koruması sağlar',
                'recommended': '1; mode=block',
                'risk_level': 'Orta'
            },
            'Content-Security-Policy': {
                'description': 'Kaynak yükleme politikalarını kontrol eder',
                'recommended': "default-src 'self'",
                'risk_level': 'Yüksek'
            },
            'Referrer-Policy': {
                'description': 'HTTP referrer bilgisinin gönderimini kontrol eder',
                'recommended': 'strict-origin-when-cross-origin',
                'risk_level': 'Düşük'
            },
            'Permissions-Policy': {
                'description': 'Tarayıcı özelliklerinin kullanımını kontrol eder',
                'recommended': 'geolocation=(), microphone=(), camera=()',
                'risk_level': 'Orta'
            },
            'Access-Control-Allow-Origin': {
                'description': 'CORS politikasını kontrol eder',
                'recommended': '*',
                'risk_level': 'Orta'
            },
            'X-Permitted-Cross-Domain-Policies': {
                'description': 'Cross-domain politikalarını kontrol eder',
                'recommended': 'none',
                'risk_level': 'Düşük'
            }
        }
        
    def scan(self):
        """HTTP güvenlik başlıklarını test eder"""
        result = {
            "title": "HTTP Güvenlik Başlıkları Testi",
            "findings": []
        }
        
        try:
            # HTTPS ve HTTP istekleri yap
            https_response = requests.get(f"https://{self.target_url.split('://')[-1]}", 
                                       verify=False, allow_redirects=True)
            headers = https_response.headers
            
            # Her güvenlik başlığını kontrol et
            for header, config in self.security_headers.items():
                if header not in headers:
                    result["findings"].append({
                        "name": f"Eksik Güvenlik Başlığı: {header}",
                        "description": config['description'],
                        "risk_level": config['risk_level'],
                        "impact": f"Bu başlığın olmaması güvenlik risklerine yol açabilir",
                        "recommendation": f"'{header}: {config['recommended']}' başlığını ekleyin"
                    })
                else:
                    # Başlık var ama değeri uygun değil mi?
                    current_value = headers[header]
                    if not self._is_header_value_secure(header, current_value):
                        result["findings"].append({
                            "name": f"Zayıf Güvenlik Başlığı: {header}",
                            "description": f"{config['description']}\nMevcut değer: {current_value}",
                            "risk_level": config['risk_level'],
                            "impact": "Başlık değeri yeterince güvenli değil",
                            "recommendation": f"Başlık değerini '{config['recommended']}' olarak güncelleyin"
                        })
            
            # Server ve X-Powered-By başlıklarını kontrol et
            info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']
            for header in info_headers:
                if header in headers:
                    result["findings"].append({
                        "name": f"Bilgi İfşa Başlığı: {header}",
                        "description": f"'{header}: {headers[header]}' başlığı sistem bilgisi sızdırıyor",
                        "risk_level": "Düşük",
                        "impact": "Saldırganlar sistem/teknoloji bilgilerini öğrenebilir",
                        "recommendation": f"'{header}' başlığını kaldırın veya değerini gizleyin"
                    })
            
            # HTTPS yönlendirmesi kontrol et
            try:
                http_response = requests.get(f"http://{self.target_url.split('://')[-1]}", 
                                          verify=False, allow_redirects=False)
                if http_response.status_code not in [301, 302] or \
                   not http_response.headers.get('Location', '').startswith('https://'):
                    result["findings"].append({
                        "name": "HTTPS Yönlendirmesi Eksik",
                        "description": "HTTP'den HTTPS'e otomatik yönlendirme yapılmıyor",
                        "risk_level": "Yüksek",
                        "impact": "Kullanıcılar güvensiz HTTP bağlantısı kullanabilir",
                        "recommendation": "Tüm HTTP trafiğini HTTPS'e yönlendirin"
                    })
            except:
                pass
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "HTTP Başlıkları Güvenli",
                    "description": "Tüm önemli güvenlik başlıkları mevcut ve uygun değerlere sahip",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
            
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"HTTP başlıkları taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "HTTP başlık güvenliği belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result
        
    def _is_header_value_secure(self, header, value):
        """Başlık değerinin güvenli olup olmadığını kontrol eder"""
        if header == 'Strict-Transport-Security':
            return 'max-age=' in value.lower() and int(value.split('max-age=')[1].split(';')[0]) >= 31536000
        elif header == 'X-Frame-Options':
            return value.upper() in ['DENY', 'SAMEORIGIN']
        elif header == 'X-Content-Type-Options':
            return value.lower() == 'nosniff'
        elif header == 'X-XSS-Protection':
            return value in ['1', '1; mode=block']
        elif header == 'Content-Security-Policy':
            return "default-src" in value or "script-src" in value
        elif header == 'Referrer-Policy':
            return value.lower() in ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
        elif header == 'Permissions-Policy':
            return any(feature in value for feature in ['geolocation', 'microphone', 'camera'])
        elif header == 'Access-Control-Allow-Origin':
            return value == '*' or value.startswith('http')
        elif header == 'X-Permitted-Cross-Domain-Policies':
            return value.lower() in ['none', 'master-only']
        return True 