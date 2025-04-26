import requests
from urllib.parse import urlparse

class HTTPHeaderScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        
    def scan(self):
        """HTTP güvenlik başlıklarını kontrol eder"""
        result = {
            "title": "HTTP Güvenlik Başlıkları Testi",
            "findings": []
        }
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False, allow_redirects=True)
            headers = response.headers
            
            # HSTS başlığı kontrolü
            if 'Strict-Transport-Security' not in headers:
                result["findings"].append({
                    "name": "HSTS Eksikliği",
                    "description": "HTTP Strict Transport Security (HSTS) başlığı bulunamadı",
                    "risk_level": "Orta",
                    "impact": "MITM saldırılarına ve protokol indirgeme saldırılarına karşı zafiyet",
                    "recommendation": "Strict-Transport-Security başlığını aktifleştirin"
                })
            
            # X-Frame-Options başlığı kontrolü
            if 'X-Frame-Options' not in headers:
                result["findings"].append({
                    "name": "X-Frame-Options Eksikliği",
                    "description": "X-Frame-Options başlığı bulunamadı",
                    "risk_level": "Orta",
                    "impact": "Clickjacking saldırılarına karşı zafiyet",
                    "recommendation": "X-Frame-Options başlığını DENY veya SAMEORIGIN olarak ayarlayın"
                })
            
            # Content-Security-Policy başlığı kontrolü
            if 'Content-Security-Policy' not in headers:
                result["findings"].append({
                    "name": "Content-Security-Policy Eksikliği",
                    "description": "Content-Security-Policy başlığı bulunamadı",
                    "risk_level": "Orta",
                    "impact": "XSS ve veri enjeksiyon saldırılarına karşı zafiyet",
                    "recommendation": "İçerik Güvenlik Politikası başlığını tanımlayın"
                })
            
            # X-XSS-Protection başlığı kontrolü
            if 'X-XSS-Protection' not in headers:
                result["findings"].append({
                    "name": "X-XSS-Protection Eksikliği",
                    "description": "X-XSS-Protection başlığı bulunamadı",
                    "risk_level": "Düşük",
                    "impact": "XSS koruma mekanizması eksik",
                    "recommendation": "X-XSS-Protection başlığını '1; mode=block' olarak ayarlayın"
                })
            
            # X-Content-Type-Options başlığı kontrolü
            if 'X-Content-Type-Options' not in headers:
                result["findings"].append({
                    "name": "X-Content-Type-Options Eksikliği",
                    "description": "X-Content-Type-Options başlığı bulunamadı",
                    "risk_level": "Düşük",
                    "impact": "MIME sniffing saldırılarına karşı zafiyet",
                    "recommendation": "X-Content-Type-Options başlığını 'nosniff' olarak ayarlayın"
                })
            
            # Referrer-Policy başlığı kontrolü
            if 'Referrer-Policy' not in headers:
                result["findings"].append({
                    "name": "Referrer-Policy Eksikliği",
                    "description": "Referrer-Policy başlığı bulunamadı",
                    "risk_level": "Düşük",
                    "impact": "Referrer bilgisi ile veri sızıntısı riski",
                    "recommendation": "Referrer-Policy başlığını 'strict-origin-when-cross-origin' veya 'no-referrer' olarak ayarlayın"
                })
            
            # Mevcut başlık değerlerinin güvenli olup olmadığını kontrol et
            if 'X-Frame-Options' in headers:
                value = headers['X-Frame-Options'].upper()
                if value not in ['DENY', 'SAMEORIGIN']:
                    result["findings"].append({
                        "name": "Zayıf X-Frame-Options Değeri",
                        "description": f"X-Frame-Options başlığı zayıf değer içeriyor: {value}",
                        "risk_level": "Düşük",
                        "impact": "Clickjacking saldırılarına karşı zafiyet riski devam ediyor",
                        "recommendation": "X-Frame-Options başlığını DENY veya SAMEORIGIN olarak ayarlayın"
                    })
            
            if 'X-XSS-Protection' in headers:
                value = headers['X-XSS-Protection']
                if value != '1; mode=block':
                    result["findings"].append({
                        "name": "Zayıf X-XSS-Protection Değeri",
                        "description": f"X-XSS-Protection başlığı zayıf değer içeriyor: {value}",
                        "risk_level": "Düşük",
                        "impact": "XSS koruması tam olarak etkin değil",
                        "recommendation": "X-XSS-Protection başlığını '1; mode=block' olarak ayarlayın"
                    })
            
        except requests.exceptions.RequestException as e:
            result["findings"].append({
                "name": "HTTP İstek Hatası",
                "description": f"HTTP isteği sırasında hata oluştu: {str(e)}",
                "risk_level": "Orta",
                "impact": "HTTP başlık kontrolü tamamlanamadı",
                "recommendation": "Sunucu erişilebilirliğini kontrol edin"
            })
        
        if not result["findings"]:
            result["findings"].append({
                "name": "HTTP Güvenlik Başlıkları",
                "description": "Tüm gerekli güvenlik başlıkları mevcut",
                "risk_level": "Düşük",
                "impact": "Herhangi bir sorun tespit edilmedi",
                "recommendation": "Güvenlik başlıklarını düzenli olarak gözden geçirin"
            })
            
        return result 