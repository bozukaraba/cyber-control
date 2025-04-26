import ssl
import socket
import datetime
import OpenSSL.crypto as crypto
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from urllib.parse import urlparse

class SSLTLSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        parsed_url = urlparse(target_url)
        self.hostname = parsed_url.netloc
        self.port = 443 if parsed_url.scheme == "https" else 80
        
    def scan(self):
        """SSL/TLS güvenlik taraması gerçekleştirir"""
        result = {
            "title": "SSL/TLS Güvenlik Testi",
            "findings": []
        }
        
        # HTTPS kullanımı kontrolü
        if not self.target_url.startswith("https://"):
            result["findings"].append({
                "name": "HTTPS Kullanımı",
                "description": "Site HTTPS protokolü kullanmıyor",
                "risk_level": "Yüksek",
                "impact": "Veri transferi şifrelenmeden gerçekleşiyor, veri açıkta kalabilir",
                "recommendation": "HTTPS protokolünü aktifleştiriniz"
            })
            # HTTPS yoksa diğer SSL testlerini yapamayız
            return result
        
        try:
            # SSL bağlantısı kurma
            context = ssl.create_default_context()
            with socket.create_connection((self.hostname, self.port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                    # Sertifika bilgilerini al
                    cert = ssock.getpeercert()
                    
                    # Sertifika geçerlilik kontrolü
                    if cert:
                        not_after = datetime.datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                        not_before = datetime.datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                        now = datetime.datetime.now()
                        
                        # Sertifika süresi dolmuş mu?
                        if now > not_after:
                            result["findings"].append({
                                "name": "Sertifika Geçerlilik Süresi",
                                "description": "SSL sertifikasının süresi dolmuş",
                                "risk_level": "Kritik",
                                "impact": "Kullanıcılar güvenlik uyarısı alacak ve siteyi güvensiz olarak görecek",
                                "recommendation": "SSL sertifikasını yenileyin"
                            })
                        elif now < not_before:
                            result["findings"].append({
                                "name": "Sertifika Geçerlilik Süresi",
                                "description": "SSL sertifikası henüz geçerli değil",
                                "risk_level": "Kritik",
                                "impact": "Kullanıcılar güvenlik uyarısı alacak ve siteyi güvensiz olarak görecek",
                                "recommendation": "Sertifika yapılandırmasını kontrol edin"
                            })
                        
                        # Sertifika bitiş tarihine 30 gün veya daha az kaldı mı?
                        days_to_expire = (not_after - now).days
                        if days_to_expire <= 30:
                            result["findings"].append({
                                "name": "Sertifika Sona Erme Tarihi",
                                "description": f"SSL sertifikasının süresi {days_to_expire} gün içinde dolacak",
                                "risk_level": "Orta",
                                "impact": "Yakın zamanda kullanıcılar güvenlik uyarısı alabilir",
                                "recommendation": "SSL sertifikasını yenileyin"
                            })
                            
                    # Şifreleme protokolü kontrolü
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Zayıf şifreleme algılama
                        weak_ciphers = ["DES", "RC4", "MD5", "NULL", "EXPORT", "anon"]
                        for weak in weak_ciphers:
                            if weak in cipher_name:
                                result["findings"].append({
                                    "name": "Zayıf Şifreleme",
                                    "description": f"Zayıf şifreleme protokolü kullanılıyor: {cipher_name}",
                                    "risk_level": "Yüksek",
                                    "impact": "Şifreleme kırılabilir ve veriler açığa çıkabilir",
                                    "recommendation": "Sunucu yapılandırmasını güncelleyerek güçlü şifreleme protokollerini aktifleştirin"
                                })
                                
        except (socket.gaierror, socket.error, ssl.SSLError, ConnectionRefusedError) as e:
            result["findings"].append({
                "name": "SSL/TLS Bağlantı Hatası",
                "description": f"SSL bağlantısı kurulamadı: {str(e)}",
                "risk_level": "Yüksek",
                "impact": "SSL/TLS taraması tamamlanamadı",
                "recommendation": "Sunucu SSL/TLS yapılandırmasını kontrol edin"
            })
            
        if not result["findings"]:
            result["findings"].append({
                "name": "SSL/TLS Güvenlik",
                "description": "SSL/TLS yapılandırması güvenli",
                "risk_level": "Düşük",
                "impact": "Herhangi bir sorun tespit edilmedi",
                "recommendation": "Düzenli aralıklarla SSL güvenlik kontrollerini sürdürün"
            })
            
        return result 