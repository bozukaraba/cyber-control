import socket
import ssl
import OpenSSL
from datetime import datetime
from urllib.parse import urlparse

class SSLScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        parsed_url = urlparse(target_url)
        self.target_host = parsed_url.netloc.split(':')[0]
        self.target_port = parsed_url.port or 443
        
    def get_certificate(self):
        """SSL sertifikasını alır"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((self.target_host, self.target_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
                    return x509
        except:
            return None
            
    def check_protocol_support(self):
        """Desteklenen SSL/TLS protokollerini kontrol eder"""
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
            'TLSv1.3': ssl.PROTOCOL_TLS
        }
        
        supported = {}
        for protocol_name, protocol in protocols.items():
            try:
                context = ssl.SSLContext(protocol)
                with socket.create_connection((self.target_host, self.target_port)) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                        version = ssock.version()
                        supported[protocol_name] = True
            except:
                supported[protocol_name] = False
                
        return supported
        
    def check_cipher_suites(self):
        """Desteklenen şifreleme paketlerini kontrol eder"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((self.target_host, self.target_port)) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_host) as ssock:
                    return ssock.cipher()
        except:
            return None
            
    def scan(self):
        """SSL/TLS güvenliğini test eder"""
        result = {
            "title": "SSL/TLS Güvenlik Testi",
            "findings": []
        }
        
        try:
            # Sertifika kontrolü
            cert = self.get_certificate()
            if cert:
                # Sertifika geçerlilik tarihi kontrolü
                not_before = datetime.strptime(cert.get_notBefore().decode(), '%Y%m%d%H%M%SZ')
                not_after = datetime.strptime(cert.get_notAfter().decode(), '%Y%m%d%H%M%SZ')
                now = datetime.utcnow()
                
                if now < not_before:
                    result["findings"].append({
                        "name": "Sertifika Henüz Geçerli Değil",
                        "description": f"Sertifika başlangıç tarihi: {not_before}",
                        "risk_level": "Yüksek",
                        "impact": "SSL sertifikası henüz geçerli olmadığı için güvenli bağlantı kurulamaz",
                        "recommendation": "Geçerli bir SSL sertifikası yükleyin"
                    })
                elif now > not_after:
                    result["findings"].append({
                        "name": "Sertifika Süresi Dolmuş",
                        "description": f"Sertifika bitiş tarihi: {not_after}",
                        "risk_level": "Kritik",
                        "impact": "SSL sertifikası geçersiz olduğu için güvenli bağlantı kurulamaz",
                        "recommendation": "SSL sertifikasını yenileyin"
                    })
                elif (not_after - now).days < 30:
                    result["findings"].append({
                        "name": "Sertifika Yakında Sona Erecek",
                        "description": f"Sertifika bitiş tarihi: {not_after}",
                        "risk_level": "Orta",
                        "impact": "SSL sertifikası yakında geçersiz olacak",
                        "recommendation": "SSL sertifikasını yenileme işlemlerini başlatın"
                    })
                
                # Sertifika algoritması kontrolü
                signature_algorithm = cert.get_signature_algorithm().decode()
                weak_algorithms = ['md5', 'sha1']
                if any(algo in signature_algorithm.lower() for algo in weak_algorithms):
                    result["findings"].append({
                        "name": "Zayıf Sertifika İmza Algoritması",
                        "description": f"Kullanılan algoritma: {signature_algorithm}",
                        "risk_level": "Yüksek",
                        "impact": "Zayıf şifreleme algoritması kullanıldığı için sertifika güvenliği düşük",
                        "recommendation": "SHA-256 veya daha güçlü bir algoritma kullanan sertifika alın"
                    })
                
                # Anahtar uzunluğu kontrolü
                key_length = cert.get_pubkey().bits()
                if key_length < 2048:
                    result["findings"].append({
                        "name": "Yetersiz Anahtar Uzunluğu",
                        "description": f"Anahtar uzunluğu: {key_length} bit",
                        "risk_level": "Yüksek",
                        "impact": "Kısa anahtar uzunluğu nedeniyle sertifika güvenliği düşük",
                        "recommendation": "En az 2048 bit RSA veya eşdeğer güçte bir anahtar kullanın"
                    })
            else:
                result["findings"].append({
                    "name": "SSL Sertifikası Alınamadı",
                    "description": "SSL sertifikasına erişilemedi veya sertifika bulunamadı",
                    "risk_level": "Kritik",
                    "impact": "SSL/TLS güvenliği sağlanamıyor",
                    "recommendation": "Geçerli bir SSL sertifikası yükleyin"
                })
            
            # Protokol desteği kontrolü
            protocols = self.check_protocol_support()
            insecure_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0']
            for protocol, supported in protocols.items():
                if supported and protocol in insecure_protocols:
                    result["findings"].append({
                        "name": f"Güvensiz {protocol} Protokolü Aktif",
                        "description": f"{protocol} protokolü sunucu tarafından destekleniyor",
                        "risk_level": "Yüksek",
                        "impact": "Eski ve güvensiz protokoller üzerinden saldırılar mümkün",
                        "recommendation": f"{protocol} protokolünü devre dışı bırakın"
                    })
                elif not supported and protocol in ['TLSv1.2', 'TLSv1.3']:
                    result["findings"].append({
                        "name": f"Güvenli {protocol} Protokolü Pasif",
                        "description": f"{protocol} protokolü sunucu tarafından desteklenmiyor",
                        "risk_level": "Orta",
                        "impact": "Modern ve güvenli protokoller kullanılamıyor",
                        "recommendation": f"{protocol} protokolünü etkinleştirin"
                    })
            
            # Şifreleme paketi kontrolü
            cipher = self.check_cipher_suites()
            if cipher:
                cipher_name = cipher[0]
                weak_ciphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT']
                if any(c in cipher_name for c in weak_ciphers):
                    result["findings"].append({
                        "name": "Zayıf Şifreleme Paketi",
                        "description": f"Kullanılan şifreleme: {cipher_name}",
                        "risk_level": "Yüksek",
                        "impact": "Zayıf şifreleme nedeniyle iletişim güvenliği düşük",
                        "recommendation": "Güçlü şifreleme paketlerini kullanın ve zayıf olanları devre dışı bırakın"
                    })
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "SSL/TLS Yapılandırması Güvenli",
                    "description": "SSL/TLS güvenlik testlerinde bir sorun tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"SSL/TLS taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "SSL/TLS güvenliği belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 