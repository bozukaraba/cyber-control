import ssl
import socket
import datetime
from urllib.parse import urlparse
from sslyze import (
    Scanner, ServerNetworkLocation, ServerScanRequest,
    ScanCommand, ServerHostnameCouldNotBeResolved
)
from sslyze.errors import ConnectionToServerFailed
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

class SSLTLSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        parsed_url = urlparse(target_url)
        self.hostname = parsed_url.netloc.split(':')[0]  # Port numarasını kaldır
        self.port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        
    def scan(self):
        """Kapsamlı SSL/TLS güvenlik taraması gerçekleştirir"""
        result = {
            "title": "SSL/TLS Güvenlik Testi",
            "findings": []
        }
        
        if not self.target_url.startswith("https://"):
            result["findings"].append({
                "name": "HTTPS Kullanımı",
                "description": "Site HTTPS protokolü kullanmıyor",
                "risk_level": "Kritik",
                "impact": "Veri transferi şifrelenmeden gerçekleşiyor, veriler açıkta kalabilir",
                "recommendation": "HTTPS protokolünü aktifleştiriniz ve tüm HTTP trafiğini HTTPS'e yönlendiriniz"
            })
            return result
            
        try:
            # SSLyze ile detaylı tarama
            server_location = ServerNetworkLocation(hostname=self.hostname, port=self.port)
            request = ServerScanRequest(
                server_location=server_location,
                scan_commands={
                    ScanCommand.CERTIFICATE_INFO,
                    ScanCommand.SSL_2_0_CIPHER_SUITES,
                    ScanCommand.SSL_3_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_0_CIPHER_SUITES,
                    ScanCommand.TLS_1_1_CIPHER_SUITES,
                    ScanCommand.TLS_1_2_CIPHER_SUITES,
                    ScanCommand.TLS_1_3_CIPHER_SUITES,
                    ScanCommand.HEARTBLEED,
                    ScanCommand.ROBOT,
                    ScanCommand.OPENSSL_CCS_INJECTION,
                    ScanCommand.SESSION_RENEGOTIATION,
                    ScanCommand.HTTP_HEADERS
                }
            )
            
            scanner = Scanner()
            scan_result = scanner.run_scan_request(request)
            
            # Sertifika analizi
            cert_info = scan_result.scan_commands_results[ScanCommand.CERTIFICATE_INFO]
            cert_chain = cert_info.verified_certificate_chain
            
            if cert_chain:
                leaf_cert = cert_chain[0]
                
                # Sertifika geçerlilik kontrolü
                now = datetime.datetime.now()
                if now > leaf_cert.not_valid_after:
                    result["findings"].append({
                        "name": "Sertifika Süresi Dolmuş",
                        "description": f"SSL sertifikasının süresi {leaf_cert.not_valid_after.strftime('%Y-%m-%d')} tarihinde dolmuş",
                        "risk_level": "Kritik",
                        "impact": "Kullanıcılar güvenlik uyarısı alacak ve siteyi güvensiz olarak görecek",
                        "recommendation": "SSL sertifikasını yenileyin"
                    })
                elif now < leaf_cert.not_valid_before:
                    result["findings"].append({
                        "name": "Sertifika Henüz Geçerli Değil",
                        "description": f"SSL sertifikası {leaf_cert.not_valid_before.strftime('%Y-%m-%d')} tarihinden itibaren geçerli olacak",
                        "risk_level": "Kritik",
                        "impact": "Kullanıcılar güvenlik uyarısı alacak ve siteyi güvensiz olarak görecek",
                        "recommendation": "Sertifika yapılandırmasını kontrol edin"
                    })
                
                # Sertifika bitiş tarihi yaklaşıyor mu?
                days_to_expire = (leaf_cert.not_valid_after - now).days
                if days_to_expire <= 30:
                    result["findings"].append({
                        "name": "Sertifika Yakında Sona Erecek",
                        "description": f"SSL sertifikası {days_to_expire} gün içinde sona erecek",
                        "risk_level": "Orta",
                        "impact": "Sertifika süresi dolduğunda site güvensiz olarak işaretlenecek",
                        "recommendation": "SSL sertifikasını yenileyin"
                    })
                
                # Zayıf imza algoritması kontrolü
                if leaf_cert.signature_hash_algorithm.name in ['md5', 'sha1']:
                    result["findings"].append({
                        "name": "Zayıf Sertifika İmza Algoritması",
                        "description": f"Sertifika {leaf_cert.signature_hash_algorithm.name.upper()} imza algoritması kullanıyor",
                        "risk_level": "Yüksek",
                        "impact": "Sertifika güvenliği tehlikeye girebilir",
                        "recommendation": "Daha güçlü bir imza algoritması (SHA-256 veya üzeri) kullanan yeni bir sertifika edinin"
                    })
            
            # SSL/TLS protokol ve şifreleme analizi
            protocols = {
                ScanCommand.SSL_2_0_CIPHER_SUITES: "SSL 2.0",
                ScanCommand.SSL_3_0_CIPHER_SUITES: "SSL 3.0",
                ScanCommand.TLS_1_0_CIPHER_SUITES: "TLS 1.0",
                ScanCommand.TLS_1_1_CIPHER_SUITES: "TLS 1.1"
            }
            
            for protocol_command, protocol_name in protocols.items():
                if protocol_command in scan_result.scan_commands_results:
                    result_for_protocol = scan_result.scan_commands_results[protocol_command]
                    if result_for_protocol.accepted_cipher_suites:
                        result["findings"].append({
                            "name": f"Eski {protocol_name} Protokolü Aktif",
                            "description": f"{protocol_name} protokolü aktif ve {len(result_for_protocol.accepted_cipher_suites)} şifreleme paketi destekliyor",
                            "risk_level": "Yüksek",
                            "impact": "Eski protokoller bilinen güvenlik açıklarına sahiptir",
                            "recommendation": f"{protocol_name} protokolünü devre dışı bırakın"
                        })
            
            # Heartbleed kontrolü
            heartbleed_result = scan_result.scan_commands_results[ScanCommand.HEARTBLEED]
            if heartbleed_result.is_vulnerable_to_heartbleed:
                result["findings"].append({
                    "name": "Heartbleed Açığı",
                    "description": "Sunucu Heartbleed (CVE-2014-0160) açığına karşı savunmasız",
                    "risk_level": "Kritik",
                    "impact": "Bellek sızıntısı yoluyla hassas veriler çalınabilir",
                    "recommendation": "OpenSSL'i güncelleyin ve sunucuyu yeniden başlatın"
                })
            
            # ROBOT saldırısı kontrolü
            robot_result = scan_result.scan_commands_results[ScanCommand.ROBOT]
            if robot_result.robot_result_enum.value > 1:  # 1 = NOT_VULNERABLE
                result["findings"].append({
                    "name": "ROBOT Açığı",
                    "description": "Sunucu ROBOT (Return Of Bleichenbacher's Oracle Threat) saldırısına karşı savunmasız",
                    "risk_level": "Yüksek",
                    "impact": "RSA şifreleme sistemi tehlikeye girebilir",
                    "recommendation": "RSA şifreleme paketlerini devre dışı bırakın veya sunucu yazılımını güncelleyin"
                })
            
            # CCS Injection kontrolü
            ccs_result = scan_result.scan_commands_results[ScanCommand.OPENSSL_CCS_INJECTION]
            if ccs_result.is_vulnerable_to_ccs_injection:
                result["findings"].append({
                    "name": "OpenSSL CCS Injection Açığı",
                    "description": "Sunucu OpenSSL CCS Injection (CVE-2014-0224) açığına karşı savunmasız",
                    "risk_level": "Yüksek",
                    "impact": "Man-in-the-middle saldırıları mümkün olabilir",
                    "recommendation": "OpenSSL'i güncelleyin"
                })
            
            # HTTP Güvenlik Başlıkları
            headers_result = scan_result.scan_commands_results[ScanCommand.HTTP_HEADERS]
            if headers_result:
                if not headers_result.strict_transport_security_header:
                    result["findings"].append({
                        "name": "HSTS Eksik",
                        "description": "HTTP Strict Transport Security (HSTS) başlığı eksik",
                        "risk_level": "Orta",
                        "impact": "SSL stripping saldırıları mümkün olabilir",
                        "recommendation": "Strict-Transport-Security başlığını ekleyin"
                    })
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "SSL/TLS Yapılandırması Güvenli",
                    "description": "SSL/TLS yapılandırmasında önemli bir güvenlik sorunu tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except (ConnectionToServerFailed, ServerHostnameCouldNotBeResolved) as e:
            result["findings"].append({
                "name": "Bağlantı Hatası",
                "description": f"SSL/TLS taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "SSL/TLS güvenlik durumu belirlenemedi",
                "recommendation": "Sunucu SSL/TLS yapılandırmasını ve erişilebilirliğini kontrol edin"
            })
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Beklenmeyen hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "SSL/TLS güvenlik durumu belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 