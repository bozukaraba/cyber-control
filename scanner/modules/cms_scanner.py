import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
import json

class CMSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.cms_signatures = {
            'wordpress': {
                'paths': [
                    '/wp-admin/',
                    '/wp-content/',
                    '/wp-includes/',
                    '/wp-login.php',
                    '/xmlrpc.php'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'WordPress'},
                    {'name': 'generator', 'content': 'wordpress'}
                ],
                'headers': {
                    'X-Powered-By': 'WordPress'
                },
                'patterns': [
                    'wp-content',
                    'wp-includes',
                    'wp-json'
                ]
            },
            'joomla': {
                'paths': [
                    '/administrator/',
                    '/components/',
                    '/modules/',
                    '/templates/',
                    '/media/system/js/'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'Joomla!'},
                    {'name': 'generator', 'content': 'joomla'}
                ],
                'headers': {
                    'X-Powered-By': 'Joomla'
                },
                'patterns': [
                    'joomla',
                    'mosConfig',
                    '/media/system/js/'
                ]
            },
            'drupal': {
                'paths': [
                    '/admin/',
                    '/sites/all/',
                    '/sites/default/',
                    '/node/',
                    '/modules/'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'Drupal'},
                    {'name': 'generator', 'content': 'drupal'}
                ],
                'headers': {
                    'X-Generator': 'Drupal',
                    'X-Drupal-Cache': ''
                },
                'patterns': [
                    'drupal',
                    'sites/all',
                    'sites/default'
                ]
            },
            'magento': {
                'paths': [
                    '/admin/',
                    '/skin/',
                    '/media/',
                    '/app/etc/',
                    '/app/design/'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'Magento'},
                    {'name': 'generator', 'content': 'magento'}
                ],
                'headers': {
                    'X-Magento-Cache-Control': '',
                    'X-Magento-Cache-Debug': ''
                },
                'patterns': [
                    'magento',
                    'skin/frontend',
                    'Mage.Cookies'
                ]
            },
            'opencart': {
                'paths': [
                    '/admin/',
                    '/catalog/',
                    '/system/',
                    '/image/',
                    '/download/'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'OpenCart'},
                    {'name': 'generator', 'content': 'opencart'}
                ],
                'headers': {},
                'patterns': [
                    'opencart',
                    'index.php?route='
                ]
            }
        }
        
    def scan(self):
        """CMS türünü ve versiyonunu tespit eder"""
        result = {
            "title": "CMS Testi",
            "findings": []
        }
        
        try:
            response = requests.get(self.target_url, verify=False, allow_redirects=True)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            detected_cms = None
            version = None
            confidence = 0
            evidence = []
            
            # Her CMS için kontrol yap
            for cms_name, signatures in self.cms_signatures.items():
                current_confidence = 0
                current_evidence = []
                
                # Meta etiketlerini kontrol et
                for meta in signatures['meta']:
                    meta_tag = soup.find('meta', attrs=meta)
                    if meta_tag:
                        current_confidence += 30
                        current_evidence.append(f"Meta etiketi: {meta['name']}={meta['content']}")
                        # Versiyon bilgisini ara
                        if 'content' in meta_tag.attrs:
                            version_match = re.search(r'\d+\.\d+(\.\d+)?', meta_tag['content'])
                            if version_match:
                                version = version_match.group(0)
                
                # HTTP başlıklarını kontrol et
                for header, value in signatures['headers'].items():
                    if header in response.headers:
                        if value and value in response.headers[header]:
                            current_confidence += 20
                            current_evidence.append(f"HTTP başlığı: {header}={response.headers[header]}")
                        elif not value:  # Sadece başlığın varlığını kontrol et
                            current_confidence += 20
                            current_evidence.append(f"HTTP başlığı: {header} mevcut")
                
                # Belirli desenleri kontrol et
                for pattern in signatures['patterns']:
                    if pattern in response.text.lower():
                        current_confidence += 15
                        current_evidence.append(f"İçerik deseni: {pattern}")
                
                # Yolları kontrol et
                for path in signatures['paths']:
                    try:
                        path_url = urljoin(self.target_url, path)
                        path_response = requests.get(path_url, verify=False, allow_redirects=False, timeout=5)
                        if path_response.status_code in [200, 301, 302, 403]:
                            current_confidence += 10
                            current_evidence.append(f"Erişilebilir yol: {path}")
                    except:
                        continue
                
                # En yüksek güven skoruna sahip CMS'i seç
                if current_confidence > confidence:
                    detected_cms = cms_name
                    confidence = current_confidence
                    evidence = current_evidence
            
            # Sonuçları raporla
            if detected_cms and confidence >= 30:
                finding = {
                    "name": "CMS Tespit Edildi",
                    "description": f"CMS: {detected_cms.upper()}\n" + \
                                 (f"Versiyon: {version}\n" if version else "") + \
                                 f"Güven Skoru: {confidence}%\n\n" + \
                                 "Tespit Kanıtları:\n- " + "\n- ".join(evidence),
                    "risk_level": "Orta",
                    "impact": "CMS türü ve versiyonu bilindiğinde bilinen güvenlik açıkları hedeflenebilir",
                    "recommendation": "\n".join([
                        "1. CMS'i her zaman güncel tutun",
                        "2. Gereksiz modül ve eklentileri kaldırın",
                        "3. Varsayılan tema ve eklentileri özelleştirin",
                        "4. Güvenlik eklentileri kullanın",
                        "5. CMS sürüm bilgisini gizleyin",
                        "6. Düzenli güvenlik güncellemelerini takip edin"
                    ])
                }
                
                # Eski sürüm kontrolü
                if version:
                    finding["description"] += "\n\nNOT: Sürüm bilgisi tespit edildi. Bu bilgi saldırganlar tarafından kullanılabilir."
                    finding["recommendation"] += "\n7. Sürüm bilgisini gizleyin veya güncel sürüme yükseltin"
                
                result["findings"].append(finding)
            else:
                result["findings"].append({
                    "name": "CMS Tespit Edilemedi",
                    "description": "Bilinen CMS imzaları tespit edilemedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Özel bir CMS kullanıyorsanız güvenlik en iyi uygulamalarını takip edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"CMS taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "CMS türü ve versiyonu belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 