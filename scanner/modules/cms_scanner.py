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
                    '/xmlrpc.php',
                    '/wp-cron.php',
                    '/wp-config.php',
                    '/wp-blog-header.php'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'WordPress'},
                    {'name': 'generator', 'content': 'wordpress'}
                ],
                'headers': [
                    'x-powered-by: WordPress'
                ],
                'cookies': [
                    'wordpress_test_cookie',
                    'wp-settings-'
                ],
                'html': [
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
                    '/installation/',
                    '/cache/',
                    '/includes/',
                    '/language/',
                    '/plugins/',
                    '/tmp/'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'Joomla!'},
                    {'name': 'generator', 'content': 'joomla'}
                ],
                'headers': [
                    'x-powered-by: Joomla'
                ],
                'cookies': [
                    'jfcookie',
                    'joomla_user_state'
                ],
                'html': [
                    'com_content',
                    'com_users',
                    'mod_'
                ]
            },
            'drupal': {
                'paths': [
                    '/admin/',
                    '/includes/',
                    '/misc/',
                    '/modules/',
                    '/profiles/',
                    '/scripts/',
                    '/sites/',
                    '/themes/',
                    '/core/',
                    '/vendor/'
                ],
                'meta': [
                    {'name': 'generator', 'content': 'Drupal'},
                    {'name': 'generator', 'content': 'drupal'}
                ],
                'headers': [
                    'x-generator: Drupal',
                    'x-drupal-cache'
                ],
                'cookies': [
                    'SESS',
                    'Drupal.visitor'
                ],
                'html': [
                    'drupal.js',
                    'drupal.min.js',
                    'sites/all'
                ]
            }
        }
        
    def detect_cms(self):
        """CMS türünü tespit eder"""
        try:
            response = requests.get(self.target_url, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            for cms_name, signatures in self.cms_signatures.items():
                score = 0
                evidence = []
                
                # Meta tag kontrolü
                for meta in signatures['meta']:
                    meta_tag = soup.find('meta', attrs=meta)
                    if meta_tag:
                        score += 2
                        evidence.append(f"Meta tag: {meta['name']}={meta['content']}")
                
                # Header kontrolü
                for header in signatures['headers']:
                    header_name = header.split(':')[0].lower()
                    if header_name in response.headers:
                        score += 2
                        evidence.append(f"Header: {header}")
                
                # Cookie kontrolü
                for cookie in signatures['cookies']:
                    if any(cookie in c for c in response.cookies.keys()):
                        score += 1
                        evidence.append(f"Cookie: {cookie}")
                
                # HTML içerik kontrolü
                for pattern in signatures['html']:
                    if pattern in response.text.lower():
                        score += 1
                        evidence.append(f"HTML: {pattern}")
                
                # Path kontrolü
                for path in signatures['paths']:
                    try:
                        path_url = urljoin(self.target_url, path)
                        path_response = requests.get(path_url, verify=False)
                        if path_response.status_code in [200, 301, 302, 403]:
                            score += 2
                            evidence.append(f"Path: {path}")
                    except:
                        continue
                
                if score >= 3:
                    return {
                        'name': cms_name,
                        'score': score,
                        'evidence': evidence
                    }
            
            return None
            
        except Exception as e:
            return None
            
    def get_version(self, cms_info):
        """CMS versiyonunu tespit etmeye çalışır"""
        try:
            if cms_info['name'] == 'wordpress':
                # readme.html kontrolü
                readme_url = urljoin(self.target_url, '/readme.html')
                response = requests.get(readme_url, verify=False)
                if response.status_code == 200:
                    version_match = re.search(r'Version\s+(\d+\.\d+\.?\d*)', response.text)
                    if version_match:
                        return version_match.group(1)
                
                # feed kontrolü
                feed_url = urljoin(self.target_url, '/feed/')
                response = requests.get(feed_url, verify=False)
                if response.status_code == 200:
                    version_match = re.search(r'generator>https://wordpress.org/\?v=(\d+\.\d+\.?\d*)', response.text)
                    if version_match:
                        return version_match.group(1)
                        
            elif cms_info['name'] == 'joomla':
                # manifest.xml kontrolü
                manifest_paths = [
                    '/administrator/manifests/files/joomla.xml',
                    '/language/en-GB/en-GB.xml'
                ]
                
                for path in manifest_paths:
                    manifest_url = urljoin(self.target_url, path)
                    response = requests.get(manifest_url, verify=False)
                    if response.status_code == 200:
                        version_match = re.search(r'<version>(\d+\.\d+\.?\d*)', response.text)
                        if version_match:
                            return version_match.group(1)
                            
            elif cms_info['name'] == 'drupal':
                # CHANGELOG.txt kontrolü
                changelog_url = urljoin(self.target_url, '/CHANGELOG.txt')
                response = requests.get(changelog_url, verify=False)
                if response.status_code == 200:
                    version_match = re.search(r'Drupal\s+(\d+\.\d+\.?\d*)', response.text)
                    if version_match:
                        return version_match.group(1)
                
                # core/CHANGELOG.txt kontrolü
                core_changelog_url = urljoin(self.target_url, '/core/CHANGELOG.txt')
                response = requests.get(core_changelog_url, verify=False)
                if response.status_code == 200:
                    version_match = re.search(r'Drupal\s+(\d+\.\d+\.?\d*)', response.text)
                    if version_match:
                        return version_match.group(1)
            
            return None
            
        except Exception as e:
            return None
            
    def check_vulnerabilities(self, cms_info, version):
        """Bilinen zafiyetleri kontrol eder"""
        vulnerabilities = []
        
        try:
            # WPScan API veya benzer bir API kullanılabilir
            # Şimdilik örnek zafiyetler
            common_vulnerabilities = {
                'wordpress': {
                    '5.8': [
                        {
                            'name': 'SQL Injection in WP_Query',
                            'description': 'SQL injection vulnerability in WP_Query class',
                            'severity': 'High',
                            'cve': 'CVE-2021-XXXX'
                        }
                    ],
                    '5.7': [
                        {
                            'name': 'XSS in Media Library',
                            'description': 'Cross-site scripting vulnerability in media library',
                            'severity': 'Medium',
                            'cve': 'CVE-2021-YYYY'
                        }
                    ]
                },
                'joomla': {
                    '3.9': [
                        {
                            'name': 'Path Traversal',
                            'description': 'Path traversal vulnerability in media manager',
                            'severity': 'High',
                            'cve': 'CVE-2020-XXXX'
                        }
                    ]
                },
                'drupal': {
                    '9.1': [
                        {
                            'name': 'Remote Code Execution',
                            'description': 'Remote code execution vulnerability in Form API',
                            'severity': 'Critical',
                            'cve': 'CVE-2021-ZZZZ'
                        }
                    ]
                }
            }
            
            if cms_info['name'] in common_vulnerabilities and \
               version in common_vulnerabilities[cms_info['name']]:
                vulnerabilities.extend(common_vulnerabilities[cms_info['name']][version])
            
            return vulnerabilities
            
        except Exception as e:
            return []
            
    def scan(self):
        """CMS zafiyetlerini test eder"""
        result = {
            "title": "CMS Zafiyet Testi",
            "findings": []
        }
        
        try:
            # CMS'i tespit et
            cms_info = self.detect_cms()
            
            if not cms_info:
                result["findings"].append({
                    "name": "CMS Tespit Edilemedi",
                    "description": "Bilinen CMS imzaları bulunamadı",
                    "risk_level": "Bilgi",
                    "impact": "Test yapılamadı",
                    "recommendation": "Site bir CMS kullanmıyor olabilir"
                })
                return result
            
            # CMS versiyonunu bul
            version = self.get_version(cms_info)
            
            # CMS tespiti raporla
            result["findings"].append({
                "name": "CMS Tespit Edildi",
                "description": f"CMS: {cms_info['name'].upper()}\n" + \
                             f"Versiyon: {version if version else 'Belirlenemedi'}\n" + \
                             f"Eşleşme Skoru: {cms_info['score']}\n" + \
                             f"Kanıtlar:\n" + \
                             "\n".join(f"- {e}" for e in cms_info['evidence']),
                "risk_level": "Orta",
                "impact": "CMS türü ve versiyonu tespit edilebiliyor",
                "recommendation": "\n".join([
                    "1. CMS versiyonunu güncel tutun",
                    "2. Gereksiz meta tag ve headerları kaldırın",
                    "3. Varsayılan dosya ve dizinleri yeniden adlandırın",
                    "4. Web Application Firewall (WAF) kullanın",
                    "5. Güvenlik başlıklarını ekleyin"
                ])
            })
            
            if version:
                # Zafiyetleri kontrol et
                vulnerabilities = self.check_vulnerabilities(cms_info, version)
                
                if vulnerabilities:
                    for vuln in vulnerabilities:
                        result["findings"].append({
                            "name": f"CMS Zafiyeti: {vuln['name']}",
                            "description": f"CVE: {vuln.get('cve', 'N/A')}\n" + \
                                         f"Açıklama: {vuln['description']}",
                            "risk_level": vuln['severity'],
                            "impact": "CMS üzerinde güvenlik açığı mevcut",
                            "recommendation": "\n".join([
                                "1. CMS'i en son sürüme güncelleyin",
                                "2. Güvenlik yamalarını uygulayın",
                                "3. İlgili eklenti veya modülü devre dışı bırakın",
                                "4. WAF kurallarını güncelleyin",
                                "5. Düzenli güvenlik taramaları yapın"
                            ])
                        })
                else:
                    result["findings"].append({
                        "name": "CMS Zafiyeti Tespit Edilmedi",
                        "description": "Bilinen CMS zafiyetleri bulunamadı",
                        "risk_level": "Bilgi",
                        "impact": "Yok",
                        "recommendation": "CMS'i güncel tutmaya devam edin"
                    })
                    
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"CMS taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "CMS zafiyetleri belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 