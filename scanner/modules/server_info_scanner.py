import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin

class ServerInfoScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.sensitive_headers = [
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version',
            'X-Runtime',
            'X-Version',
            'X-Generator',
            'X-Drupal-Cache',
            'X-Drupal-Dynamic-Cache',
            'X-Varnish',
            'Via',
            'X-Backend-Server',
            'X-Served-By',
            'X-Host',
            'X-Server',
            'X-App-Server',
            'X-Application-Context'
        ]
        self.sensitive_files = [
            '/robots.txt',
            '/sitemap.xml',
            '/.git/config',
            '/.env',
            '/.htaccess',
            '/web.config',
            '/phpinfo.php',
            '/info.php',
            '/server-status',
            '/server-info',
            '/.svn/entries',
            '/.idea/workspace.xml',
            '/README.md',
            '/CHANGELOG.md',
            '/composer.json',
            '/package.json',
            '/Gemfile',
            '/requirements.txt',
            '/config.php',
            '/config.yml',
            '/wp-config.php',
            '/configuration.php',
            '/database.yml',
            '/settings.py',
            '/config.inc.php'
        ]
        self.sensitive_directories = [
            '/admin',
            '/backup',
            '/log',
            '/logs',
            '/temp',
            '/tmp',
            '/test',
            '/dev',
            '/development',
            '/staging',
            '/old',
            '/new',
            '/beta',
            '/sql',
            '/db',
            '/database',
            '/upload',
            '/uploads',
            '/files',
            '/private',
            '/secret',
            '/hidden',
            '/config',
            '/configuration',
            '/settings',
            '/.git',
            '/.svn',
            '/CVS',
            '/.idea',
            '/.vscode'
        ]
        
    def check_headers(self, headers):
        """HTTP başlıklarını kontrol eder"""
        findings = []
        for header in self.sensitive_headers:
            if header in headers:
                findings.append({
                    'type': 'header',
                    'name': header,
                    'value': headers[header]
                })
        return findings
        
    def check_file(self, path):
        """Hassas dosyaları kontrol eder"""
        try:
            url = urljoin(self.target_url, path)
            response = requests.get(url, verify=False, allow_redirects=False)
            if response.status_code == 200:
                return {
                    'type': 'file',
                    'path': path,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'unknown')
                }
            return None
        except:
            return None
            
    def check_directory(self, path):
        """Hassas dizinleri kontrol eder"""
        try:
            url = urljoin(self.target_url, path)
            response = requests.get(url, verify=False, allow_redirects=False)
            if response.status_code in [200, 301, 302, 403]:
                return {
                    'type': 'directory',
                    'path': path,
                    'status': response.status_code
                }
            return None
        except:
            return None
            
    def check_comments(self, content):
        """HTML yorumlarını kontrol eder"""
        findings = []
        soup = BeautifulSoup(content, 'html.parser')
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        
        sensitive_patterns = [
            r'user\w*',
            r'pass\w*',
            r'admin\w*',
            r'root\w*',
            r'db\w*',
            r'sql\w*',
            r'api\w*',
            r'key\w*',
            r'secret\w*',
            r'config\w*',
            r'todo\w*',
            r'fix\w*',
            r'bug\w*',
            r'hack\w*',
            r'vulnerable\w*',
            r'vulnerability\w*',
            r'debug\w*',
            r'test\w*'
        ]
        
        for comment in comments:
            comment_text = comment.strip()
            if any(re.search(pattern, comment_text, re.I) for pattern in sensitive_patterns):
                findings.append({
                    'type': 'comment',
                    'content': comment_text
                })
                
        return findings
        
    def scan(self):
        """Sunucu bilgi sızıntılarını test eder"""
        result = {
            "title": "Sunucu Bilgi Sızıntısı Testi",
            "findings": []
        }
        
        try:
            # Ana sayfayı kontrol et
            response = requests.get(self.target_url, verify=False)
            
            # HTTP başlıklarını kontrol et
            header_findings = self.check_headers(response.headers)
            if header_findings:
                for finding in header_findings:
                    result["findings"].append({
                        "name": f"Hassas HTTP Başlığı: {finding['name']}",
                        "description": f"Başlık değeri: {finding['value']}",
                        "risk_level": "Orta",
                        "impact": "Sunucu teknoloji/versiyon bilgileri sızdırılıyor",
                        "recommendation": f"'{finding['name']}' başlığını kaldırın veya içeriğini gizleyin"
                    })
            
            # HTML yorumlarını kontrol et
            comment_findings = self.check_comments(response.text)
            if comment_findings:
                for finding in comment_findings:
                    result["findings"].append({
                        "name": "Hassas HTML Yorumu",
                        "description": f"Yorum içeriği: {finding['content'][:100]}...",
                        "risk_level": "Düşük",
                        "impact": "Kaynak kodda hassas bilgiler açığa çıkıyor",
                        "recommendation": "Hassas bilgi içeren yorumları kaldırın"
                    })
            
            # Hassas dosyaları kontrol et
            for file_path in self.sensitive_files:
                finding = self.check_file(file_path)
                if finding:
                    result["findings"].append({
                        "name": "Hassas Dosya Tespit Edildi",
                        "description": f"Dosya: {finding['path']}\n" + \
                                     f"Boyut: {finding['size']} bytes\n" + \
                                     f"Tür: {finding['content_type']}",
                        "risk_level": "Yüksek",
                        "impact": "Hassas yapılandırma veya sistem dosyalarına erişilebiliyor",
                        "recommendation": "\n".join([
                            "1. Dosyayı kaldırın veya erişimi engelleyin",
                            "2. Hassas bilgileri yapılandırma dosyalarından ayırın",
                            "3. Web kök dizini dışında saklayın",
                            "4. Dosya erişim izinlerini sıkılaştırın"
                        ])
                    })
            
            # Hassas dizinleri kontrol et
            for dir_path in self.sensitive_directories:
                finding = self.check_directory(dir_path)
                if finding:
                    result["findings"].append({
                        "name": "Hassas Dizin Tespit Edildi",
                        "description": f"Dizin: {finding['path']}\n" + \
                                     f"HTTP Durum Kodu: {finding['status']}",
                        "risk_level": "Yüksek" if finding['status'] != 403 else "Orta",
                        "impact": "Hassas sistem dizinlerine erişilebiliyor",
                        "recommendation": "\n".join([
                            "1. Dizini kaldırın veya erişimi engelleyin",
                            "2. Dizin listelemesini devre dışı bırakın",
                            "3. Dizin erişim izinlerini sıkılaştırın",
                            "4. Web kök dizini dışında saklayın",
                            "5. .htaccess veya web.config ile koruyun"
                        ])
                    })
            
            # Eğer hiç bulgu yoksa
            if not result["findings"]:
                result["findings"].append({
                    "name": "Bilgi Sızıntısı Tespit Edilmedi",
                    "description": "Sunucuda hassas bilgi sızıntısı tespit edilmedi",
                    "risk_level": "Bilgi",
                    "impact": "Yok",
                    "recommendation": "Düzenli güvenlik kontrollerine devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "Tarama Hatası",
                "description": f"Bilgi sızıntısı taraması sırasında hata: {str(e)}",
                "risk_level": "Hata",
                "impact": "Bilgi sızıntıları belirlenemedi",
                "recommendation": "Sistem yöneticinize başvurun"
            })
            
        return result 