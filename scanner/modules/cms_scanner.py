import requests
import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

class CMSScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.cms_signatures = {
            "wordpress": {
                "patterns": [
                    "/wp-content/", 
                    "/wp-includes/", 
                    "wp-login.php",
                    "<meta name=\"generator\" content=\"WordPress"
                ],
                "paths": [
                    "/wp-login.php",
                    "/license.txt",
                    "/wp-content/themes/",
                    "/wp-content/plugins/",
                    "/wp-includes/",
                    "/xmlrpc.php"
                ],
                "vulnerabilities": {
                    "versions": {
                        "<5.8": "Eski WordPress sürümleri güvenlik güncellemeleri almıyor olabilir",
                        "<5.6": "Otomatik güncellemeler yapılandırılmamış olabilir",
                        "<5.0": "Gutenberg editörü öncesi sürümler kritik güvenlik açıklarına sahip olabilir",
                        "<4.7": "REST API güvenlik açıkları barındırabilir"
                    }
                }
            },
            "joomla": {
                "patterns": [
                    "/administrator/", 
                    "Joomla!",
                    "/components/",
                    "/modules/",
                    "<meta name=\"generator\" content=\"Joomla!"
                ],
                "paths": [
                    "/administrator/",
                    "/language/en-GB/en-GB.xml",
                    "/components/",
                    "/modules/",
                    "/templates/",
                    "/libraries/joomla/"
                ],
                "vulnerabilities": {
                    "versions": {
                        "<4.0": "Eski Joomla sürümleri güvenlik güncellemeleri almıyor olabilir",
                        "<3.9": "Veri gizliliği özellikleri eksik olabilir",
                        "<3.0": "Kritik güvenlik açıklarına sahip olabilir"
                    }
                }
            },
            "drupal": {
                "patterns": [
                    "/sites/all/", 
                    "/sites/default/",
                    "Drupal.settings",
                    "<meta name=\"Generator\" content=\"Drupal"
                ],
                "paths": [
                    "/CHANGELOG.txt",
                    "/core/CHANGELOG.txt",
                    "/sites/all/",
                    "/sites/default/",
                    "/core/misc/drupal.js",
                    "/modules/"
                ],
                "vulnerabilities": {
                    "versions": {
                        "<9.0": "Eski Drupal sürümleri güvenlik güncellemeleri almıyor olabilir",
                        "<8.9": "Eski sürümler için güvenlik desteği sona ermiş olabilir",
                        "<8.0": "Symfony bileşenlerini kullanmayan eski sürümler güvenlik sorunlarına açık olabilir",
                        "<7.0": "Kritik güvenlik açıklarına sahip olabilir"
                    }
                }
            },
            "magento": {
                "patterns": [
                    "Mage.Cookies",
                    "/skin/frontend/",
                    "/app/design/frontend/"
                ],
                "paths": [
                    "/app/",
                    "/skin/",
                    "/js/mage/",
                    "/media/",
                    "/var/"
                ],
                "vulnerabilities": {
                    "versions": {
                        "<2.3": "Eski Magento sürümleri kritik güvenlik açıkları içerebilir",
                        "<2.0": "Magento 1.x sürümleri için güvenlik desteği sona ermiştir"
                    }
                }
            }
        }
        
    def scan(self):
        """CMS tespiti ve açık taraması yapar"""
        result = {
            "title": "CMS Açıkları Taraması",
            "findings": []
        }
        
        try:
            # CMS tespiti yap
            cms_info = self._detect_cms()
            
            if cms_info:
                cms_name = cms_info["name"]
                cms_version = cms_info.get("version", "Bilinmeyen")
                
                result["findings"].append({
                    "name": "CMS Tespiti",
                    "description": f"Site {cms_name.capitalize()} CMS kullanıyor (Sürüm: {cms_version})",
                    "risk_level": "Düşük",
                    "impact": "CMS kullanımı kendi başına bir risk değildir, ancak bilinen açıklar olabilir",
                    "recommendation": f"{cms_name.capitalize()} CMS'i güncel tutun ve güvenlik güncellemelerini düzenli olarak uygulayın"
                })
                
                # CMS sürüm kontrolü ve bilinen zafiyet taraması
                vulnerabilities = self._check_vulnerabilities(cms_name, cms_version)
                
                for vuln in vulnerabilities:
                    result["findings"].append(vuln)
            else:
                result["findings"].append({
                    "name": "CMS Tespiti",
                    "description": "Bilinen bir CMS tespit edilemedi veya CMS gizlenmiş olabilir",
                    "risk_level": "Düşük",
                    "impact": "CMS tespit edilemediği için özel zafiyetler taranamadı",
                    "recommendation": "CMS gizleme uygulamanız varsa, bunu sürdürmeye devam edin"
                })
                
        except Exception as e:
            result["findings"].append({
                "name": "CMS Tarama Hatası",
                "description": f"CMS taraması sırasında hata oluştu: {str(e)}",
                "risk_level": "Düşük",
                "impact": "CMS taraması tamamlanamadı",
                "recommendation": "Taramayı yeniden deneyin"
            })
            
        return result
    
    def _detect_cms(self):
        """Kullanılan CMS'i tespit etmeye çalışır"""
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            content = response.text
            
            # BeautifulSoup ile HTML analizi
            soup = BeautifulSoup(content, 'html.parser')
            
            # Her CMS için belirtilen pattern'ları kontrol et
            for cms_name, cms_data in self.cms_signatures.items():
                patterns = cms_data["patterns"]
                
                # İçerikte pattern'lar var mı kontrol et
                for pattern in patterns:
                    if pattern in content:
                        # CMS tespit edildi, şimdi versiyon tespiti yapalım
                        version = self._detect_version(cms_name, content, soup)
                        
                        return {
                            "name": cms_name,
                            "version": version
                        }
                        
                # Pattern'lar yoksa, spesifik yolları kontrol et
                if "paths" in cms_data:
                    for path in cms_data["paths"]:
                        # Tam URL oluştur
                        parsed_url = urlparse(self.target_url)
                        test_url = urljoin(f"{parsed_url.scheme}://{parsed_url.netloc}", path)
                        
                        try:
                            path_response = requests.get(test_url, timeout=5, verify=False)
                            if path_response.status_code == 200:
                                # Bu yol var, bu CMS'e ait olabilir
                                version = self._detect_version(cms_name, path_response.text, BeautifulSoup(path_response.text, 'html.parser'))
                                
                                return {
                                    "name": cms_name,
                                    "version": version
                                }
                        except requests.exceptions.RequestException:
                            continue
            
            return None
            
        except requests.exceptions.RequestException:
            return None
            
    def _detect_version(self, cms_name, content, soup):
        """CMS versiyonunu tespit etmeye çalışır"""
        version = "Bilinmeyen"
        
        # WordPress versiyon tespiti
        if cms_name == "wordpress":
            # Meta tag içinde versiyon kontrolü
            meta_generator = soup.find("meta", {"name": "generator"})
            if meta_generator and "content" in meta_generator.attrs:
                match = re.search(r'WordPress\s+([\d.]+)', meta_generator["content"])
                if match:
                    version = match.group(1)
            
            # RSS feed içinde versiyon kontrolü
            if version == "Bilinmeyen":
                try:
                    feed_url = urljoin(self.target_url, "/feed/")
                    feed_response = requests.get(feed_url, timeout=5, verify=False)
                    if feed_response.status_code == 200:
                        feed_match = re.search(r'<generator>https://wordpress.org/\?v=([\d.]+)</generator>', feed_response.text)
                        if feed_match:
                            version = feed_match.group(1)
                except requests.exceptions.RequestException:
                    pass
            
            # readme.html içinde versiyon kontrolü
            if version == "Bilinmeyen":
                try:
                    readme_url = urljoin(self.target_url, "/readme.html")
                    readme_response = requests.get(readme_url, timeout=5, verify=False)
                    if readme_response.status_code == 200:
                        readme_match = re.search(r'Version\s+([\d.]+)', readme_response.text)
                        if readme_match:
                            version = readme_match.group(1)
                except requests.exceptions.RequestException:
                    pass
                    
        # Joomla versiyon tespiti
        elif cms_name == "joomla":
            # Meta tag içinde versiyon kontrolü
            meta_generator = soup.find("meta", {"name": "generator"})
            if meta_generator and "content" in meta_generator.attrs:
                match = re.search(r'Joomla!\s+([\d.]+)', meta_generator["content"])
                if match:
                    version = match.group(1)
            
            # XML dosyasında versiyon kontrolü
            if version == "Bilinmeyen":
                try:
                    xml_url = urljoin(self.target_url, "/language/en-GB/en-GB.xml")
                    xml_response = requests.get(xml_url, timeout=5, verify=False)
                    if xml_response.status_code == 200:
                        xml_match = re.search(r'<version>([\d.]+)', xml_response.text)
                        if xml_match:
                            version = xml_match.group(1)
                except requests.exceptions.RequestException:
                    pass
                    
        # Drupal versiyon tespiti
        elif cms_name == "drupal":
            # CHANGELOG.txt içinde versiyon kontrolü
            try:
                changelog_url = urljoin(self.target_url, "/CHANGELOG.txt")
                changelog_response = requests.get(changelog_url, timeout=5, verify=False)
                if changelog_response.status_code == 200:
                    changelog_match = re.search(r'Drupal\s+([\d.]+)', changelog_response.text)
                    if changelog_match:
                        version = changelog_match.group(1)
            except requests.exceptions.RequestException:
                pass
                
            # Alternatif CHANGELOG.txt yolu
            if version == "Bilinmeyen":
                try:
                    alt_changelog_url = urljoin(self.target_url, "/core/CHANGELOG.txt")
                    alt_changelog_response = requests.get(alt_changelog_url, timeout=5, verify=False)
                    if alt_changelog_response.status_code == 200:
                        alt_changelog_match = re.search(r'Drupal\s+([\d.]+)', alt_changelog_response.text)
                        if alt_changelog_match:
                            version = alt_changelog_match.group(1)
                except requests.exceptions.RequestException:
                    pass
                    
        # Magento versiyon tespiti
        elif cms_name == "magento":
            # CSS dosyaları içinde versiyon kontrol etme
            try:
                for css_path in ["/skin/frontend/default/default/css/styles.css", "/skin/frontend/base/default/css/styles.css"]:
                    css_url = urljoin(self.target_url, css_path)
                    css_response = requests.get(css_url, timeout=5, verify=False)
                    if css_response.status_code == 200:
                        # CSS yorumlarında versiyon bilgisi olabilir
                        css_match = re.search(r'@version\s+([\d.]+)', css_response.text)
                        if css_match:
                            version = css_match.group(1)
                            break
            except requests.exceptions.RequestException:
                pass
                
        return version
    
    def _check_vulnerabilities(self, cms_name, version):
        """Tespit edilen CMS'in bilinen açıklarını kontrol eder"""
        vulnerabilities = []
        
        if cms_name in self.cms_signatures and "vulnerabilities" in self.cms_signatures[cms_name]:
            cms_vulns = self.cms_signatures[cms_name]["vulnerabilities"]
            
            # Sürüm bazlı güvenlik açıkları kontrolü
            if "versions" in cms_vulns and version != "Bilinmeyen":
                for vuln_version, vuln_description in cms_vulns["versions"].items():
                    # Sürüm karşılaştırması (örn: <5.8)
                    operation = vuln_version[0]
                    compare_version = vuln_version[1:]
                    
                    version_parts = version.split('.')
                    compare_parts = compare_version.split('.')
                    
                    # Eksik kısımları 0 ile tamamlayarak karşılaştırma yapalım
                    while len(version_parts) < len(compare_parts):
                        version_parts.append('0')
                    while len(compare_parts) < len(version_parts):
                        compare_parts.append('0')
                    
                    # Karşılaştırma için int'e çevirelim
                    try:
                        v_parts = [int(p) for p in version_parts]
                        c_parts = [int(p) for p in compare_parts]
                        
                        is_vulnerable = False
                        
                        if operation == "<" and v_parts < c_parts:
                            is_vulnerable = True
                        elif operation == "<=" and v_parts <= c_parts:
                            is_vulnerable = True
                        elif operation == ">" and v_parts > c_parts:
                            is_vulnerable = True
                        elif operation == ">=" and v_parts >= c_parts:
                            is_vulnerable = True
                        elif operation == "=" and v_parts == c_parts:
                            is_vulnerable = True
                            
                        if is_vulnerable:
                            vulnerabilities.append({
                                "name": f"{cms_name.capitalize()} Sürüm Güvenlik Açığı",
                                "description": f"{cms_name.capitalize()} sürümü ({version}) potansiyel güvenlik açıkları içeriyor: {vuln_description}",
                                "risk_level": "Yüksek",
                                "impact": "Kritik güvenlik açıkları, veri sızıntısı, site ele geçirme riski",
                                "recommendation": f"{cms_name.capitalize()} CMS'i en son sürüme güncelleyin"
                            })
                    except ValueError:
                        # Sürüm sayı değilse karşılaştırma yapamıyoruz
                        pass
        
        return vulnerabilities 