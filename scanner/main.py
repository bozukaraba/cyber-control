import sys
import json
import warnings
import urllib3
from modules.admin_panel_scanner import AdminPanelScanner
from modules.cms_scanner import CMSScanner
from modules.sql_injection_scanner import SQLInjectionScanner
from modules.xss_scanner import XSSScanner
from modules.file_upload_scanner import FileUploadScanner
from modules.brute_force_scanner import BruteForceScanner

# Uyarıları gizle
warnings.filterwarnings("ignore")
urllib3.disable_warnings()

def main():
    if len(sys.argv) != 2:
        print("Kullanım: python3 main.py <hedef_url>")
        sys.exit(1)
        
    target_url = sys.argv[1]
    results = []
    
    # Admin Panel Taraması
    print("\n[*] Admin Panel Taraması Başlatılıyor...")
    admin_scanner = AdminPanelScanner(target_url)
    admin_results = admin_scanner.scan()
    results.append(admin_results)
    
    # CMS Taraması
    print("\n[*] CMS Zafiyet Taraması Başlatılıyor...")
    cms_scanner = CMSScanner(target_url)
    cms_results = cms_scanner.scan()
    results.append(cms_results)
    
    # SQL Injection Taraması
    print("\n[*] SQL Injection Taraması Başlatılıyor...")
    sql_scanner = SQLInjectionScanner(target_url)
    sql_results = sql_scanner.scan()
    results.append(sql_results)
    
    # XSS Taraması
    print("\n[*] XSS Taraması Başlatılıyor...")
    xss_scanner = XSSScanner(target_url)
    xss_results = xss_scanner.scan()
    results.append(xss_results)
    
    # Dosya Yükleme Taraması
    print("\n[*] Dosya Yükleme Zafiyeti Taraması Başlatılıyor...")
    upload_scanner = FileUploadScanner(target_url)
    upload_results = upload_scanner.scan()
    results.append(upload_results)
    
    # Brute Force Taraması
    print("\n[*] Brute Force Saldırı Testi Başlatılıyor...")
    brute_scanner = BruteForceScanner(target_url)
    brute_results = brute_scanner.scan()
    results.append(brute_results)
    
    # Sonuçları yazdır
    print("\n[+] Tarama Tamamlandı!")
    print("\nSONUÇLAR:")
    print("=" * 80)
    
    for result in results:
        print(f"\n{result['title']}")
        print("-" * 80)
        
        for finding in result['findings']:
            print(f"\nBulgu: {finding['name']}")
            print(f"Risk Seviyesi: {finding['risk_level']}")
            print(f"Açıklama:\n{finding['description']}")
            print(f"Etki: {finding['impact']}")
            print(f"Öneriler:\n{finding['recommendation']}")
            print("-" * 40)
            
    # JSON olarak kaydet
    with open('scan_results.json', 'w', encoding='utf-8') as f:
        json.dump(results, f, ensure_ascii=False, indent=4)
    print(f"\n[+] Sonuçlar scan_results.json dosyasına kaydedildi.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Tarama kullanıcı tarafından durduruldu.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Hata: {str(e)}")
        sys.exit(1) 