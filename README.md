# Siber Güvenlik Tarama Aracı

Bu proje, web uygulamalarında güvenlik testleri yapmak için geliştirilmiş bir araçtır.

## Özellikler

- SSL/TLS Güvenlik Testi
- Açık Port Taraması
- HTTP Güvenlik Header Testi
- SQL Injection Testi
- XSS (Cross Site Scripting) Testi
- Sunucu Bilgi Sızıntısı Testi
- Admin Panel Tespiti
- CMS Zafiyet Taraması
- Dosya Yükleme Zafiyeti Testi
- Brute Force Saldırı Testi

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/yourusername/cybercontrol.git
cd cybercontrol
```

2. Sanal ortam oluşturun ve aktif edin:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Gereksinimleri yükleyin:
```bash
pip install -r requirements.txt
```

4. Uygulamayı çalıştırın:
```bash
python app.py
```

5. Tarayıcınızda http://localhost:5000 adresine gidin

## Kullanım

1. Web arayüzünden taranacak URL'yi girin
2. İstediğiniz tarama seçeneklerini işaretleyin
3. "Taramayı Başlat" butonuna tıklayın
4. Sonuçları bekleyin ve raporu inceleyin

## Güvenlik Notu

Bu araç sadece yetkilendirilmiş sistemlerde test amaçlı kullanılmalıdır. İzinsiz kullanım yasal sorunlara yol açabilir.

## Lisans

MIT License 