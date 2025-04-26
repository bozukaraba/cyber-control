# CyberControl - İleri Seviye Siber Güvenlik Tarama Aracı

CyberControl, web uygulamaları ve sunucular için kapsamlı bir güvenlik tarama aracıdır. Bu araç, siber güvenlik uzmanlarının potansiyel güvenlik açıklarını tespit etmesine yardımcı olmak üzere tasarlanmıştır.

## Özellikler

- **SSL/TLS Güvenlik Testi:** Sertifika geçerliliği ve zayıf şifreleme algoritması kontrolü
- **Açık Port Taraması:** İlk 1000 yaygın portun taranması
- **HTTP Güvenlik Header Testi:** HSTS, CSP, X-Frame-Options kontrolü
- **SQL Injection Testi:** URL parametrelerinde temel ve gelişmiş SQL enjeksiyonu denemeleri
- **XSS (Cross Site Scripting) Testi:** Form alanlarında XSS açıkları kontrolü
- **Sunucu Bilgi Sızıntısı Testi:** Server HTTP Header ve X-Powered-By gibi bilgi sızdıran başlıkların kontrolü
- **Admin Panel Tespiti:** Yaygın admin panel URL'leri taraması
- **CMS Açıkları Taraması:** WordPress, Joomla, vb. CMS sürüm ve eklenti açıklarının kontrolü
- **Dosya Yükleme Zafiyeti Testi:** Upload alanlarına zararlı dosya yükleme denemeleri
- **Brute Force Saldırı Testi:** Kullanıcı adı ve şifre kombinasyonları ile kaba kuvvet saldırısı testi

## Tarama Sonuçları

- Detaylı güvenlik puanı ve risk analizi
- Tespit edilen açıkların risk seviyelerine göre (Kritik, Yüksek, Orta, Düşük) sınıflandırılması
- Her açık için açıklama ve çözüm önerileri
- Profesyonel PDF raporu oluşturma

## Kullanım

1. Hedef web sitesinin URL'sini girin
2. Gerçekleştirmek istediğiniz tarama türlerini seçin
3. "Taramayı Başlat" düğmesine tıklayın
4. Tarama tamamlandığında ayrıntılı sonuçları görüntüleyin
5. PDF raporunu indirin

## Teknik Yapı

- HTML5, CSS3 ve JavaScript ile geliştirilmiş modern ve responsive ön yüz
- Bootstrap 5 ile tasarlanmış kullanıcı arayüzü
- PDF raporları için jsPDF kütüphanesi kullanımı

## Uyarı

Bu araç, **yalnızca güvenlik testi amacıyla, yetkili olduğunuz sistemlerde kullanılmalıdır**. İzinsiz tarama yapmak yasal sorumluluklar doğurabilir.

## Kurulum

Bu araç tamamen tarayıcı tabanlı çalışmaktadır. Kullanmak için:

1. Repo'yu klonlayın: `git clone https://github.com/GITHUB_KULLANICI_ADINIZ/cybercontrol.git`
2. `index.html` dosyasını bir web tarayıcısında açın

## Lisans

MIT 