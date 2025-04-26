// DOM elementlerini seç
const scanForm = document.getElementById('scanForm');
const selectAllBtn = document.getElementById('selectAllBtn');
const deselectAllBtn = document.getElementById('deselectAllBtn');
const resultsSection = document.getElementById('resultsSection');
const loadingIndicator = document.getElementById('loadingIndicator');
const resultDownload = document.getElementById('resultDownload');
const downloadBtn = document.getElementById('downloadBtn');
const currentScan = document.getElementById('currentScan');
const scanProgress = document.getElementById('scanProgress');
const aboutBtn = document.getElementById('aboutBtn');
const aboutModal = document.getElementById('aboutModal');
const urlInput = document.getElementById('url');
const toastContainer = document.getElementById('toastContainer');

// Tüm checkboxları seç
const checkboxes = document.querySelectorAll('input[name="scan_options"]');

// DOM yüklendikten sonra çalışacak kodlar
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM yüklendi!');
    // Sayfanın yükleme animasyonu
    document.body.classList.add('loaded');
    
    // Bootstrap tooltips'i başlat (Bootstrap yüklenmişse)
    if (typeof bootstrap !== 'undefined') {
        const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
        [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));
    } else {
        console.warn('Bootstrap yüklenmemiş');
    }

    // URL girişi için tooltip
    if (urlInput && typeof bootstrap !== 'undefined') {
        new bootstrap.Tooltip(urlInput, {
            title: 'Hedef web sitesinin tam URL adresini girin (https://hedefsite.com)',
            placement: 'top',
            trigger: 'focus'
        });
    }

    // Hoş geldin bildirimi
    setTimeout(() => {
        showToast('Hoş Geldiniz', 'Cursor Siber Güvenlik Tarama Aracına hoş geldiniz! Taramaya başlamak için bir URL girin.', 'primary');
    }, 1000);

    // Modal yönetimi için Bootstrap modal kullan
    if (aboutModal && aboutBtn && typeof bootstrap !== 'undefined') {
        const bsAboutModal = new bootstrap.Modal(aboutModal);
        
        // Modal açma
        aboutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            bsAboutModal.show();
        });
    }

    // Tümünü Seç butonu işlevi
    if (selectAllBtn && checkboxes.length > 0) {
        selectAllBtn.addEventListener('click', function() {
            checkboxes.forEach(checkbox => {
                checkbox.checked = true;
            });
            showToast('Bilgi', 'Tüm tarama seçenekleri seçildi.', 'info');
        });
    }

    // Tümünü Kaldır butonu işlevi
    if (deselectAllBtn && checkboxes.length > 0) {
        deselectAllBtn.addEventListener('click', function() {
            checkboxes.forEach(checkbox => {
                checkbox.checked = false;
            });
            showToast('Bilgi', 'Tüm tarama seçenekleri kaldırıldı.', 'info');
        });
    }

    // Form gönderildiğinde işlem yap
    if (scanForm) {
        scanForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            // Form doğrulama
            if (!validateForm()) {
                return;
            }

            // Form verilerini al
            const url = urlInput ? urlInput.value.trim() : '';
            
            // Seçilen tarama seçeneklerini topla
            const selectedOptions = [];
            document.querySelectorAll('input[name="scan_options"]:checked').forEach(checkbox => {
                selectedOptions.push(checkbox.id);
            });
            
            if (selectedOptions.length === 0) {
                showToast('Uyarı', 'Lütfen en az bir tarama seçeneği seçin', 'warning');
                return;
            }
            
            try {
                // Tarama işlemini başlat
                const result = await runScanProcess(url, selectedOptions);
                
                // Tarama sonuçlarını görüntüle
                if (typeof displayScanResults === 'function') {
                    displayScanResults(result);
                }
            } catch (error) {
                // Hata durumunda bildirim göster
                showToast('Hata', `Tarama sırasında bir hata oluştu: ${error.message}`, 'danger');
                console.error('Tarama hatası:', error);
            }
        });
    }

    // PDF Rapor indirme işlemi
    if (downloadBtn) {
        downloadBtn.addEventListener('click', function() {
            const url = urlInput ? urlInput.value : 'ornek.com';
            const now = new Date();
            const dateStr = now.toISOString().slice(0, 10);
            const fileName = `siber_guvenlik_raporu_${url.replace(/^https?:\/\//, '').replace(/[^\w]/g, '_')}_${dateStr}.pdf`;
            
            // PDF indirme işlemini simüle et
            showToast('Bilgi', 'PDF Raporu indiriliyor...', 'info');
            
            // PDF blob nesnesini oluştur ve indir
            setTimeout(() => {
                // Boş bir PDF (gerçek uygulamada burada gerçek PDF veri oluşturma kodu olacak)
                const pdfBlob = new Blob(['PDF rapor içeriği burada olacak'], { type: 'application/pdf' });
                const downloadLink = document.createElement('a');
                downloadLink.href = URL.createObjectURL(pdfBlob);
                downloadLink.download = fileName;
                document.body.appendChild(downloadLink);
                downloadLink.click();
                document.body.removeChild(downloadLink);
                
                showToast('Başarılı', 'PDF Raporu başarıyla indirildi!', 'success');
            }, 1500);
        });
    }
});

// Toast bildirimlerini gösterme
function showToast(title, message, type = 'info') {
    if (!toastContainer) return;
    
    const toast = document.createElement('div');
    toast.className = `toast align-items-center border-0 bg-${type}`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    const toastHeader = document.createElement('div');
    toastHeader.className = 'toast-header';
    
    const strongTitle = document.createElement('strong');
    strongTitle.className = 'me-auto';
    strongTitle.textContent = title;
    
    const closeButton = document.createElement('button');
    closeButton.type = 'button';
    closeButton.className = 'btn-close';
    closeButton.setAttribute('data-bs-dismiss', 'toast');
    closeButton.setAttribute('aria-label', 'Kapat');
    
    toastHeader.appendChild(strongTitle);
    toastHeader.appendChild(closeButton);
    
    const toastBody = document.createElement('div');
    toastBody.className = 'toast-body text-white';
    toastBody.textContent = message;
    
    toast.appendChild(toastHeader);
    toast.appendChild(toastBody);
    
    toastContainer.appendChild(toast);
    
    const bsToast = new bootstrap.Toast(toast, {
        autohide: true,
        delay: 4000
    });
    
    bsToast.show();
    
    // 5 saniye sonra toast'u kaldır
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

// URL doğrulama fonksiyonu
function validateForm() {
    // urlInput element kontrolü
    if (!urlInput) {
        showToast('Hata', 'URL giriş alanı bulunamadı', 'danger');
        return false;
    }
    
    const targetUrl = urlInput.value.trim();
    
    // URL kontrolü
    if (!targetUrl) {
        showToast('Hata', 'Lütfen hedef URL giriniz', 'danger');
        return false;
    } 
    
    if (!isValidUrl(targetUrl)) {
        showToast('Hata', 'Lütfen geçerli bir URL giriniz (http:// veya https:// ile başlamalı)', 'danger');
        return false;
    }
    
    // Seçenek kontrolü
    const selectedOptions = document.querySelectorAll('input[name="scan_options"]:checked');
    if (selectedOptions.length === 0) {
        showToast('Uyarı', 'Lütfen en az bir tarama seçeneği seçiniz', 'warning');
        return false;
    }
    
    return true;
}

// URL doğrulama fonksiyonu
function isValidUrl(url) {
    try {
        const urlObj = new URL(url);
        return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
    } catch (e) {
        return false;
    }
}

// Tarama sürecini çalıştırma fonksiyonu
async function runScanProcess(url, options) {
    try {
        // Yükleme göstergesini göster
        if (loadingIndicator) loadingIndicator.style.display = 'block';
        if (resultsSection) resultsSection.style.display = 'none';
        
        // Simüle edilmiş süreç
        await simulateScanProcess(url, options);
        
        // Gerçek tarama işlemi (normalde bir API'ye istek atılır)
        const formData = new FormData();
        formData.append('url', url);
        options.forEach(option => {
            formData.append('scan_options[]', option);
        });
        
        const response = await fetch('/scan', {
            method: 'POST',
            body: formData
        });
        
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || 'Tarama sırasında bir hata oluştu');
        }
        
        const data = await response.json();
        
        // Yükleme göstergesini gizle
        if (loadingIndicator) loadingIndicator.style.display = 'none';
        
        return data;
    } catch (error) {
        console.error('Tarama hatası:', error);
        if (loadingIndicator) loadingIndicator.style.display = 'none';
        throw error;
    }
}

// Tarama işlemini simüle eden fonksiyon
async function simulateScanProcess(url, options) {
    const scanStages = [
        'SSL/TLS güvenlik testi yapılıyor...',
        'Açık port taraması gerçekleştiriliyor...',
        'HTTP güvenlik başlıkları kontrol ediliyor...',
        'SQL Injection testleri yapılıyor...',
        'XSS testleri yapılıyor...',
        'Sunucu bilgi sızıntıları kontrol ediliyor...',
        'Admin panel tespiti yapılıyor...',
        'CMS açıkları taranıyor...',
        'Dosya yükleme zafiyetleri test ediliyor...',
        'Brute force saldırı testi yapılıyor...',
        'Sonuçlar hazırlanıyor ve rapor oluşturuluyor...'
    ];

    // Tarama seçeneklerine göre filtreleme yapalım
    const stagesToRun = scanStages.filter((_, index) => {
        // Tüm seçenekler seçilmediyse ve bu bir seçenek ise
        if (options.length === 0 || (index < options.length && options[index])) {
            return true;
        }
        return false;
    });

    const totalStages = stagesToRun.length;
    
    for (let i = 0; i < totalStages; i++) {
        // Mevcut taramayı güncelle
        updateScanStatus(stagesToRun[i], (i + 1) / totalStages * 100);
        
        // Bu adımın tamamlanması için bekle (gerçek bir tarama için API çağrısı yapılacak)
        await sleep(Math.random() * 1000 + 500); // 500ms - 1.5s arası rastgele bekleme
    }
}

// Tarama durumunu güncelleyen fonksiyon
function updateScanStatus(message, percentage) {
    if (currentScan) {
        currentScan.textContent = message;
    }
    
    if (scanProgress) {
        scanProgress.style.width = `${percentage}%`;
        scanProgress.setAttribute('aria-valuenow', percentage);
    }
}

// Sleep fonksiyonu - asenkron bekleme
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// Sonuçları gösterme fonksiyonu
function displayScanResults(result) {
    if (resultsSection) {
        resultsSection.style.display = 'block';
        
        // Sonuçları DOM'a yerleştir
        const vulnerabilityCountElement = document.getElementById('vulnerabilityCount');
        const securityScoreElement = document.getElementById('securityScore');
        const recommendationsList = document.getElementById('recommendationsList');
        
        if (vulnerabilityCountElement) {
            vulnerabilityCountElement.textContent = result.results?.vulnerabilitiesFound || 0;
        }
        
        if (securityScoreElement) {
            securityScoreElement.textContent = result.results?.securityScore || 0;
        }
        
        if (recommendationsList) {
            recommendationsList.innerHTML = '';
            if (result.results?.recommendations) {
                result.results.recommendations.forEach(recommendation => {
                    const li = document.createElement('li');
                    li.textContent = recommendation;
                    recommendationsList.appendChild(li);
                });
            }
        }
        
        // İndirme linkini etkinleştir
        if (downloadBtn && result.report_url) {
            downloadBtn.href = result.report_url;
            downloadBtn.style.display = 'inline-block';
        }
        
        // Sayfayı sonuçlar bölümüne kaydır
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
}

// Risk seviyesine göre badge sınıfı dön
function getBadgeClass(risk) {
    switch(risk) {
        case 'Düşük': return 'bg-info';
        case 'Orta': return 'bg-warning text-dark';
        case 'Yüksek': return 'bg-danger';
        case 'Kritik': return 'bg-dark';
        default: return 'bg-secondary';
    }
}

// Sayfa tamamen yüklendiğinde body'e loaded class'ı ekle
window.addEventListener('load', () => {
    document.body.classList.add('loaded');
});

// PDF rapor oluştur
function generatePDF(data) {
    // PDF oluşturmak için jsPDF kütüphanesini kullanıyoruz
    // Not: Bu çalışması için HTML'de jsPDF kütüphanesinin dahil edilmesi gerekiyor
    try {
        const { jsPDF } = window.jspdf;
        
        // Yeni bir PDF dokümanı oluştur
        const doc = new jsPDF();
        
        // Başlık ve logo
        doc.setFontSize(22);
        doc.setTextColor(33, 37, 41);
        doc.text('CyberControl Güvenlik Raporu', 105, 20, { align: 'center' });
        
        // Alt başlık
        doc.setFontSize(12);
        doc.setTextColor(108, 117, 125);
        doc.text(`Tarama Tarihi: ${new Date(data.scannedAt).toLocaleString('tr-TR')}`, 105, 30, { align: 'center' });
        
        // Hedef bilgileri
        doc.setFontSize(14);
        doc.setTextColor(33, 37, 41);
        doc.text('Hedef Bilgileri', 20, 45);
        
        doc.setFontSize(11);
        doc.text(`Taranan URL: ${data.url}`, 20, 55);
        doc.text(`Seçilen Tarama Seçenekleri: ${data.options.join(', ')}`, 20, 62);
        
        // Tarama sonuçları
        doc.setFontSize(14);
        doc.setTextColor(33, 37, 41);
        doc.text('Güvenlik Durumu', 20, 80);
        
        // Güvenlik puanı
        doc.setFontSize(11);
        doc.text(`Güvenlik Puanı: ${data.results.securityScore}/100`, 20, 90);
        
        // Bulunan zafiyetler
        doc.text(`Bulunan Zafiyet Sayısı: ${data.results.vulnerabilitiesFound}`, 20, 97);
        
        // Tavsiyeler başlığı
        doc.setFontSize(14);
        doc.setTextColor(33, 37, 41);
        doc.text('Öneriler', 20, 115);
        
        // Öneriler listesi
        doc.setFontSize(11);
        data.results.recommendations.forEach((rec, index) => {
            doc.text(`${index + 1}. ${rec}`, 20, 125 + (index * 7));
        });
        
        // Sayfa altı bilgisi
        doc.setFontSize(9);
        doc.setTextColor(108, 117, 125);
        doc.text('Bu rapor CyberControl tarafından oluşturulmuştur.', 105, 280, { align: 'center' });
        
        // PDF'i indir
        doc.save(`CyberControl_Rapor_${new Date().toISOString().slice(0, 10)}.pdf`);
        
        // Başarı bildirimi göster
        showToast('Başarılı', 'PDF rapor başarıyla indirildi!', 'success');
    } catch (error) {
        console.error('PDF oluşturma hatası:', error);
        showToast('Hata', 'PDF rapor oluşturulurken bir hata oluştu.', 'danger');
    }
}

// PDF rapor oluşturma fonksiyonu
function generatePdfReport(result) {
    // Bu fonksiyonun içeriği, PDF raporunun gerçek oluşturulması için gerekli olan kodları içermelidir.
    // Bu örnekte, PDF raporunun gerçek oluşturulması için jsPDF kullanılmıştır.
    // Gerçek uygulamada, bu fonksiyonun içeriği, PDF raporunun gerçek oluşturulması için gerekli olan kodları içermelidir.
    generatePDF(result);
}

// Event Listeners
document.addEventListener('DOMContentLoaded', function() {
    // Form gönderme olayını dinle
    if (scanForm) {
        scanForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            
            if (!validateForm()) {
                return false;
            }
            
            const url = urlInput.value.trim();
            const selectedOptions = Array.from(document.querySelectorAll('input[name="scan_options"]:checked')).map(opt => opt.value);
            
            // Tarama sürecini başlat
            try {
                const result = await runScanProcess(url, selectedOptions);
                displayScanResults(result);
            } catch (error) {
                console.error('Tarama hatası:', error);
                showToast('Hata', 'Tarama sırasında bir hata oluştu: ' + error.message, 'danger');
            }
        });
    }
    
    // Tüm seçenekleri seç butonu
    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelectorAll('input[name="scan_options"]').forEach(checkbox => {
                checkbox.checked = true;
            });
        });
    }
    
    // Tüm seçimleri kaldır butonu
    if (deselectAllBtn) {
        deselectAllBtn.addEventListener('click', function(e) {
            e.preventDefault();
            document.querySelectorAll('input[name="scan_options"]').forEach(checkbox => {
                checkbox.checked = false;
            });
        });
    }
    
    // Hakkında butonu
    if (aboutBtn && aboutModal) {
        aboutBtn.addEventListener('click', function() {
            const modal = new bootstrap.Modal(aboutModal);
            modal.show();
        });
    }
}); 