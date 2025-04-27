// DOM elementlerini tanımla
let scanForm, urlInput, scanProgress, currentScan, loadingIndicator, scanStatusContainer, resultsSection, vulnerabilitiesTable, downloadBtn, aboutModal, aboutBtn, selectAllBtn, deselectAllBtn;

// Tüm checkboxları seç
const checkboxes = document.querySelectorAll('input[name="scan_options"]');

// Tarama durumu
let isScanning = false;

// DOM yüklendikten sonra çalışacak kodlar
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM yüklendi!');
    
    // DOM elementlerini seç
    scanForm = document.getElementById('scanForm');
    urlInput = document.getElementById('targetUrl');
    scanProgress = document.querySelector('.progress-bar');
    currentScan = document.getElementById('currentScan');
    loadingIndicator = document.getElementById('loadingIndicator');
    scanStatusContainer = document.getElementById('scanStatusContainer');
    resultsSection = document.getElementById('resultsSection');
    vulnerabilitiesTable = document.getElementById('vulnerabilitiesTable');
    downloadBtn = document.getElementById('downloadBtn');
    aboutModal = document.getElementById('aboutModal');
    aboutBtn = document.getElementById('aboutBtn');
    selectAllBtn = document.getElementById('selectAllBtn');
    deselectAllBtn = document.getElementById('deselectAllBtn');
    
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
    
    // Form gönderildiğinde işlem yap
    if (scanForm) {
        scanForm.addEventListener('submit', async function(e) {
            e.preventDefault(); // Sayfanın yenilenmesini engelle
            
            // URL kontrolü
            const url = urlInput.value.trim();
            if (!url) {
                showToast('Hata', 'Lütfen hedef URL giriniz', 'error');
                return;
            }
            
            try {
                // URL formatını kontrol et
                new URL(url);
            } catch {
                showToast('Hata', 'Lütfen geçerli bir URL giriniz', 'error');
                return;
            }
            
            // Seçili testleri al
            const selectedTests = {
                ssl: document.getElementById('sslCheck')?.checked || false,
                port: document.getElementById('portCheck')?.checked || false,
                header: document.getElementById('headerCheck')?.checked || false,
                sql: document.getElementById('sqlCheck')?.checked || false,
                xss: document.getElementById('xssCheck')?.checked || false,
                info: document.getElementById('infoCheck')?.checked || false,
                admin: document.getElementById('adminCheck')?.checked || false,
                cms: document.getElementById('cmsCheck')?.checked || false,
                upload: document.getElementById('uploadCheck')?.checked || false,
                brute: document.getElementById('bruteCheck')?.checked || false
            };
            
            // En az bir test seçili mi kontrol et
            if (!Object.values(selectedTests).some(Boolean)) {
                showToast('Uyarı', 'Lütfen en az bir tarama seçeneği seçiniz', 'warning');
                return;
            }

            try {
                // Tarama modalını göster
                const scanModal = new bootstrap.Modal(document.getElementById('scanModal'));
                scanModal.show();
                
                // Progress bar'ı sıfırla
                const progressBar = document.querySelector('.progress-bar');
                if (progressBar) {
                    progressBar.style.width = '0%';
                    progressBar.setAttribute('aria-valuenow', '0');
                }
                
                // Seçili testleri sırayla çalıştır
                let progress = 0;
                const selectedTestCount = Object.values(selectedTests).filter(Boolean).length;
                const increment = 100 / selectedTestCount;
                
                for (const [test, isSelected] of Object.entries(selectedTests)) {
                    if (isSelected) {
                        // Test durumunu güncelle
                        const currentTest = document.getElementById('currentTest');
                        if (currentTest) {
                            currentTest.textContent = getTestName(test);
                        }
                        
                        // Test simülasyonu
                        await simulateTest(test, url);
                        
                        // Progress bar'ı güncelle
                        progress += increment;
                        if (progressBar) {
                            progressBar.style.width = `${progress}%`;
                            progressBar.setAttribute('aria-valuenow', progress);
                        }
                    }
                }
                
                // Taramayı tamamla
                setTimeout(() => {
                    scanModal.hide();
                    showResults();
                }, 1000);
                
            } catch (error) {
                console.error('Tarama hatası:', error);
                showToast('Hata', 'Tarama sırasında bir hata oluştu', 'error');
            }
        });
    }
    
    // PDF Rapor indirme işlemi
    if (downloadBtn) {
        downloadBtn.addEventListener('click', generatePDFReport);
    }
    
    // Tümünü Seç butonu işlevi
    if (selectAllBtn) {
        selectAllBtn.addEventListener('click', selectAllCheckboxes);
    }
    
    // Tümünü Kaldır butonu işlevi
    if (deselectAllBtn) {
        deselectAllBtn.addEventListener('click', deselectAllCheckboxes);
    }
    
    // Modal yönetimi için Bootstrap modal kullan
    if (aboutModal && aboutBtn && typeof bootstrap !== 'undefined') {
        const bsAboutModal = new bootstrap.Modal(aboutModal);
        
        // Modal açma
        aboutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            bsAboutModal.show();
        });
    }

    // Hoş geldin bildirimi
    setTimeout(() => {
        showToast('Hoş Geldiniz', 'Siber Güvenlik Tarama Aracına hoş geldiniz! Taramaya başlamak için bir URL girin.', 'info');
    }, 1000);

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

    // Bootstrap tooltip'leri aktifleştir
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Bootstrap popover'ları aktifleştir
    const popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
});

// Test adını döndür
function getTestName(test) {
    const names = {
        ssl: 'SSL/TLS Güvenlik Testi',
        port: 'Açık Port Taraması',
        header: 'HTTP Güvenlik Header Testi',
        sql: 'SQL Injection Testi',
        xss: 'XSS Testi',
        info: 'Sunucu Bilgi Sızıntısı Testi',
        admin: 'Admin Panel Tespiti',
        cms: 'CMS Zafiyet Taraması',
        upload: 'Dosya Yükleme Zafiyeti Testi',
        brute: 'Brute Force Saldırı Testi'
    };
    return names[test] || test;
}

// Test simülasyonu
async function simulateTest(test, url) {
    return new Promise(resolve => {
        setTimeout(resolve, Math.random() * 1000 + 500);
    });
}

// Sonuçları göster
function showResults() {
    const resultModal = new bootstrap.Modal(document.getElementById('resultModal'));
    
    const results = [
        {
            test: 'SSL/TLS Güvenlik Testi',
            status: 'Güvenli',
            details: 'SSL sertifikası geçerli ve güncel.'
        },
        {
            test: 'Açık Port Taraması',
            status: 'Uyarı',
            details: '80 ve 443 portları dışında açık port tespit edilmedi.'
        },
        {
            test: 'HTTP Güvenlik Header Testi',
            status: 'Uyarı',
            details: 'X-Frame-Options ve CSP başlıkları eksik.'
        }
    ];
    
    const resultsHtml = results.map(result => `
        <div class="alert ${result.status === 'Güvenli' ? 'alert-success' : 'alert-warning'} mb-3">
            <h5 class="alert-heading">${result.test}</h5>
            <p class="mb-0">${result.details}</p>
        </div>
    `).join('');
    
    const scanResults = document.getElementById('scanResults');
    if (scanResults) {
        scanResults.innerHTML = resultsHtml;
        resultModal.show();
    }
}

// Toast mesajı göster
function showToast(title, message, type) {
    let container = document.getElementById('toastContainer');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toastContainer';
        container.className = 'toast-container position-fixed top-0 end-0 p-3';
        document.body.appendChild(container);
    }
    
    const toastHtml = `
        <div class="toast align-items-center text-white bg-${type === 'error' ? 'danger' : type} border-0" 
             role="alert" aria-live="assertive" aria-atomic="true" data-bs-delay="3000">
            <div class="d-flex">
                <div class="toast-body">
                    <strong>${title}</strong><br>${message}
                </div>
                <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
            </div>
        </div>
    `;
    
    container.insertAdjacentHTML('beforeend', toastHtml);
    const toastElement = container.lastElementChild;
    const toast = new bootstrap.Toast(toastElement);
    toast.show();
    
    toastElement.addEventListener('hidden.bs.toast', () => {
        toastElement.remove();
    });
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
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch (_) {
        return false;
    }
}

// Tarama işlemini çalıştırma fonksiyonu
async function runScanProcess(url, options) {
    try {
        // Yükleme göstergesini göster
        if (loadingIndicator) loadingIndicator.style.display = 'block';
        if (resultsSection) resultsSection.style.display = 'none';
        
        // Simüle edilmiş süreç
        const result = await simulateScanProcess(url, options);
        
        // API çağrısı
        const response = await fetch('/.netlify/functions/scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                targetUrl: url,
                scanOptions: options
            })
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

// Tarama işlemini simüle et
function simulateScanProcess(url, selectedTests) {
    // Tarama modalını göster
    const scanModal = document.getElementById('scanModal');
    if (scanModal) {
        scanModal.classList.remove('d-none');
    }
    
    // Progress bar ve durum bilgisi elementleri
    const progressBar = document.querySelector('.progress-bar');
    const scanStatus = document.getElementById('scanStatus');
    const scanStep = document.getElementById('scanStep');
    
    if (progressBar) {
        progressBar.style.width = '0%';
        progressBar.classList.add('progress-bar-animated');
    }
    
    if (scanStatus) {
        scanStatus.textContent = 'Hazırlanıyor...';
    }
    
    if (scanStep) {
        scanStep.textContent = 'Hedef URL analiz ediliyor';
    }
    
    // Adım 1
    setTimeout(() => {
        updateScanStatus(1);
        
        // Adım 2
        setTimeout(() => {
            updateScanStatus(2);
            
            // Adım 3
            setTimeout(() => {
                updateScanStatus(3);
                
                // Adım 4
                setTimeout(() => {
                    updateScanStatus(4);
                    
                    // Adım 5
                    setTimeout(() => {
                        updateScanStatus(5);
                        
                        // Adım 6
                        setTimeout(() => {
                            updateScanStatus(6);
                        }, 2000);
                    }, 2500);
                }, 2000);
            }, 2500);
        }, 2000);
    }, 1500);
}

// Tarama durumunu güncelle
function updateScanStatus(step, isError = false) {
    // Progress bar ve durum bilgisi elementleri
    const progressBar = document.querySelector('.progress-bar');
    const scanStatus = document.getElementById('scanStatus');
    const scanStep = document.getElementById('scanStep');
    const scanModal = document.getElementById('scanModal');
    const resultsSection = document.getElementById('resultsSection');
    
    // Progress bar'ı güncelle
    if (!isError) {
        switch (step) {
            case 1: // Başlangıç
                progressBar.style.width = '10%';
                scanStatus.textContent = 'Tarama başlatılıyor...';
                scanStep.textContent = 'Başlangıç kontrolleri yapılıyor';
                break;
            case 2: // Port tarama
                progressBar.style.width = '25%';
                scanStatus.textContent = 'Devam ediyor...';
                scanStep.textContent = 'Açık portlar taranıyor';
                break;
            case 3: // Servis tarama
                progressBar.style.width = '40%';
                scanStatus.textContent = 'Devam ediyor...';
                scanStep.textContent = 'Servis ve sürüm bilgileri tespit ediliyor';
                break;
            case 4: // Güvenlik başlıkları kontrolü
                progressBar.style.width = '60%';
                scanStatus.textContent = 'Devam ediyor...';
                scanStep.textContent = 'HTTP güvenlik başlıkları kontrol ediliyor';
                break;
            case 5: // Zafiyet tarama
                progressBar.style.width = '80%';
                scanStatus.textContent = 'Devam ediyor...';
                scanStep.textContent = 'Web uygulama zafiyetleri taranıyor';
                break;
            case 6: // Tamamlandı
                progressBar.style.width = '100%';
                progressBar.classList.remove('progress-bar-animated');
                scanStatus.textContent = 'Tamamlandı';
                scanStep.textContent = 'Tarama tamamlandı, sonuçlar hazırlanıyor...';
                
                // Tarama modalini gizle
                setTimeout(() => {
                    scanModal.classList.add('d-none');
                    resultsSection.classList.remove('d-none');
                    
                    // Zafiyet tablosunu doldur
                    fillVulnerabilitiesTable();
                    
                    // Raporlama butonunu aktif et
                    const reportBtn = document.getElementById('generateReportBtn');
                    if (reportBtn) {
                        reportBtn.classList.remove('disabled');
                    }
                    
                    // Başarılı tarama mesajı göster
                    showToast('Başarılı', 'Siber güvenlik taraması tamamlandı. Sonuçlar aşağıda listelenmektedir.', 'success');
                }, 1000);
                break;
        }
    } else {
        // Hata durumu
        progressBar.style.width = '100%';
        progressBar.classList.remove('progress-bar-animated', 'bg-primary');
        progressBar.classList.add('bg-danger');
        scanStatus.textContent = 'Hata';
        scanStep.textContent = 'Tarama sırasında bir hata oluştu. Lütfen tekrar deneyin.';
        
        // Hata toast mesajı göster
        showToast('Hata', 'Tarama sırasında bir hata oluştu. Lütfen tekrar deneyin.', 'danger');
    }
}

// Zafiyet tablosunu doldur
function fillVulnerabilitiesTable() {
    const tbody = document.querySelector('#vulnerabilitiesTable tbody');
    if (!tbody) return;
    
    // Tabloyu temizle
    tbody.innerHTML = '';
    
    // Örnek zafiyet verileri
    const vulnerabilities = [
        {
            id: 1,
            name: 'SSL/TLS Zayıf Şifreleme',
            severity: 'Yüksek',
            description: 'Sunucu, eskimiş ve güvenli olmayan SSL/TLS şifreleme algoritmalarını destekliyor.',
            remediation: 'Sunucu yapılandırmasını güncelleyin ve yalnızca güçlü şifreleme algoritmalarını (TLS 1.2+) etkinleştirin.'
        },
        {
            id: 2,
            name: 'X-Frame-Options Header Eksik',
            severity: 'Orta',
            description: 'X-Frame-Options HTTP başlığı eksik, bu durum clickjacking saldırılarına karşı savunmasızlığa neden olabilir.',
            remediation: 'X-Frame-Options: DENY veya X-Frame-Options: SAMEORIGIN header\'ını ekleyin.'
        },
        {
            id: 3,
            name: 'HTTP Strict Transport Security (HSTS) Eksik',
            severity: 'Orta',
            description: 'HSTS politikası yapılandırılmamış, bu durum HTTPS downgrade saldırılarına karşı savunmasızlığa neden olabilir.',
            remediation: 'Strict-Transport-Security header\'ını ekleyin ve uygun maksimum yaş değerini ayarlayın.'
        },
        {
            id: 4,
            name: 'Admin Panel Tespit Edildi',
            severity: 'Düşük',
            description: 'Standart admin panel yolu (/admin) tespit edildi. Bu, potansiyel saldırganlar için hedef olabilir.',
            remediation: 'Admin panel yolunu değiştirin ve IP bazlı erişim kısıtlamaları uygulayın.'
        },
        {
            id: 5,
            name: 'Server Header Bilgisi Sızıntısı',
            severity: 'Düşük',
            description: 'Server HTTP başlığı, sunucu yazılımı ve sürüm bilgilerini açığa çıkarıyor.',
            remediation: 'Server HTTP başlığını kaldırın veya değiştirin, özel bir değerle değiştirin.'
        }
    ];
    
    // Risk seviyesi renklerini tanımla
    const severityColors = {
        'Kritik': 'danger',
        'Yüksek': 'danger',
        'Orta': 'warning',
        'Düşük': 'info',
        'Bilgi': 'primary'
    };
    
    // Her bir zafiyet için tablo satırı oluştur
    vulnerabilities.forEach(vuln => {
        const tr = document.createElement('tr');
        
        const severityColor = severityColors[vuln.severity] || 'secondary';
        
        tr.innerHTML = `
            <td>${vuln.id}</td>
            <td>${vuln.name}</td>
            <td><span class="badge bg-${severityColor}">${vuln.severity}</span></td>
            <td>
                <button class="btn btn-sm btn-info" type="button" data-bs-toggle="collapse" 
                    data-bs-target="#vulnDetails${vuln.id}" aria-expanded="false">
                    Detaylar
                </button>
            </td>
        `;
        
        tbody.appendChild(tr);
        
        // Detay satırı
        const detailRow = document.createElement('tr');
        detailRow.className = 'collapse-row';
        
        detailRow.innerHTML = `
            <td colspan="4" class="p-0">
                <div class="collapse" id="vulnDetails${vuln.id}">
                    <div class="card card-body">
                        <h5>Açıklama</h5>
                        <p>${vuln.description}</p>
                        <h5>Çözüm Önerisi</h5>
                        <p>${vuln.remediation}</p>
                    </div>
                </div>
            </td>
        `;
        
        tbody.appendChild(detailRow);
    });
    
    // Sonuç sayısını güncelle
    const vulnCount = document.getElementById('vulnCount');
    if (vulnCount) {
        vulnCount.textContent = vulnerabilities.length;
    }
    
    // Risk dağılımı çubuğunu güncelle
    updateRiskDistribution(vulnerabilities);
}

// Risk dağılımı çubuğunu güncelle
function updateRiskDistribution(vulnerabilities) {
    // Risk seviyelerine göre sayıları hesapla
    const counts = {
        'Kritik': 0,
        'Yüksek': 0,
        'Orta': 0,
        'Düşük': 0,
        'Bilgi': 0
    };
    
    vulnerabilities.forEach(vuln => {
        if (counts[vuln.severity] !== undefined) {
            counts[vuln.severity]++;
        }
    });
    
    // Progress barları güncelle
    const criticalBar = document.getElementById('criticalRiskBar');
    const highBar = document.getElementById('highRiskBar');
    const mediumBar = document.getElementById('mediumRiskBar');
    const lowBar = document.getElementById('lowRiskBar');
    const infoBar = document.getElementById('infoRiskBar');
    
    if (criticalBar) criticalBar.style.width = `${(counts['Kritik'] / vulnerabilities.length) * 100}%`;
    if (highBar) highBar.style.width = `${(counts['Yüksek'] / vulnerabilities.length) * 100}%`;
    if (mediumBar) mediumBar.style.width = `${(counts['Orta'] / vulnerabilities.length) * 100}%`;
    if (lowBar) lowBar.style.width = `${(counts['Düşük'] / vulnerabilities.length) * 100}%`;
    if (infoBar) infoBar.style.width = `${(counts['Bilgi'] / vulnerabilities.length) * 100}%`;
    
    // Sayıları güncelle
    document.querySelectorAll('[data-risk-count]').forEach(element => {
        const riskLevel = element.getAttribute('data-risk-count');
        if (counts[riskLevel] !== undefined) {
            element.textContent = counts[riskLevel];
        }
    });
}

// PDF raporu oluştur
function generatePDFReport() {
    showToast('Bilgi', 'PDF raporu hazırlanıyor...', 'primary');
    
    // PDF rapor oluşturma kodları buraya gelecek
    // Gerçek bir uygulamada, sunucudan rapor alınabilir veya jsPDF gibi bir kütüphane kullanılabilir
    
    setTimeout(() => {
        showToast('Başarılı', 'PDF raporu başarıyla oluşturuldu. İndirme başlayacak.', 'success');
        
        // Gerçek bir dosya indirme mantığı buraya gelecek
        // Bu örnek için sadece simülasyon yapıyoruz
    }, 2000);
}

// Spesifik tarama türü için tarama gerçekleştir
async function scanFunction(url, scanType) {
    // Gerçek uygulamada burada API istekleri olacak
    // Şimdilik demo için simüle ediyoruz
    
    // SSL/TLS Güvenlik Testi
    if (scanType === 'ssl') {
        await sleep(Math.random() * 1000 + 1500); // SSL kontrolü simülasyonu
        
        // Daha gerçekçi test verileri üretelim
        const usesHTTPS = url.startsWith('https://');
        const hasValidCert = usesHTTPS && Math.random() > 0.2;
        const vulnerabilities = [];
        
        if (!usesHTTPS) {
            vulnerabilities.push({
                name: 'HTTPS Kullanılmıyor',
                description: 'Web sitesi, şifrelenmiş bağlantı (HTTPS) kullanmıyor.',
                severity: 'Yüksek',
                recommendation: 'Web sitenizi HTTPS protokolünü kullanacak şekilde yapılandırın ve SSL sertifikası edinin.'
            });
        } else if (!hasValidCert) {
            vulnerabilities.push({
                name: 'Geçersiz SSL Sertifikası',
                description: 'SSL sertifikası geçerli değil veya süresi dolmuş.',
                severity: 'Yüksek',
                recommendation: 'Geçerli bir SSL sertifikası edinin ve düzenli olarak yenileyin.'
            });
        }
        
        // TLS versiyonu kontrolü
        if (Math.random() > 0.7) {
            vulnerabilities.push({
                name: 'Zayıf SSL/TLS Protokol Desteği',
                description: 'Sunucu, güvenli olmayan TLS 1.0/1.1 protokollerini destekliyor.',
                severity: 'Orta',
                recommendation: 'Sunucunuzu TLS 1.2 ve üzeri protokollerini kullanacak şekilde yapılandırın ve eski protokolleri devre dışı bırakın.'
            });
        }
        
        // Zayıf şifreleme algoritmaları
        if (Math.random() > 0.6) {
            vulnerabilities.push({
                name: 'Zayıf Şifreleme Algoritmaları',
                description: 'Sunucu, DES, RC4 gibi güvenli olmayan şifreleme algoritmalarını destekliyor.',
                severity: 'Kritik',
                recommendation: 'Güvenli şifreleme algoritmaları (AES-256, ChaCha20) kullanacak şekilde yapılandırın.'
            });
        }
        
        // Heartbleed açığı
        if (Math.random() > 0.9) {
            vulnerabilities.push({
                name: 'Heartbleed (CVE-2014-0160) Açığı',
                description: 'OpenSSL Heartbleed açığı tespit edildi. Bu açık, bellek sızıntısına yol açabilir.',
                severity: 'Kritik',
                recommendation: 'OpenSSL yazılımını en son sürüme güncelleyin ve tüm SSL sertifikalarını yenileyin.'
            });
        }
        
        return {
            usesHTTPS,
            hasValidCert,
            vulnerabilities,
            tlsVersion: usesHTTPS ? (Math.random() > 0.7 ? 'TLSv1.0/1.1' : 'TLSv1.2/1.3') : 'N/A'
        };
    }
    
    // Port Tarama
    else if (scanType === 'port') {
        await sleep(Math.random() * 2000 + 2000); // Port taraması simülasyonu
        
        const commonPorts = [
            { number: 21, service: 'FTP', danger: Math.floor(Math.random() * 5) + 1 },
            { number: 22, service: 'SSH', danger: Math.floor(Math.random() * 3) + 1 },
            { number: 23, service: 'Telnet', danger: Math.floor(Math.random() * 2) + 4 },
            { number: 25, service: 'SMTP', danger: Math.floor(Math.random() * 3) + 2 },
            { number: 53, service: 'DNS', danger: Math.floor(Math.random() * 3) + 1 },
            { number: 80, service: 'HTTP', danger: Math.floor(Math.random() * 3) + 2 },
            { number: 443, service: 'HTTPS', danger: Math.floor(Math.random() * 2) + 1 },
            { number: 445, service: 'SMB', danger: Math.floor(Math.random() * 2) + 3 },
            { number: 3306, service: 'MySQL', danger: Math.floor(Math.random() * 3) + 2 },
            { number: 3389, service: 'RDP', danger: Math.floor(Math.random() * 2) + 3 },
            { number: 8080, service: 'HTTP-Proxy', danger: Math.floor(Math.random() * 3) + 2 }
        ];
        
        // Rastgele 3-7 portu açık olarak seç
        const openPortCount = Math.floor(Math.random() * 5) + 3;
        const shuffled = commonPorts.sort(() => 0.5 - Math.random());
        const openPorts = shuffled.slice(0, openPortCount);
        
        const vulnerabilities = [];
        
        // Tehlikeli portlar için zafiyet ekle
        openPorts.forEach(port => {
            if (port.danger >= 4) { // Yüksek tehlikeli portlar
                let severity = port.danger === 5 ? 'Kritik' : 'Yüksek';
                let portDesc = '';
                
                switch(port.service) {
                    case 'Telnet':
                        portDesc = 'Telnet şifresiz bağlantı sağlar ve tüm veri düz metin olarak iletilir.';
                        break;
                    case 'FTP':
                        portDesc = 'FTP protokolü, kimlik bilgilerini şifrelenmemiş şekilde iletebilir.';
                        break;
                    case 'SMB':
                        portDesc = 'SMB protokolü uzaktan kod çalıştırma açıkları taşıyabilir (ör. EternalBlue).';
                        break;
                    case 'RDP':
                        portDesc = 'RDP protokolü brute force saldırılarına ve uzaktan kod çalıştırma açıklarına karşı savunmasız olabilir.';
                        break;
                    default:
                        portDesc = `${port.service} portu açık ve potansiyel güvenlik riski taşıyor.`;
                }
                
                vulnerabilities.push({
                    name: `Açık ${port.service} Portu (${port.number})`,
                    description: portDesc,
                    severity: severity,
                    recommendation: `${port.number} portunu kapatın veya sadece güvenilir IP adreslerine erişim izni verin.`
                });
            }
        });
        
        return {
            openPorts,
            vulnerabilities,
            scannedPortCount: 1000 // İlk 1000 port
        };
    }
    
    // HTTP Güvenlik Header'ları
    else if (scanType === 'http_headers') {
        await sleep(Math.random() * 1500 + 1000); // HTTP header kontrolü
        
        const headers = {
            'X-Frame-Options': Math.random() > 0.4,
            'Content-Security-Policy': Math.random() > 0.6,
            'X-XSS-Protection': Math.random() > 0.5,
            'X-Content-Type-Options': Math.random() > 0.4,
            'Strict-Transport-Security': Math.random() > 0.7,
            'Public-Key-Pins': Math.random() > 0.8,
            'Referrer-Policy': Math.random() > 0.5
        };
        
        const vulnerabilities = [];
        
        // Eksik header'lar için zafiyet ekle
        if (!headers['X-Frame-Options']) {
            vulnerabilities.push({
                name: 'X-Frame-Options Header Eksik',
                description: 'X-Frame-Options header eksikliği clickjacking saldırılarına olanak sağlar.',
                severity: 'Orta',
                recommendation: 'X-Frame-Options: DENY veya SAMEORIGIN header ekleyin.'
            });
        }
        
        if (!headers['Content-Security-Policy']) {
            vulnerabilities.push({
                name: 'Content-Security-Policy Header Eksik',
                description: 'CSP eksikliği XSS saldırılarının etki alanını genişletir.',
                severity: 'Yüksek',
                recommendation: 'Güvenli bir Content-Security-Policy header tanımlayın.'
            });
        }
        
        if (!headers['X-XSS-Protection']) {
            vulnerabilities.push({
                name: 'X-XSS-Protection Header Eksik',
                description: 'XSS koruması için tarayıcı mekanizmaları etkinleştirilmemiş.',
                severity: 'Orta',
                recommendation: 'X-XSS-Protection: 1; mode=block header ekleyin.'
            });
        }
        
        if (!headers['Strict-Transport-Security']) {
            vulnerabilities.push({
                name: 'HSTS Header Eksik',
                description: 'HSTS eksikliği SSL stripping saldırılarına olanak sağlar.',
                severity: 'Yüksek',
                recommendation: 'Strict-Transport-Security header ekleyin ve max-age değerini en az 1 yıl olarak ayarlayın.'
            });
        }
        
        return {
            headers,
            vulnerabilities
        };
    }
    
    // Geri kalan tarama türleri için benzer işlevleri ekleyin
    // ... existing code ...
    
    // Analiz
    else if (scanType === 'analyzing') {
        await sleep(Math.random() * 1000 + 2000);
        return {
            analyzed: true
        };
    }
    
    return {}; // Varsayılan sonuç
}

// Taramayı bitir ve sonuçları göster
function finishScan() {
    isScanning = false;
    
    // İlerleme çubuğunu 100% yap
    updateScanStatus('Tarama tamamlandı!', 100);
    
    // Sonuçları göster
    setTimeout(() => {
        // Yükleme göstergesini gizle
        loadingIndicator.style.display = 'none';
        
        // Sonuç sayfasını hazırla
        fillVulnerabilitiesTable();
        
        // Sonuçlar bölümünü göster
        const resultsSection = document.getElementById('resultsSection');
        if (resultsSection) {
            resultsSection.style.display = 'block';
            resultsSection.scrollIntoView({ behavior: 'smooth' });
        }
        
        // Sonuç indirme butonunu göster
        resultDownload.style.display = 'block';
        
        // Başarı mesajı göster
        showToast('Başarılı', 'Tarama tamamlandı! Sonuçlar hazırlandı.', 'success');
    }, 1000);
}

// Tüm checkboxları seç
function selectAllCheckboxes() {
    document.querySelectorAll('input[name="scan_options"]').forEach(checkbox => {
        checkbox.checked = true;
    });
}

// Tüm checkbox seçimlerini kaldır
function deselectAllCheckboxes() {
    document.querySelectorAll('input[name="scan_options"]').forEach(checkbox => {
        checkbox.checked = false;
    });
}

// İlerleme çubuğunu güncelle
function updateProgressBar(value) {
    const percent = Math.round(value);
    scanProgress.style.width = `${percent}%`;
    scanProgress.setAttribute('aria-valuenow', percent);
    scanProgress.textContent = `${percent}%`;
}

// Tarama durumunu güncelle ve loglama yap
function updateScanStatus(testName, status, type) {
    // Status log container
    const scanLog = document.getElementById('scanLog');
    if (!scanLog) return;
    
    // Log class türünü belirle
    const logClass = {
        'info': 'text-info',
        'success': 'text-success',
        'warning': 'text-warning',
        'error': 'text-danger'
    }[type] || 'text-muted';
    
    // Timestamp
    const now = new Date();
    const timestamp = now.toLocaleTimeString('tr-TR');
    
    // Log mesajı oluştur
    const logItem = document.createElement('div');
    logItem.classList.add('scan-log-item', 'mb-2');
    logItem.innerHTML = `
        <span class="text-muted">[${timestamp}]</span>
        <span class="${logClass}"><i class="bi bi-arrow-right-circle me-1"></i>${testName} ${status}</span>
    `;
    
    // Loga ekle
    scanLog.appendChild(logItem);
    
    // Otomatik scroll
    scanLog.scrollTop = scanLog.scrollHeight;
}

// Taramayı tamamla
function completeScan() {
    // İlerleme çubuğunu %100 yap
    updateProgressBar(100);
    
    // UI güncelle
    loadingIndicator.classList.add('d-none');
    isScanning = false;
    
    // Tamamlandı mesajı göster
    updateScanStatus('Tüm tarama testleri', 'tamamlandı', 'success');
    showToast('Başarılı', 'Güvenlik taraması başarıyla tamamlandı!', 'success');
    
    // Sonuçları göster
    setTimeout(() => {
        // Zafiyet tablosunu doldur
        fillVulnerabilitiesTable();
        
        // Sonuçlar bölümünü göster
        resultsSection.classList.remove('d-none');
        
        // Sayfayı sonuçlara kaydır
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }, 1000);
}

// Sleep fonksiyonu - asenkron bekleme
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
} 