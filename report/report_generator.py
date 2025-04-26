import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.platypus.flowables import HRFlowable
from reportlab.graphics.shapes import Drawing
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics.charts.barcharts import VerticalBarChart
import matplotlib.pyplot as plt
import io

class ReportGenerator:
    def __init__(self, target_url, scan_results):
        self.target_url = target_url
        self.scan_results = scan_results
        self.scan_date = scan_results["scan_date"]
        self.report_dir = os.path.join(os.getcwd(), 'reports')
        os.makedirs(self.report_dir, exist_ok=True)
        self.filename = f"security_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        self.report_path = os.path.join(self.report_dir, self.filename)
        
        # Stil ayarları
        self.styles = getSampleStyleSheet()
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=18,
            spaceAfter=12,
            textColor=colors.darkblue
        ))
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceAfter=8,
            textColor=colors.darkblue
        ))
        self.styles.add(ParagraphStyle(
            name='TableHeader',
            parent=self.styles['Normal'],
            fontSize=10,
            textColor=colors.white,
            alignment=1  # center
        ))
        self.styles.add(ParagraphStyle(
            name='RiskHigh',
            parent=self.styles['Normal'],
            textColor=colors.red
        ))
        self.styles.add(ParagraphStyle(
            name='RiskMedium',
            parent=self.styles['Normal'],
            textColor=colors.orange
        ))
        self.styles.add(ParagraphStyle(
            name='RiskLow',
            parent=self.styles['Normal'],
            textColor=colors.green
        ))
        
    def generate_pdf(self):
        """PDF raporu oluşturur ve dosya yolunu döndürür"""
        document = SimpleDocTemplate(
            self.report_path,
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=72
        )
        
        # Rapor içeriğini oluştur
        story = []
        
        # Kapak sayfası
        self._add_cover_page(story)
        
        # İçindekiler
        self._add_table_of_contents(story)
        
        # Tarama özeti
        self._add_scan_summary(story)
        
        # Risk dağılımı grafiği
        self._add_risk_chart(story)
        
        # Her test için detaylı sonuçlar
        self._add_detailed_results(story)
        
        # Sonuç ve öneriler
        self._add_conclusion(story)
        
        # PDF oluştur
        document.build(story)
        
        return self.report_path
        
    def _add_cover_page(self, story):
        """Kapak sayfası oluştur"""
        # Logo veya başlık
        title = Paragraph("Cursor Güvenlik Taraması Raporu", self.styles['Title'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Hedef URL
        target_text = Paragraph(f"<b>Hedef URL:</b> {self.target_url}", self.styles['Normal'])
        story.append(target_text)
        story.append(Spacer(1, 10))
        
        # Tarama tarihi
        date_text = Paragraph(f"<b>Tarama Tarihi:</b> {self.scan_date}", self.styles['Normal'])
        story.append(date_text)
        story.append(Spacer(1, 10))
        
        # Oluşturulma tarihi
        generated_text = Paragraph(f"<b>Rapor Oluşturulma Tarihi:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", self.styles['Normal'])
        story.append(generated_text)
        
        story.append(Spacer(1, 40))
        
        # Bilgilendirme notu
        note = Paragraph(
            "<i>Bu rapor, belirtilen URL'ye yönelik otomatik güvenlik tarama sonuçlarını içermektedir. "
            "Raporda yer alan bulgular, etik ilkeler çerçevesinde yalnızca "
            "güvenlik zaafiyetlerinin tespiti ve düzeltilmesi amacıyla kullanılmalıdır.</i>",
            self.styles['Italic']
        )
        story.append(note)
        
        story.append(PageBreak())
        
    def _add_table_of_contents(self, story):
        """İçindekiler oluştur"""
        title = Paragraph("İçindekiler", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        toc_data = [
            ["1. Tarama Özeti", "3"],
            ["2. Risk Dağılımı", "4"],
            ["3. Detaylı Test Sonuçları", "5"],
        ]
        
        # Detaylı testler için içindekiler
        test_index = 3.1
        line_index = 3
        for module_name, results in self.scan_results["scan_results"].items():
            toc_data.append([f"   {test_index} {results['title']}", f"{line_index + 2}"])
            test_index += 0.1
            line_index += 1
            
        toc_data.append(["4. Sonuç ve Öneriler", f"{line_index + 3}"])
        
        toc_table = Table(toc_data, colWidths=[350, 50])
        toc_table.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.5, colors.white),
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 10),
            ('ALIGN', (1, 0), (1, -1), 'RIGHT'),
        ]))
        
        story.append(toc_table)
        story.append(PageBreak())
        
    def _add_scan_summary(self, story):
        """Tarama özeti oluştur"""
        title = Paragraph("1. Tarama Özeti", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Risk sayılarını hesapla
        risk_counts = self._count_risks()
        total_findings = sum(risk_counts.values())
        
        # Özet metni
        summary_text = f"""
        Bu rapor, <b>{self.target_url}</b> adresine yönelik kapsamlı bir siber güvenlik taraması sonuçlarını 
        içermektedir. Tarama tarihinde ({self.scan_date}) gerçekleştirilen test sonuçlarına göre:
        <br/><br/>
        Toplam <b>{total_findings}</b> güvenlik bulgusu tespit edilmiştir:
        <br/><br/>
        - <b>Kritik</b> seviye bulgular: <font color="red">{risk_counts.get('Kritik', 0)}</font>
        <br/>
        - <b>Yüksek</b> seviye bulgular: <font color="red">{risk_counts.get('Yüksek', 0)}</font>
        <br/>
        - <b>Orta</b> seviye bulgular: <font color="orange">{risk_counts.get('Orta', 0)}</font>
        <br/>
        - <b>Düşük</b> seviye bulgular: <font color="green">{risk_counts.get('Düşük', 0)}</font>
        <br/><br/>
        Bu raporda her bir testin detaylı sonuçları, tespit edilen açıkların açıklamaları ve 
        bunları gidermek için öneriler bulunmaktadır.
        """
        
        paragraph = Paragraph(summary_text, self.styles['Normal'])
        story.append(paragraph)
        
        # Genel güvenlik skoru
        story.append(Spacer(1, 20))
        score = self._calculate_security_score(risk_counts)
        score_text = Paragraph(f"<b>Genel Güvenlik Skoru:</b> {score}/100", self.styles['Normal'])
        story.append(score_text)
        
        story.append(PageBreak())
        
    def _add_risk_chart(self, story):
        """Risk dağılımı grafiği ekle"""
        title = Paragraph("2. Risk Dağılımı", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Risk sayılarını hesapla
        risk_counts = self._count_risks()
        
        # Pasta grafik oluştur
        buffer = io.BytesIO()
        plt.figure(figsize=(6, 4))
        
        labels = []
        sizes = []
        colors = []
        
        if 'Kritik' in risk_counts and risk_counts['Kritik'] > 0:
            labels.append('Kritik')
            sizes.append(risk_counts['Kritik'])
            colors.append('darkred')
            
        if 'Yüksek' in risk_counts and risk_counts['Yüksek'] > 0:
            labels.append('Yüksek')
            sizes.append(risk_counts['Yüksek'])
            colors.append('red')
            
        if 'Orta' in risk_counts and risk_counts['Orta'] > 0:
            labels.append('Orta')
            sizes.append(risk_counts['Orta'])
            colors.append('orange')
            
        if 'Düşük' in risk_counts and risk_counts['Düşük'] > 0:
            labels.append('Düşük')
            sizes.append(risk_counts['Düşük'])
            colors.append('green')
        
        if not sizes:  # Hiç bulgu yoksa
            labels = ['Güvenli']
            sizes = [1]
            colors = ['green']
            
        plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
        plt.axis('equal')
        plt.title('Risk Seviyelerine Göre Bulgular')
        plt.savefig(buffer, format='png')
        buffer.seek(0)
        
        # Grafiği rapora ekle
        img = Image(buffer)
        img.drawHeight = 300
        img.drawWidth = 400
        story.append(img)
        
        # Risk tablosunu ekle
        story.append(Spacer(1, 20))
        risk_data = [["Risk Seviyesi", "Bulgu Sayısı"]]
        
        for level in ['Kritik', 'Yüksek', 'Orta', 'Düşük']:
            risk_data.append([level, str(risk_counts.get(level, 0))])
            
        risk_table = Table(risk_data, colWidths=[200, 200])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (1, 0), colors.white),
            ('ALIGN', (0, 0), (1, 0), 'CENTER'),
            ('FONT', (0, 0), (1, 0), 'Helvetica-Bold', 10),
            ('BOTTOMPADDING', (0, 0), (1, 0), 8),
            ('GRID', (0, 0), (1, -1), 0.5, colors.grey),
        ]))
        
        story.append(risk_table)
        story.append(PageBreak())
        
    def _add_detailed_results(self, story):
        """Her test için detaylı sonuçları ekle"""
        title = Paragraph("3. Detaylı Test Sonuçları", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Her modül için detaylı sonuçları ekle
        test_index = 3.1
        for module_name, results in self.scan_results["scan_results"].items():
            module_title = Paragraph(f"{test_index} {results['title']}", self.styles['SectionTitle'])
            story.append(module_title)
            story.append(Spacer(1, 10))
            
            # Bulgular tablosu
            if results['findings']:
                findings_data = [["Bulgu", "Risk Seviyesi", "Açıklama", "Öneri"]]
                
                for finding in results['findings']:
                    findings_data.append([
                        finding['name'],
                        finding['risk_level'],
                        finding['description'],
                        finding['recommendation']
                    ])
                    
                findings_table = Table(findings_data, colWidths=[100, 60, 180, 160])
                findings_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                    ('FONT', (0, 0), (-1, 0), 'Helvetica-Bold', 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                    ('FONT', (0, 1), (-1, -1), 'Helvetica', 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('WORDWRAP', (0, 0), (-1, -1), True),
                ]))
                
                # Risk seviyesi hücre renklerini ayarla
                for i in range(1, len(findings_data)):
                    level = findings_data[i][1]
                    if level == "Kritik":
                        findings_table.setStyle(TableStyle([
                            ('TEXTCOLOR', (1, i), (1, i), colors.darkred),
                            ('FONT', (1, i), (1, i), 'Helvetica-Bold', 8),
                        ]))
                    elif level == "Yüksek":
                        findings_table.setStyle(TableStyle([
                            ('TEXTCOLOR', (1, i), (1, i), colors.red),
                            ('FONT', (1, i), (1, i), 'Helvetica-Bold', 8),
                        ]))
                    elif level == "Orta":
                        findings_table.setStyle(TableStyle([
                            ('TEXTCOLOR', (1, i), (1, i), colors.orange),
                        ]))
                    elif level == "Düşük":
                        findings_table.setStyle(TableStyle([
                            ('TEXTCOLOR', (1, i), (1, i), colors.green),
                        ]))
                
                story.append(findings_table)
            else:
                story.append(Paragraph("Bu testte hiçbir bulgu tespit edilmedi.", self.styles['Normal']))
                
            story.append(Spacer(1, 20))
            test_index += 0.1
            
        story.append(PageBreak())
        
    def _add_conclusion(self, story):
        """Sonuç ve öneriler bölümü ekle"""
        title = Paragraph("4. Sonuç ve Öneriler", self.styles['CustomTitle'])
        story.append(title)
        story.append(Spacer(1, 20))
        
        # Risk sayılarını yeniden hesapla
        risk_counts = self._count_risks()
        total_findings = sum(risk_counts.values())
        
        # Genel duruma göre sonuç metni oluştur
        if risk_counts.get('Kritik', 0) > 0 or risk_counts.get('Yüksek', 0) > 0:
            conclusion_text = f"""
            <b>Sonuç:</b> Yapılan güvenlik taramasında kritik veya yüksek riskli güvenlik açıkları tespit edilmiştir.
            Bu açıklar, sistemin güvenliğini önemli ölçüde tehlikeye atabilir ve acil olarak ele alınmalıdır.
            <br/><br/>
            <b>Genel Öneriler:</b>
            <br/><br/>
            1. Kritik ve yüksek riskli güvenlik açıklarını öncelikli olarak ele alın ve düzeltin.
            <br/>
            2. Yamaları ve güncellemeleri düzenli olarak uygulayın.
            <br/>
            3. Güvenli kodlama pratiklerini uygulayın ve tüm kullanıcı girdilerini doğrulayın.
            <br/>
            4. Web uygulamanızı Web Application Firewall (WAF) ile koruyun.
            <br/>
            5. Düzenli olarak güvenlik taramaları ve penetrasyon testleri yaptırın.
            <br/>
            6. Güvenlik politikalarınızı ve prosedürlerinizi sürekli gözden geçirin ve güncelleyin.
            """
        elif risk_counts.get('Orta', 0) > 0:
            conclusion_text = f"""
            <b>Sonuç:</b> Yapılan güvenlik taramasında orta seviyeli güvenlik açıkları tespit edilmiştir.
            Bu açıklar, sistemin güvenliğini tehlikeye atabilir ve uygun bir zaman diliminde ele alınmalıdır.
            <br/><br/>
            <b>Genel Öneriler:</b>
            <br/><br/>
            1. Tespit edilen orta riskli güvenlik açıklarını en kısa sürede düzeltin.
            <br/>
            2. Yamaları ve güncellemeleri düzenli olarak uygulayın.
            <br/>
            3. Güvenli kodlama pratiklerini uygulayın ve tüm kullanıcı girdilerini doğrulayın.
            <br/>
            4. Güvenlik konfigürasyonlarını düzenli olarak gözden geçirin.
            <br/>
            5. Düzenli olarak güvenlik taramaları yaptırın.
            """
        elif risk_counts.get('Düşük', 0) > 0:
            conclusion_text = f"""
            <b>Sonuç:</b> Yapılan güvenlik taramasında yalnızca düşük seviyeli güvenlik açıkları tespit edilmiştir.
            Bu açıklar, sistemin güvenliğini önemli ölçüde tehlikeye atmaz ancak daha iyi bir güvenlik duruşu için düzeltilebilir.
            <br/><br/>
            <b>Genel Öneriler:</b>
            <br/><br/>
            1. Tespit edilen düşük riskli güvenlik açıklarını planlı bir şekilde ele alın.
            <br/>
            2. En iyi güvenlik uygulamalarını takip etmeye devam edin.
            <br/>
            3. Yamaları ve güncellemeleri düzenli olarak uygulayın.
            <br/>
            4. Düzenli olarak güvenlik taramaları yaptırın.
            """
        else:
            conclusion_text = f"""
            <b>Sonuç:</b> Yapılan güvenlik taramasında herhangi bir güvenlik açığı tespit edilmemiştir.
            Bu, sistemin mevcut güvenlik testlerine karşı dayanıklı olduğunu göstermektedir.
            <br/><br/>
            <b>Genel Öneriler:</b>
            <br/><br/>
            1. Güvenlik durumunuzu korumak için en iyi uygulamalara devam edin.
            <br/>
            2. Yamaları ve güncellemeleri düzenli olarak uygulayın.
            <br/>
            3. Düzenli olarak güvenlik taramaları yaptırın.
            <br/>
            4. Çalışanlarınıza güvenlik farkındalık eğitimleri verin.
            """
            
        story.append(Paragraph(conclusion_text, self.styles['Normal']))
        
    def _count_risks(self):
        """Farklı risk seviyelerindeki bulguların sayısını hesaplar"""
        risk_counts = {
            'Kritik': 0,
            'Yüksek': 0,
            'Orta': 0,
            'Düşük': 0
        }
        
        for module_name, results in self.scan_results["scan_results"].items():
            for finding in results['findings']:
                risk_level = finding['risk_level']
                risk_counts[risk_level] = risk_counts.get(risk_level, 0) + 1
                
        return risk_counts
        
    def _calculate_security_score(self, risk_counts):
        """Genel güvenlik skoru hesaplar (0-100)"""
        total_findings = sum(risk_counts.values())
        
        if total_findings == 0:
            return 100
            
        # Risk ağırlıkları
        weights = {
            'Kritik': 10,
            'Yüksek': 5,
            'Orta': 2,
            'Düşük': 1
        }
        
        # Ağırlıklı toplam hesapla
        weighted_sum = 0
        for level, count in risk_counts.items():
            weighted_sum += count * weights.get(level, 0)
            
        # Maksimum 100 puan üzerinden skor hesapla (ne kadar az sorun, o kadar yüksek puan)
        max_score = 100
        penalty = min(weighted_sum, max_score)
        
        return max(0, max_score - penalty) 