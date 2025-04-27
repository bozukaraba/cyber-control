exports.handler = async function(event, context) {
  // CORS başlıkları
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  };

  // OPTIONS isteklerini yanıtla
  if (event.httpMethod === 'OPTIONS') {
    return {
      statusCode: 200,
      headers,
      body: ''
    };
  }

  try {
    const { targetUrl, scanOptions } = JSON.parse(event.body);

    // Örnek sonuç verisi
    const results = [
      {
        title: "SSL/TLS Güvenlik Testi",
        findings: [
          {
            name: "SSL Sertifikası Kontrolü",
            risk_level: "Düşük",
            description: "SSL sertifikası geçerli ve güncel.",
            impact: "Minimal etki",
            recommendation: "Sertifika yönetimini sürdürün."
          }
        ]
      },
      {
        title: "Port Taraması",
        findings: [
          {
            name: "Açık Port Tespiti",
            risk_level: "Orta",
            description: "80 ve 443 portları dışında açık port tespit edilmedi.",
            impact: "Düşük risk",
            recommendation: "Güvenlik duvarı kurallarını düzenli kontrol edin."
          }
        ]
      }
    ];

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({
        status: 'success',
        results: results
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({
        status: 'error',
        message: error.message
      })
    };
  }
}; 