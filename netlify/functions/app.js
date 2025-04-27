const { spawn } = require('child_process');
const path = require('path');

exports.handler = async function(event, context) {
  // CORS başlıkları
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS'
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
    // Flask uygulamasını çalıştır
    const flask = spawn('python', ['wsgi.py'], {
      cwd: path.resolve(__dirname, '../../')
    });

    // Uygulama çıktısını topla
    let output = '';
    flask.stdout.on('data', (data) => {
      output += data.toString();
    });

    // Hata çıktısını topla
    let error = '';
    flask.stderr.on('data', (data) => {
      error += data.toString();
    });

    // İşlem tamamlandığında
    await new Promise((resolve, reject) => {
      flask.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`Flask uygulaması ${code} koduyla çıktı: ${error}`));
        } else {
          resolve();
        }
      });
    });

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ message: 'Flask uygulaması başarıyla çalıştı', output })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ error: error.message })
    };
  }
}; 