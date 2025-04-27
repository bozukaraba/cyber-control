#!/bin/bash

# Frontend dosyalarını build dizinine kopyala
mkdir -p dist
cp -r templates/* dist/
cp -r static dist/

# index.html'i düzenle - Flask template değişkenlerini kaldır
sed -i '' 's/{{ url_for('\''static'\'', filename='\''css\/style.css'\'') }}/static\/css\/style.css/g' dist/index.html
sed -i '' 's/{{ url_for('\''static'\'', filename='\''js\/script.js'\'') }}/static\/js\/script.js/g' dist/index.html
sed -i '' 's/{{ url_for('\''static'\'', filename='\''img\/favicon.ico'\'') }}/static\/img\/favicon.ico/g' dist/index.html 