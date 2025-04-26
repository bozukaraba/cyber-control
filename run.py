#!/usr/bin/env python
# -*- coding: utf-8 -*-

from app import app

if __name__ == '__main__':
    print("CyberControl uygulaması başlatılıyor...")
    print("Tarayıcınızda http://127.0.0.1:5000 adresini açın")
    app.run(debug=True) 