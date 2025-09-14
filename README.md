✨ Özellikler

    🔍 Çoklu Dosya Uzantı Desteği (.php, .phtml, .php3, .php4, .php5, .php7, .phps)

    🎯 Gelişmiş Pattern Tanıma - 8 farklı zararlı kod kategorisi

    ✅ Akıllı Whitelist Sistemi - False positive'ları önler

    📊 Detaylı Raporlama - HTML ve metin formatında raporlar

    🔒 Güvenli Karantina - Otomatik yedekleme ve izin kısıtlama

    ⚡ Performans Optimizasyonu - Büyük dosya filtreleme

    🔐 Hash Doğrulama - SHA256 hash hesaplama ve doğrulama

    🛡️ Güvenlik Kontrolleri - Dosya tipi ve izin doğrulama

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install coreutils findutils grep

# CentOS/RHEL
sudo yum install coreutils findutils grep

# macOS (Homebrew)
brew install coreutils grep

# Otomatik dizin oluşturma
sudo php-shell-scanner --setup

# Manuel dizin oluşturma
sudo mkdir -p /opt/quarantine /opt/backups /etc/php-scanner
sudo chmod 700 /opt/quarantine
sudo chmod 755 /opt/backups


# Varsayılan dizinde tarama (/var/www/html)
sudo php-shell-scanner

# Belirli bir dizinde tarama
sudo php-shell-scanner /path/to/your/website

# Özyinelemeli olmayan tarama
sudo php-shell-scanner /path/to/dir --no-recursive

# Sadece belirli uzantıları tara
sudo php-shell-scanner /path/to/dir --extensions "php,php5,phtml"



/etc/php-scanner/whitelist.conf:


# WordPress dosyaları
.*wp-admin/.*
.*wp-includes/.*
wp-config\.php

# Joomla dosyaları
.*administrator/.*
.*includes/.*

# Özel scriptler
legitimate_cron\.php
upload_handler\.php

# Dizin pattern'leri
.*/cache/.*
.*/uploads/.*
.*/tmp/.*


