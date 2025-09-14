#!/bin/bash

# GELİŞMİŞ PHP SHELL TARAYICI
# Version: 2.0
# Author: Security Expert by Sinan AYDIN

# -------------------- KONFİGÜRASYON --------------------
SCAN_DIRECTORY="${1:-/var/www/html}"  # Komut satırı argümanı veya varsayılan
FILE_EXTENSIONS=("*.php" "*.phtml" "*.php3" "*.php4" "*.php5" "*.php7" "*.phps")
OUTPUT_FILE="/var/log/php_shell_scan_$(date +%Y%m%d_%H%M%S).log"
QUARANTINE_DIR="/opt/quarantine"
BACKUP_DIR="/opt/backups"
WHITELIST_FILE="/etc/php_shell_whitelist.conf"
MAX_FILE_SIZE="10M"  # 10MB'dan büyük dosyaları tarama

# Gelişmiş zararlı kod pattern'leri
declare -A MALICIOUS_PATTERNS=(
    ["system_calls"]='system\(|exec\(|passthru\(|shell_exec\(|popen\(|proc_open\('
    ["eval"]='eval\(|assert\(|create_function\('
    ["file_operations"]='fwrite\(|file_put_contents\(|unlink\(|mkdir\(|rmdir\(|chmod\('
    ["obfuscation"]='base64_decode\(|gzinflate\(|str_rot13\(|urldecode\('
    ["suspicious_comments"]='@ini_set|@error_reporting|@set_time_limit'
    ["dangerous_functions"]='pcntl_exec\(|dl\(|ini_alter\(|phpinfo\(|posix_kill\('
    ["network_operations"]='fsockopen\(|curl_init\(|socket_create\(|file_get_contents\(.*http://'
    ["database_operations"]='mysql_connect\(|mysqli_connect\(|pg_connect\('
)

# Whitelist pattern'leri (false positive önlemek için)
WHITELIST_PATTERNS=(
    'WordPress|wp-admin|wp-includes'
    'Joomla|joomla'
    'Drupal|drupal'
    'Symfony|symfony'
    'Laravel|laravel'
    'CodeIgniter|codeigniter'
    'cron\.php|install\.php|update\.php'
)

# -------------------- FONKSİYONLAR --------------------
log_message() {
    local message="$1"
    local level="${2:-INFO}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$level] $message" | tee -a "$OUTPUT_FILE"
}

check_dependencies() {
    local deps=("grep" "find" "file" "stat" "md5sum" "sha256sum")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            log_message "Gerekli araç bulunamadı: $dep" "ERROR"
            exit 1
        fi
    done
}

create_directories() {
    mkdir -p "$QUARANTINE_DIR" "$BACKUP_DIR"
    chmod 700 "$QUARANTINE_DIR"
}

load_whitelist() {
    if [[ -f "$WHITELIST_FILE" ]]; then
        mapfile -t CUSTOM_WHITELIST < "$WHITELIST_FILE"
    fi
}

is_whitelisted() {
    local file_path="$1"
    local file_content="$2"
    
    # Built-in whitelist kontrolü
    for pattern in "${WHITELIST_PATTERNS[@]}"; do
        if [[ "$file_path" =~ $pattern ]] || [[ "$file_content" =~ $pattern ]]; then
            return 0
        fi
    done
    
    # Custom whitelist kontrolü
    for pattern in "${CUSTOM_WHITELIST[@]}"; do
        if [[ "$file_path" =~ $pattern ]] || [[ "$file_content" =~ $pattern ]]; then
            return 0
        fi
    done
    
    return 1
}

analyze_file() {
    local file="$1"
    local findings=()
    
    # Dosya boyutu kontrolü
    local file_size=$(stat -c%s "$file")
    if (( file_size > 10485760 )); then  # 10MB
        log_message "Büyük dosya atlandı: $file (${file_size} bytes)" "WARNING"
        return
    fi
    
    # Dosya tipi kontrolü (gerçekten PHP mi?)
    if ! file "$file" | grep -q "PHP"; then
        log_message "PHP olmayan dosya atlandı: $file" "DEBUG"
        return
    fi
    
    local file_content=$(cat "$file")
    
    # Whitelist kontrolü
    if is_whitelisted "$file" "$file_content"; then
        log_message "Whitelist'te bulunan dosya atlandı: $file" "DEBUG"
        return
    fi
    
    # Pattern taraması
    for category in "${!MALICIOUS_PATTERNS[@]}"; do
        if echo "$file_content" | grep -E -q "${MALICIOUS_PATTERNS[$category]}"; then
            local matches=$(echo "$file_content" | grep -E -o "${MALICIOUS_PATTERNS[$category]}" | head -5 | tr '\n' ' ')
            findings+=("$category: $matches")
        fi
    done
    
    # Obfuscation tespiti
    if [[ ${#file_content} -gt 1000 ]] && [[ $(echo "$file_content" | grep -o '[a-zA-Z]' | wc -l) -lt $((${#file_content} / 10)) ]]; then
        findings+=("OBFUSCATION: Yüksek oranda obfuscated kod")
    fi
    
    if [[ ${#findings[@]} -gt 0 ]]; then
        local file_hash=$(sha256sum "$file" | cut -d' ' -f1)
        local file_info=$(stat -c "%U:%G %a %y" "$file")
        
        log_message "ZARARLI DOSYA BULUNDU: $file" "ALERT"
        log_message "Hash: $file_hash" "ALERT"
        log_message "Info: $file_info" "ALERT"
        log_message "Buluntular:" "ALERT"
        
        for finding in "${findings[@]}"; do
            log_message "  - $finding" "ALERT"
        done
        
        quarantine_file "$file" "$file_hash"
    fi
}

quarantine_file() {
    local file="$1"
    local hash="$2"
    local filename=$(basename "$file")
    local quarantine_path="$QUARANTINE_DIR/${filename}_${hash}"
    
    # Backup al
    cp "$file" "$BACKUP_DIR/${filename}_$(date +%s).bak"
    
    # Karantinaya taşı
    mv "$file" "$quarantine_path"
    
    # Dosya izinlerini kısıtla
    chmod 000 "$quarantine_path"
    chown root:root "$quarantine_path"
    
    log_message "Dosya karantinaya alındı: $quarantine_path" "INFO"
}

generate_report() {
    local alert_count=$(grep -c "ALERT" "$OUTPUT_FILE")
    local total_files=$(find "$SCAN_DIRECTORY" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php3" -o -name "*.php4" -o -name "*.php5" -o -name "*.php7" -o -name "*.phps" \) | wc -l)
    
    echo "=================== TARAMA RAPORU ===================" | tee -a "$OUTPUT_FILE"
    echo "Tarama Zamanı: $(date)" | tee -a "$OUTPUT_FILE"
    echo "Taranan Dizin: $SCAN_DIRECTORY" | tee -a "$OUTPUT_FILE"
    echo "Toplam Dosya: $total_files" | tee -a "$OUTPUT_FILE"
    echo "Zararlı Dosya: $alert_count" | tee -a "$OUTPUT_FILE"
    echo "Log Dosyası: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
    echo "=====================================================" | tee -a "$OUTPUT_FILE"
}

# -------------------- ANA PROGRAM --------------------
main() {
    echo "Gelişmiş PHP Shell Tarayıcı Başlatılıyor..."
    echo "Taranacak Dizin: $SCAN_DIRECTORY"
    echo "Log Dosyası: $OUTPUT_FILE"
    echo "====================================================="
    
    # Başlangıç kontrolleri
    check_dependencies
    create_directories
    load_whitelist
    
    if [[ ! -d "$SCAN_DIRECTORY" ]]; then
        log_message "Dizin bulunamadı: $SCAN_DIRECTORY" "ERROR"
        exit 1
    fi
    
    # Dosya tarama
    local find_cmd="find \"$SCAN_DIRECTORY\" -type f \( "
    for ext in "${FILE_EXTENSIONS[@]}"; do
        find_cmd+=" -name \"$ext\" -o"
    done
    find_cmd="${find_cmd% -o} \) -print0"
    
    log_message "Tarama başlatılıyor..." "INFO"
    
    eval "$find_cmd" | while IFS= read -r -d '' file; do
        analyze_file "$file"
    done
    
    # Rapor oluştur
    generate_report
    
    log_message "Tarama tamamlandı" "INFO"
}

# Trap sinyalleri
trap 'log_message "Script kullanıcı tarafından durduruldu" "WARNING"; exit 1' INT TERM

# Ana programı çalıştır
main "$@"
