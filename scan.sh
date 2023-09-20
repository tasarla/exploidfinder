#!/bin/bash

# Taramak istediğiniz dizini ve uzantıyı burada belirtin
directory_to_scan="/path/to/your/directory"
file_extension=".php"

# Shell kodlarını tespit etmek için kullanılacak anahtar kelimeleri belirtin
keywords=("system(" "exec(" "shell_exec(" "passthru(" "eval(")

# Zararlı dosyaları saklamak için bir dizin oluşturun (isteğe bağlı)
quarantine_directory="/path/to/quarantine"

# Belirtilen dizindeki tüm PHP dosyalarını tara
for file in $(find "$directory_to_scan" -type f -name "*$file_extension"); do
  # Dosyanın içeriğini oku
  file_content=$(cat "$file")

  # Anahtar kelimeleri ara ve bulunanları ekrana yazdır
  for keyword in "${keywords[@]}"; do
    if [[ $file_content == *"$keyword"* ]]; then
      echo "Potansiyel zararlı dosya bulundu: $file"

      # Kullanıcıya silmek isteyip istemediğini sor
      read -p "Bu dosyayı silmek istiyor musunuz? (Evet/Hayır): " choice

      if [[ $choice == "Evet" || $choice == "evet" ]]; then
        # Dosyayı sil (ya da başka bir işlem yapabilirsiniz)
        rm "$file"
        echo "Dosya silindi: $file"
      else
        # Dosyayı karantinaya taşı (isteğe bağlı)
        if [ -n "$quarantine_directory" ]; then
          mv "$file" "$quarantine_directory"
          echo "Dosya karantinaya taşındı: $file"
        fi
      fi
      break
    fi
  done
done
