#!/data/data/com.termux/files/usr/bin/bash
# install_termux.sh - Setup Ethical Hacking Burp di Termux
# Author: ZamurSec | https://discord.com/invite/AA92kB5GSB

set -e

echo "[*] Update package list..."
pkg update -y

echo "[*] Install python..."
pkg install -y python

echo "[*] Install flask..."
pip install --upgrade pip
pip install flask

echo "[*] Coba install cryptography lewat pip (prebuilt wheel)..."
if ! pip install cryptography; then
    echo "[!] Gagal via pip biasa, coba install lewat pkg (prebuilt Termux package)..."
    pkg install -y python-cryptography || {
        echo "[!] Masih gagal. HTTPS intercept tidak akan aktif (fallback ke tunnel biasa)."
        echo "    Coba manual: pkg install rust binutils && pip install cryptography"
    }
fi

echo "[+] Selesai. Jalankan dengan:"
echo "    python app.py"
echo "[+] Lalu buka http://127.0.0.1:5000 di browser."
echo "[+] Gabung Discord: https://discord.com/invite/AA92kB5GSB"
