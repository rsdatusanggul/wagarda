#!/bin/bash

# Pastikan berada di direktori project (tempat file ini dan docker-compose.yml berada)
cd "$(dirname "$0")"

echo "🚀 Memulai proses build dan restart WAGARDA..."
echo "------------------------------------------------"

# Jalankan build ulang image dan recreate container di background
docker compose up -d --build

echo "------------------------------------------------"
echo "⏳ Menunggu Cloudflare mendapatkan URL publik (harap tunggu ~10 detik)..."

# Beri jeda 10 detik agar container tunnel sempat mendapatkan respon dari Cloudflare
sleep 10

echo ""
echo "✅ Proses selesai! WAGARDA dapat diakses melalui URL Publik berikut:"
echo "================================================================"

# Ekstrak URL .trycloudflare.com terbaru dari log tunnel
docker compose logs cloudflare-tunnel | grep -o 'https://[^ ]*\.trycloudflare\.com' | tail -n 1

echo "================================================================"
echo ""
echo "🔐 [Development] Default Kredensial Login:"
echo "Username : admin"
echo "Password : wagarda-admin-secret"
echo ""
echo "Catatan:"
echo "- Jika URL di atas kosong, proses mungkin butuh waktu sedikit lebih lama."
echo "- Untuk melihat URL secara manual, jalankan perintah ini:"
echo "  docker compose logs cloudflare-tunnel | grep 'trycloudflare.com'"
