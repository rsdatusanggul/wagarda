#!/bin/bash

# Pastikan berada di direktori project (tempat file ini dan docker-compose.yml berada)
cd "$(dirname "$0")"

# Load env file so checks in this script match docker-compose variables.
if [ -f .env ]; then
  set -a
  . ./.env
  set +a
fi

echo "🚀 Memulai proses build dan restart WAGARDA..."
echo "------------------------------------------------"

# Bersihkan layanan terdahulu dan jalankan build ulang image serta recreate container di background
docker compose down
docker compose up -d --build

echo "------------------------------------------------"
echo "⏳ Menunggu layanan tunnel siap (harap tunggu ~10 detik)..."

# Beri jeda 10 detik agar container tunnel sempat startup
sleep 10

echo ""
echo "✅ Proses selesai! WAGARDA dapat diakses melalui URL Publik berikut:"
echo "================================================================"

if [ -n "$CF_TUNNEL_TOKEN" ]; then
  echo "Named Tunnel aktif (berbasis token)."
  echo "Akses service melalui domain yang Anda mapping di Cloudflare Zero Trust."
else
  echo "PERINGATAN: CF_TUNNEL_TOKEN belum di-set."
  echo "Container cloudflare-tunnel production tidak akan bisa start tanpa token."
fi

echo "================================================================"
echo ""
echo "🔐 [Development] Default Kredensial Login:"
echo "Username : lihat env"
echo "Password : lihat env"
echo ""
echo "Catatan:"
echo "- Untuk melihat status tunnel, jalankan perintah ini:"
echo "  docker compose logs cloudflare-tunnel"
