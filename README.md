# WhatsApp Gateway Multi-Device (WAGARDA) Datu Sanggul

Project ini adalah WhatsApp Gateway API Datu Sanggul forking dari WAGARDA drg. Basoro yang berbasis Node.js menggunakan library `@whiskeysockets/baileys`. Mendukung multi-device, pengiriman pesan massal (bulk blast) dengan rotasi pengirim acak, manajemen perangkat, dan tingkat keamanan kelas militer.

## Fitur Utama

*   **Multi-Device Support**: Bisa menghubungkan banyak nomor WhatsApp sekaligus.
*   **Web Dashboard UI**: Interface lengkap untuk manajemen QR Code, perangkat, API Key, dan melihat daftar Log (dilindungi dengan Login Authentikasi).
*   **Random Sender Rotation**: Otomatis merotasi pengirim secara acak dari device yang terhubung untuk menghindari deteksi spam saat melakukan pengiriman massal.
*   **Bulk Blast**: Kirim pesan massal (bisa tipe Teks, Gambar, Dokumen) ke banyak nomor dengan satu hit API.
*   **Variasi Pesan (Spintax)**: Mendukung pengiriman pesan yang berbeda-beda untuk setiap target secara otomatis.
*   **Dockerized & Cloudflare Ready**: Support setup lokal maupun produksi dengan mudah menggunakan Docker Compose, Nginx, dan Cloudflare Tunnel terintegrasi.

## 🛡️ Keamanan Lanjutan (Paranoid Security Hardening)
Sistem ini menggunakan pengamanan berganda (Layered Security) yang sangat ketat:
1. **Docker Non-Root User**: Aplikasi berjalan menggunakan *user standard* (terisolasi dari akses `root`), menekan dampak kerentanan eksekusi RCE.
2. **Strict API CORS**: API WAGARDA (`/wagateway/*`) dilindungi oleh CORS yang dikonfigurasi lewat `.env`, sehingga hanya domain tertentu (misal: Google Sheets, URL RS) yang bisa melakukan hit API.
3. **Anti-Botnet Account Lockout**: Memproteksi login dashboard. Gagal login 5x berturut-turut dalam jangka 30 menit akan menyebabkan akun Admin **TERKUNCI** (Lockout) secara total selama 30 menit. Celah akses Bruteforce tertutup rapat.
4. **Deep Input Sanitization**: Semua data parameter *payload* pada API (nomor, sender, pesan, dsb) akan dibersihkan (*sanitized* & *escaped*) secara paksa untuk menghindari injeksi struktural.
5. **Secure Sessions & Headers**: Cookie session hanya dikirim lewat HTTPS (Secure: true, SameSite: Lax), diproteksi Helmets (anti-Clickjacking, MIME-sniffing blocker), dan rotasi CSRF Tokens di setiap login form.
6. **API Key Management Dashboard**: Pembuatan dan penghapusan rahasia API Key tidak lagi butuh akses DB, melainkan cukup menekan tombol di UI Dashboard utama.

## Instalasi via Docker (Rekomendasi)

Sangat disarankan menggunakan Docker Compose karena setup infrastruktur Proxy Nginx dan Cloudflare Tunnel sudah dibungkus otomatis.

1.  Clone repository ini.
2.  Buka directory WAGARDA dan ubah file konfigurasi `.env` sesuai kebutuhan (contoh di bawah).
3.  Jalankan container (Bisa berjalan di background):
    ```bash
    docker compose up -d --build
    ```
4. Sesi WA, database, dan environment terlindungi dalam volume `sessions`, `wagarda.db`, dan `.env` host secara persisten.

## Konfigurasi Kredensial & Server

Semua Environment Setup harus dimasukkan dalam sebuah file bernama `.env`:

```env
PORT=10000

# Security Configuration for Defaults (Required)
DEFAULT_ADMIN_USER=admin
DEFAULT_ADMIN_PASS=PasswordRahasiaAnda
DEFAULT_API_KEY=wagarda-secret-key

# CORS Configuration (Comma separated list of allowed domains)
# Pisahkan dengan koma jika ada banyak domain. Gunakan * untuk public (TIDAK DISARANKAN)
ALLOWED_ORIGINS=https://docs.google.com,https://your-hospital-domain.com
```

*Note: Username `admin` tidak akan bisa login apabila `DEFAULT_ADMIN_USER` belum di set di dalam file `.env` untuk menghindari Insecure Default Credentials.*

## Keamanan API (API Key)

Bahkan jika origin URL Anda lolos CORS, API Anda Wajib menyertakan Header autentikasi:

*   **Header**: `x-api-key: [API_KEY_ANDA]`

> **PENTING**: API Key tambahan dapat dikumpulkan atau direvoke kapan saja melalui menu **API Key Management** di halaman utama (Dashboard `http://localhost:10000/`) Web WAGARDA.

## Cara Penggunaan

### 1. Manajemen Perangkat & Dashboard
Akses Web Dashboard. Anda wajib login menggunakan User & Password `.env` Anda.
*   **Tambah WA**: Masukkan Device ID unik (Misal: `Klinik-Gigi`), klik **Generate QR Code** dan tunggu WA-nya melakukan scan.
*   **List Device**: Refresh tabel terdaftar untuk melihat info No HP, dan Status Koneksi (CONNECTED / DISCONNECTED). Jika dihapus (Logout), WA tidak akan nyambung lagi.
*   **Kirim Pesan**: Endpoint API ada di `/wagateway/kirimpesan` (Text), `/wagateway/send-media` (Image), `/wagateway/send-document` (File).

### 2. Mengirim Pesan Tunggal Endpoint (Contoh HTTP)
**Endpoint**: `POST /wagateway/kirimpesan`
**Header**: `x-api-key: [SECRET_KEY]`
```json
{
    "sender": "Klinik-Gigi",
    "number": "6281234567890",
    "message": "Halo Budi, waktunya kontrol gigi."
}
```

### 3. Rotasi & Bulk Blast 
Jika Anda ingin mengirim Pesan broadcast kepada banyak user sekaligus, sistem akan memastikan "pembagian beban tugas" antarnomor WA Device yang terhubung untuk meminimalisasi ban Massal dari META System.

**Endpoint**: `POST /wagateway/blast`
**Header**: `x-api-key: [SECRET_KEY]`
```json
{
    "numbers": ["6281234567890", "6289876543210"],
    "messages": ["Pesan Versi A...", "Pesan Versi B..."],
    "type": "text" 
}
```

### 4. Melihat Log Transaksi Pesan Terkirim
Akses tab `/logs-view` di Dashboard WAGARDA. Seluruh histori komunikasi yang Anda luncurkan via API (baik Berhasil atau Gagal total) disajikan dalam Tabel Database Log lengkap dengan stempel waktu, target No HP, nama Sender, dan bukti transaksinya secara real-time. Pihak ketiga tidak akan bisa mengakses Log WA karena terlindungi oleh *Session Login Cookies*.
