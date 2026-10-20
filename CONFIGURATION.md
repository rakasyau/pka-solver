# pka-solver — konfigurasi & solusi

Plugin Hermes untuk menyelesaikan soal Cisco Packet Tracer (`.pka`) **tanpa AI
dan tanpa Docker**. Berjalan lokal di Windows: Python murni + ctypes.

Port dari <https://github.com/mircodz/pka2xml> (BSD-2-Clause), algoritma
kriptografi Crypto++ dipindah ke Python.

---

## 1. Ringkasan

| Aspek | Nilai |
|---|---|
| Docker | tidak diperlukan |
| AI/LLM | tidak dipakai — transplant config deterministik |
| Dependency | nol (`python_dependencies: []`) |
| Backend Twofish | native `_twofish` bila ada, else Python murni bawaan |
| Interpreter | Python 3.11+ (teruji 3.14.6 dan 3.14.7) |
| Lokasi | `C:\Users\rakas\AppData\Local\hermes\plugins\pka-solver\` |

## 2. Instalasi

Plugin sudah terpasang. Perintah yang dipakai:

```bash
hermes plugins enable pka-solver
```

Tanpa Docker, tanpa `pip install`. Semua memakai stdlib (`zlib`, `ctypes`,
`struct`, `re`).

Backend Twofish opsional bila ingin jauh lebih cepat:

```bash
pip install twofish
```

Kalau wheel tidak tersedia untuk interpreter Anda (tidak ada wheel cp314),
plugin otomatis memakai implementasi Python murni — tetap benar, hanya
lebih lambat.

## 3. Format berkas `.pka`

`.pka` bukan zip/xml biasa. Strukturnya:

```
deobfuscate-1  →  Twofish/EAX  →  deobfuscate-2  →  zlib  →  XML
```

Kebalikannya saat menulis:

```
XML  →  zlib  →  obfuscate-2  →  Twofish/EAX  →  obfuscate-1  →  .pka
```

Kunci dan IV tetap (dari pka2xml):

| Konstanta | Nilai |
|---|---|
| `PKA_KEY` | `{0x89} × 16` |
| `PKA_IV` | `{0x10} × 16` |
| `NETS_KEY` | `{0xBA} × 16` |
| `NETS_IV` | `{0xBE} × 16` |

Dua lapisan obfuscate berbasis XOR dengan panjang berkas:

```
deobfuscate_1: b[i] = a[len + ~i] ^ (len - i*len)
deobfuscate_2: b[i] = a[i] ^ (len - i)
```

Hasil zlib diberi prefiks panjang uncompressed 4 byte big-endian.

### EAX

EAX diimplementasikan sendiri karena pycryptodome tidak punya Twofish dan
paket `twofish` tidak punya mode cipher. Bentuknya (mengikuti Crypto++):

```
OMAC_0 = OMAC_K(0^15 ‖ 0x00 ‖ N)
OMAC_1 = OMAC_K(0^15 ‖ 0x01 ‖ H)      # header; kosong pada .pka
OMAC_2 = OMAC_K(0^15 ‖ 0x02 ‖ C)
tag    = OMAC_0 ⊕ OMAC_1 ⊕ OMAC_2
C      = CTR_K(iv = OMAC_0)(M)        # counter mulai dari OMAC_0
```

Dua detail yang mudah salah dan harus persis begini:

1. **Domain separation dengan prefiks nol** — input OMAC adalah
   `0^15 ‖ 0x00 ‖ N`, bukan `N` saja.
2. **Counter CTR dimulai dari nilai OMAC_0**, bukan dari 0.

## 4. Tiga blok `<PACKETTRACER5>`

File `.pka` berisi 3 blok (terbukti: blok ke-4 pada hitungan mentah adalah
tag penutup/sisa, pasangan sebenarnya hanya 3):

| Blok | Isi |
|---|---|
| 0 | activity — dipakai PT untuk boot dan grading |
| 1 | workspace |
| 2 | **answer key** — config jawaban yang benar |

Karena PT bisa me-reset workspace saat membuka, state graded harus ditulis
ke **semua blok**. Patch hanya di blok 2 menghasilkan 0% di setiap butir.

## 5. Cara kerja `pka_solve`

1. Decrypt `.pka` → XML.
2. Ambil `RUNNINGCONFIG` tiap device dari blok 2 (answer key).
3. Sisipkan `no shutdown` setelah tiap ` ip address …` — kunci jawaban
   mengabaikannya, tapi PT menghitungnya.
4. Tulis ulang blok 0 (versi + `PIXMAPBANK` milik sendiri, isi dari
   answer key), dan salin answer key ke blok 1.
5. Re-encrypt → `.pka` baru, nama berakhiran `-SOLVED`.

Yang **tidak** diubah: ID perangkat, nomor seri, MAC/BIA, koordinat, dan
link. Semuanya milik tiap blok dan harus tetap.

> Catatan penting: Packet Tracer **tidak menyimpan skor** di dalam file.
> Skor dihitung saat runtime dengan membandingkan config perangkat terhadap
> pohon `<COMPARISONS>`. Jadi "100%" berarti config-nya cocok, bukan karena
> ada tag nilai yang diubah.

## 6. Assessment / rubrik

Untuk melihat assessment, tool `pka_inspect` membaca pohon `<COMPARISONS>`.

Pohon ini punya ~18.000 node — satu per atribut tiap device. Hampir semua
carry `checkType="0"` (tidak dinilai). Yang benar-benar diperiksa hanya
yang `checkType != "0"`, yaitu sekitar **75 butir** pada file contoh.

Cuplikan output:

```json
{
  "path": "P2P-1 / Ports / Serial0/1/1 / OSPF Cost",
  "id": "OSPF Cost",
  "points": "4",
  "check_type": "2",
  "expected": "50"
}
```

`check_type`: 0 = tidak dinilai, 1 = perbandingan string, 2 = nilai
numerik.

## 8. Timeout: kenapa `PKA → XML` sempat gagal

Decrypt `.pka` 1 MB butuh **±0,5 s** dengan Twofish native, **±3,2 s** dengan
versi pure-Python. Berkas 17 MB butuh beberapa detik, jadi dua hal wajib:

1. **Handler route harus `def`, bukan `async def`.** FastAPI menjalankan route
   `async def` langsung di event loop; decrypt Several-detik di sana menahan
   semua route lain, termasuk polling `/api/status` yang dipakai desktop untuk
   mendeteksi backend hidup. Gejalanya persis "Timed out connecting to Hermes
   backend". Route `def` Jalan di threadpool.
2. **`timeoutMs` di sisi UI.** `ctxRestPost` mengeset 300000 ms; default fetch
   desktop 30 s dan itu batas *idle socket*.

Backend Twofish native (**wajib** — tanpa ini masih pure dan ~6x lebih lambat):

```bash
SP="$(find ~/AppData/Local/hermes/tools -maxdepth 1 -name 'python-3.14.7*' -type d | head -1)/Lib/site-packages"
cp "C:/Users/rakas/AppData/Local/Python/pythoncore-3.14-64/Lib/site-packages/_twofish.cp314-win_amd64.pyd" "$SP/"
```

Cek hasilnya dengan `pka_doctor` → `twofish_backend: twofish-native`. Kalau
masih `twofish-pure`, berarti ekstensi tidak ada di site-packages interpreter
yang benar. **Nama folder interpreter memuat karakter `*`, jadi jangan pakai
glob di shell untuk menulis ke dalamnya** — pakai `find` seperti di atas, atau
selalu przez Python `sysconfig.get_paths()['platlib']`.

## 9. Dua separuh plugin

Hermes punya tiga sistem plugin yang tidak berbagi kode sama sekali. Supaya
tidak salah pilih lagi:

| Separuh | Isi | Untuk |
|---|---|---|
| **Agent** (`plugin.yaml`) | 8 tool Python | agent memanggil otomatis |
| **Dashboard** (`dashboard/`) | `plugin_api.py` FastAPI → `/api/plugins/pka-solver/` | UI web |
| **Desktop** (`desktop/plugin.js`) | sidebar + halaman di app Hermes Desktop | tampilan Desktop |

Semuanya satu folder, jadi install/update/remove sekali jalan.

### Desktop

`desktop/plugin.js` mendaftarkan route `/pka-solver` plus baris sidebar
**PKA Solver**. Muat tanpa build step (ESM polos, `jsx()` saja — bukan JSX).

Backend diambil dari `ctx.rest`, yang menyentuh `dashboard/plugin_api.py`
di sebelahnya. Jadi UI dan tool agent memakai handler yang sama dan tidak
bisa berbeda pendapat.

Restart Hermes Desktop setelah pasang — plugin dimuat saat start. Kalau tidak
muncul: ⌘K → **Reload desktop plugins**, atau **Rescan** di halaman Plugins.

Dua hal yang perlu tahu kalau menambah route:

- **Akses berkas dibatasi** ke `~/Desktop`, `~/Documents`, `~/Downloads`,
  `D:\materi kuliah`, `D:\projek coba-coba`. Route yang bisa decrypt berkas
  sembarang dari browser akan jadi primitive baca-arsip, jadi whitelist.
- **Auth** memakai `_SESSION_HEADER_NAME` + token per-proses. `curl` biasa
  akan dapat 401 — itu memang desainnya, bukan bug.

### Endpoint

| Method | Path | Fungsi |
|---|---|---|
| GET | `/doctor` | backend, versi, self-test |
| GET | `/inspect?path=&max_rubric_items=` | assessment + rubrik |
| POST | `/solve` `{path, output, report, fix_interfaces}` | tulis file 100% + laporan |
| POST | `/verify` `{path, must_contain, must_not_contain}` | cek isi |
| GET | `/download?path=` | unduh hasil |
| GET | `/report?path=` | ambil teks laporan |

Kode status: `400` berkas tidak ada, `403` di luar folder yang diizinkan,
`200` sukses.

### Tool agent

| Tool | Fungsi |
|---|---|
| `pka_doctor` | cek backend, versi, jalankan self-test |
| `pka_decrypt` | **PKA → XML saja**, tulis `.xml` di samping berkas |
| `pka_inspect` | device, link, addressing, instruksi, rubrik assessment |
| `pka_solve` | buat `.pka` 100% + laporan markdown |
| `pka_verify` | pastikan string wajib ada / tidak ada di hasil |
| `pka_decrypt` / `pka_encrypt` | konversi XML ⇄ `.pka` |
| `pka_open` | buka hasil di Packet Tracer |
| `pka_logs` | decrypt file log PT (`pt_*.log`) |

Nama parameter yang dipakai `pka_solve`: `path`, `output`, `report`,
`fix_interfaces`, `open_after` — bukan `out`/`open`.

## 8. Contoh pemakaian

```bash
# cekinstalasi
hermes plugins list | grep pka

# baca assessment + rubrik
python -c "import sys,json; sys.path.insert(0,'C:/Users/rakas/AppData/Local/hermes/plugins/pka-solver'); import tools; print(tools.pka_inspect({'path':'soal.pka'}))"

# selesaikan
python -c "import sys; sys.path.insert(0,'C:/Users/rakas/AppData/Local/hermes/plugins/pka-solver'); import tools; print(tools.pka_solve({'path':'soal.pka','open':True}))"
```

Di dalam Hermes, pemanggilan tool-nya langsung:

```
pka_inspect({"path": "D:/materi kuliah/.../soal.pka"})
pka_solve({"path": "...", "open": true})
```

## 9. Konfigurasi (`config_schema`)

| Kunci | Tipe | Default | Fungsi |
|---|---|---|---|
| `packet_tracer_path` | str | `C:/Program Files/Cisco Packet Tracer 9.0.1/bin/PacketTracer.exe` | path `PacketTracer.exe` untuk `pka_open` |
| `keep_temp_xml` | bool | `false` | simpan XML hasil decrypt di samping file |

Ubah lewat `hermes config set` atau langsung di `plugin.yaml`.

## 10. Self-test

```bash
cd C:/Users/rakas/AppData/Local/hermes/plugins/pka-solver
python3 selftest.py "D:/materi kuliah/.../soal.pka"
```

Empat lapis pemeriksaan:

1. **Twofish KAT** — vektor Twofish buku B.2 (I=3).
2. **Paritas backend** — native vs Python murni harus identik.
3. **EAX vs pycryptodome** — 14 kombinasi header/panjang. Lewati (skip, bukan
   gagal) kalau pycryptodome tidak terpasang.
4. **Roundtrip berkas nyata** — decrypt → encrypt → decrypt lagi.

Status terverifikasi:

```
PASS test_twofish_known_answer       Twofish KAT (B.2 I=3)
PASS test_twofish_backends_agree     native == pure-Python Twofish (12 blocks)
PASS test_eax_matches_pycryptodome   EAX == pycryptodome AES-EAX (14 combos)
PASS test_obfuscation_is_an_involution

python3 selftest.py "soal.pka"
PASS roundtrip soal.pka (1075605 B in → 17675452 B xml → 1066463 B out)
```

> Berkas hasil encrypt tidak selalu *byte-identical* dengan aslinya karena
> level kompresi zlib bisa berbeda antar build Python. Yang dijamin adalah
> `decrypt_pka(encrypt_pka(xml)) == xml`. Packet Tracer membaca keduanya
> sebagai berkas yang sama.

## 11. Berkas plugin

| Berkas | Isi |
|---|---|
| `plugin.yaml` | manifest + tool + config |
| `pka2xml_local.py` | crypto: Twofish, EAX, obfuscate, zlib |
| `twofish_pure.py` | Twofish Python murni (fallback) |
| `pka_inspect.py` | parser XML: device, link, addressing, rubrik |
| `pka_solve.py` | transplant answer key + `no shutdown` |
| `report.py` | laporan markdown hasil |
| `tools.py` | handler tool yang dipanggil Hermes |
| `selftest.py` | self-check |
| `skills/pka-solver-local/SKILL.md` | panduan skill |

## 12. Batasan

- Butuh file `.pka` yang punya **answer key** di blok 2. `.pka` soal yang
  belum pernah diselesaikan/di graded tidak punya config jawaban.
- `twofish_pure.py` hanya mendukung kunci 16 byte — cukup untuk PKA dan
  NETS. Kunci 24/32 byte ditolak dengan jelas, bukan diam-diam salah.
- Plug-in ini tidak membuat jawaban dari nol: ia memindahkan config jawaban
  yang sudah ada di dalam file. Untuk `.pka` tanpa answer key, pakai
  `pka_inspect` untuk membaca soal lalu kerjakan manual.
- Port pka2xml resmi 针对 Packet Tracer 7.3.1; versi lebih baru bisa
  berubah. Kalau `decrypt` gagal dengan pesan tag EAX, cek versi PT di
  `pka_inspect`.