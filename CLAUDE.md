## Project Overview                         
  batarasec-agent adalah binary Go yang di-install di VM customer untuk melakukan
  security scanning otomatis dan mengirimkan hasilnya ke platform BataraSec.
                                                                                                                                              
  Agent berjalan sebagai systemd service, scan setiap 6 jam, kirim findings ke
  BataraSec dashboard tanpa intervensi manual.                                                                                                
                                                                
  ## Tech Stack
  - **Language**: Go 1.22+
  - **CLI**: `cobra` + `viper`
  - **Logging**: `zap` (structured JSON)
  - **Local storage**: `bbolt` (embedded KV, no server)
  - **HTTP**: stdlib `net/http` dengan custom transport
  - **Build/release**: `goreleaser` (raw binaries plus `.tar.gz` release archives)

  ## Struktur Folder
  batarasec-agent/
  ├── cmd/
  │   └── batarasec-agent/
  │       └── main.go          ← entry point
  ├── internal/
  │   ├── config/              ← viper config loader
  │   ├── scanner/             ← manifest parsers (npm, go, python)
  │   ├── cache/               ← bbolt hash cache & delta detection
  │   ├── client/              ← HTTP client ke BataraSec API
  │   ├── vulndb/              ← local vuln DB matching (Trivy-DB)
  │   └── queue/               ← offline queue (bbolt)
  ├── pkg/
  │   └── findings/            ← shared types
  ├── scripts/
  │   └── install.sh           ← one-liner installer
  ├── .goreleaser.yaml
  ├── Makefile
  └── go.mod

  ## Runtime Paths (di VM customer)
  - Binary:  `/usr/local/bin/batarasec-agent`
  - Config:  `/etc/batarasec/agent.yaml` (mode 0600)
  - Cache:   `/var/lib/batarasec/cache.db` (bbolt)
  - Vuln DB: `/var/lib/batarasec/vuln-db/` (Trivy-DB packs)
  - Queue:   `/var/lib/batarasec/queue/` (offline findings)

  ## Target Platforms
  - `linux/amd64` (primary)
  - `linux/arm64`
  - Binary size target: <20MB
  - Zero external runtime dependency (pure static binary)

  ## Release Artifacts
  - GoReleaser publishes raw binaries such as `batarasec-agent_linux_amd64` for backward compatibility.
  - GoReleaser also publishes `.tar.gz` archives such as `batarasec-agent_linux_amd64.tar.gz`; each archive must contain only the expected binary.
  - Release manifests preserve raw `url`/`sha256`/`sizeBytes` fields and add optional `archiveUrl`/`archiveSha256`/`archiveSizeBytes` when archives exist.
  - Do not commit generated binaries, `.tar.gz` files, or `dist/manifest*.json` unless preparing an explicit formal release artifact commit/tag.

  ## Cara Agent Bekerja
  1. Scan manifest files (package-lock.json, go.sum, requirements.txt, dll)
  2. Delta detection: hanya proses file yang berubah sejak scan terakhir (bbolt)
  3. Match packages terhadap local vuln DB (Trivy-DB format)
  4. Kirim findings ke BataraSec API dalam chunks (100 findings/request)
  5. Jika gagal → simpan di offline queue, retry saat online

  ## Koneksi ke Platform BataraSec

  ### API Endpoints yang Dipakai Agent
  POST /agent/v1/heartbeat              ← ping setiap 30 menit
  POST /agent/v1/scan/start             ← buat scan job, dapat job_id
  POST /agent/v1/scan/:jobId/push       ← kirim findings (chunk 100)
  POST /agent/v1/scan/:jobId/done       ← finalize scan
  GET  /agent/v1/vuln-db/pack?eco=npm  ← download vuln DB pack
  GET  /agent/v1/config                 ← pull config dari platform

  ### Auth
  - Phase 1: JWT token (disimpan di config setelah enroll)
  - Phase 2: mTLS mutual certificate (belum diimplementasi)

  ### Platform Repo
  - Path lokal: `D:\Ngoprek\ngulik\BataraSec`
  - Beberapa task (API endpoints, worker, vuln DB mirror) dikerjakan di repo platform

  ## Environment

  ### Staging
  - URL: `https://172.22.115.76`
  - Login: `superadmin` / `Admin1234`
  - Lokasi: WSL Ubuntu di mesin lokal (bukan remote server)
  - Redeploy: `wsl -e sh -c "cd /opt/batarasec-staging && docker compose pull && docker compose up -d"`
  - Agent test endpoint: `https://172.22.115.76/api/agent/v1/`

  ### Production
  - URL: `https://103.93.160.112`
  - SSH: `ssh -i ~/.ssh/batarasec_prod novanovn@103.93.160.112`
  - Redeploy: `cd /opt/batarasec && docker compose pull && docker compose up -d`

  ## Key Rules
  - Pure Go — tidak boleh ada CGo (agar binary static, cross-compile mudah)
  - Zero external binary dependency (tidak wrap trivy binary, parse sendiri)
  - Semua error di-log dengan `zap`, tidak panic kecuali saat startup fatal
  - Config file selalu mode 0600 (credentials di dalamnya)
  - bbolt file tidak boleh diakses concurrent dari dua proses
  - Gunakan `context` untuk semua operasi network (timeout, cancellation)
  - Test coverage minimal untuk parser dan matching engin

## Autonomous Work Policy
Kerjakan semua task dari TODO.md tanpa minta permission untuk:
- Read/Write/Edit file di dalam repo ini
- Menjalankan `go build`, `go test`, `go mod tidy`
- Membuat file dan folder baru sesuai struktur yang sudah didefinisikan
- Menjalankan command yang bersifat read-only (ls, cat, grep, git status, dll)

Hanya minta konfirmasi untuk:
- `git push` ke remote
- Operasi yang menghapus file secara permanen
- Sesuatu yang jelas di luar scope TODO.md

## Git Workflow — Multi-Agent Safety
> Wajib diikuti setiap agent/model sebelum mulai kerja. Berlaku untuk BataraSec (platform) dan batarasec-agent.

1. **Sync dulu** — `git fetch origin && git pull --rebase origin feat/next-features`
2. **Cek status** — `git status --short` — pastikan tidak ada file A/M/??
3. **Kerja** — edit file sesuai task
4. **Test sukses** — baru commit (`git add <file-spesifik>` saja, bukan `git add -A`)
5. **Push** — `git push origin feat/next-features`
6. **Kalau conflict** — jangan force push. Tanya user dulu.
7. **Jangan copy/salin repo** — selalu clone fresh atau git pull

  ## Known Issues / Tech Debt
  > Hasil code review oleh Kiro — 2026-05-11. Di-verify ulang 2026-05-11.

  ### ✅ Bug P1 — `parseGoMod` single-line require silently dropped — FIXED
  - **File**: `internal/scanner/gomod.go`
  - **Fix**: Single-line require sekarang di-handle di blok tersendiri dengan `continue`,
    tidak lagi jatuh ke guard `if !inRequire`.

  ### ✅ Bug P1 — Cache di-mark scanned meski send gagal sebagian — FIXED
  - **File**: `cmd/batarasec-agent/scan.go`
  - **Fix**: `MarkScanned` sekarang hanya dipanggil di dalam blok `else` (no findings)
    atau setelah `sendFindings` sukses. Jika send gagal, file tidak di-mark.

  ### ✅ Security P2 — Tidak ada size limit saat download vuln DB — FIXED
  - **File**: `internal/client/client.go`, fungsi `DownloadVulnDBPack`
  - **Fix**: `io.Copy(f, io.LimitReader(resp.Body, 500<<20))` — cap 500 MB.

  ### ✅ Security P2 — Queue entry ID bisa collision — FIXED
  - **File**: `internal/queue/queue.go`, fungsi `Push`
  - **Fix**: ID sekarang `fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())`.

  ### ✅ Logic P2 — Duplicate findings dari go.mod + go.sum — FIXED
  - **File**: `cmd/batarasec-agent/scan.go`
  - **Fix**: Fungsi `deduplicateFindings` ditambahkan, dedup by `cve_id|package_name|version`
    sebelum findings dikirim.

  ### ✅ Style P3 — `dirOf` reimplements `filepath.Dir` — FIXED
  - **File**: `cmd/batarasec-agent/scan.go`
  - **Fix**: `dirOf` dihapus, diganti `filepath.Dir(cfg.CachePath)`. Import `path/filepath` ditambahkan.

  ### ✅ Style P3 — Tidak ada warning saat TLS verify dinonaktifkan — FIXED
  - **File**: `internal/client/client.go`, fungsi `New`
  - **Fix**: `zap.L().Warn("TLS verification disabled - connections may be insecure")` ditambahkan.

  ### ℹ️ Info — Tidak ada unit test (masih open)
  - **Masalah**: Belum ada file `*_test.go`. Parser dan vuln matching engine adalah bagian
    paling kritis dan paling mudah ditest.
  - **Prioritas test pertama**: `internal/scanner/` (gomod, npm, python) dan `internal/vulndb/`.
