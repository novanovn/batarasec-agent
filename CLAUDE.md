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
  - **Build/release**: `goreleaser`

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