# batarasec-agent —TODO                                                                                                                    
                                                                                                                                              
  > Agent: Go security agent binary untuk BataraSec platform                                                                                  
  > Last updated: 2026-05-10                                                                                                                  
  > Phase 1: Direct mode only (no relay)                                                                                                      
                                                                                                                                              
  ---
                                                                                                                                              
  ## Legend                                                     
  - **Priority**: P1 critical · P2 high · P3 nice-to-have
  - **Status**: `backlog` · `in_progress` · `done`
  - **Est**: rough estimate assuming no blockers

  ---

  ## Phase 1 — Core Agent

  ### [CORE] CLI skeleton (cobra + viper)
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~2 jam
  - **Scope**: Entry point `cmd/batarasec-agent/main.go`. Sub-commands: `enroll`, `scan`, `status`, `version`. Config loader via viper dari
  `/etc/batarasec/agent.yaml` (mode 0600). Structured logging via `zap`. bbolt init di `/var/lib/batarasec/cache.db`.
  - **Done when**: `batarasec-agent scan --dry-run` jalan, config loaded, log output JSON

  ### [CORE] Manifest parsers — npm, Go, Python
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~4 jam
  - **Depends on**: CLI skeleton
  - **Scope**: Native parser tanpa external binary. (1) npm: `package-lock.json` v2/v3 → `{name, version}[]`. (2) Go: `go.sum` + `go.mod` →
  module list. (3) Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`. Output unified: `{ecosystem, name, version, filePath}[]`.
  - **Done when**: Parser test pass untuk semua format; edge cases handled (monorepo, nested node_modules)

  ### [CORE] bbolt hash cache + delta detection
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~2 jam
  - **Depends on**: CLI skeleton
  - **Scope**: bbolt bucket `file_hashes`: key=`sha256(projectId+path)`, value=`{contentHash, scannedAt, sentAt}`. Delta logic: hanya proses
  file yang contentHash berubah sejak scan terakhir. Auto-purge entries >90 hari.
  - **Done when**: Scan kedua hanya proses file yang berubah; bandwidth turun drastis untuk codebase statis

  ### [CORE] Offline queue (bbolt)
  - **Status**: done
  - **Priority**: P2
  - **Est**: ~2 jam
  - **Depends on**: bbolt hash cache
  - **Scope**: bbolt bucket `send_queue`: simpan findings yang gagal dikirim. Retry dengan exponential backoff. Drop setelah 7 hari. Diproses
  saat koneksi kembali tersedia.
  - **Done when**: Agent tidak kehilangan findings saat API tidak reachable; auto-sync saat online kembali

  ---

  ## Phase 1 — API Integration

  ### [API] HTTP client ke BataraSec platform
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~2 jam
  - **Depends on**: CLI skeleton
  - **Scope**: HTTP client dengan timeout, retry (3x), exponential backoff. Endpoints yang dipakai: `POST /agent/v1/heartbeat`, `POST
  /agent/v1/scan/start`, `POST /agent/v1/scan/:jobId/push`, `POST /agent/v1/scan/:jobId/done`. Auth: JWT dari config. gzip compression untuk
  payload besar.
  - **Done when**: Agent bisa kirim heartbeat dan chunk findings ke staging API

  ### [API] Enroll flow
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~1.5 jam
  - **Depends on**: HTTP client
  - **Scope**: `batarasec-agent enroll --token <enrollment-token> --url <platform-url>`. Simpan JWT + projectId ke config. Validasi koneksi ke
   platform setelah enroll. Print success dengan info agent ID.
  - **Done when**: Agent ter-enroll ke platform, token tersimpan di config, bisa langsung scan

  ### [API] /agent/v1/ endpoints di platform (Node.js)
  - **Status**: backlog
  - **Priority**: P1
  - **Est**: ~3 jam
  - **Scope**: Buat di repo BataraSec (`D:\Ngoprek\ngulik\BataraSec`). Router `apps/api/src/routes/agentV1.ts`. Endpoints: heartbeat,
  scan/start, scan/:jobId/push (chunk 100 findings), scan/:jobId/done. Rate limit per agent-id. Semua return 202 Accepted, proses async via
  Redis queue.
  - **Done when**: Agent bisa kirim scan results; API tidak block; semua request authenticated

  ### [API] Async scan worker di platform
  - **Status**: backlog
  - **Priority**: P1
  - **Est**: ~3 jam
  - **Depends on**: /agent/v1/ endpoints
  - **Scope**: Worker di platform: dequeue dari Redis, fingerprint findings, batch upsert ke PostgreSQL `vulnerabilities` table. Handle dedup
  via `ON CONFLICT DO NOTHING`.
  - **Done when**: Findings dari agent tampil di dashboard BataraSec

  ---

  ## Phase 1 — Vulnerability Matching

  ### [VULN] Trivy-DB mirror di platform
  - **Status**: backlog
  - **Priority**: P1
  - **Est**: ~2 jam
  - **Scope**: Di repo BataraSec. Sync Trivy-DB dari `ghcr.io/aquasecurity/trivy-db` harian. Serve sebagai `GET
  /agent/v1/vuln-db/pack?eco=npm` (incremental diff). Agent tidak perlu akses langsung ke internet/ghcr.io.
  - **Done when**: Platform serve vuln DB pack; agent bisa download

  ### [VULN] Local vuln matching engine
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~3 jam
  - **Depends on**: Manifest parsers, Trivy-DB mirror
  - **Scope**: Download vuln pack dari platform, simpan di bbolt `/var/lib/batarasec/vuln-db/`. Matching: `{ecosystem, name, version}` →
  `[]CVEMatch{cveId, severity, fixedIn}`. Semver range comparison.
  - **Done when**: Agent scan npm project → temukan CVEs tanpa koneksi ke NVD/ghcr.io

  ---

  ## Phase 1 — Distribution

  ### [DIST] Install script + systemd
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~2 jam
  - **Depends on**: Semua task Phase 1 core selesai
  - **Scope**: `scripts/install.sh` di-serve dari platform `GET /agent/install.sh`. Detect OS+arch (linux/amd64, linux/arm64). Download binary
   + verify checksum. Create config. Install systemd timer (`OnCalendar=*-*-* 0/6:00:00`). Support: Ubuntu 22.04, Debian 12, RHEL 9, Rocky 9.
  - **Done when**: `curl https://platform/agent/install.sh | sudo bash` works on Ubuntu 22.04

  ### [DIST] Cross-compile + release pipeline
  - **Status**: done
  - **Priority**: P1
  - **Est**: ~2 jam
  - **Scope**: `.goreleaser.yaml` untuk build: `linux/amd64`, `linux/arm64`. GitHub Actions workflow: test → build → release on tag. SHA256
  checksums per binary. Binary size target: <20MB.
  - **Done when**: `git tag v0.1.0 && git push --tags` trigger release otomatis dengan binary siap download

  ---

  ## Phase 2 — Backlog (jangan kerjakan dulu)

  - Hardening checks (SSH, firewall, /etc/shadow, world-writable files, dll)
  - Docker/container runtime audit
  - File integrity monitoring
  - Process baseline & suspicious binary detection
  - Windows agent (PowerShell + Scheduled Task)
  - macOS agent (LaunchDaemon)
  - mTLS mutual authentication
  - Auto-update agent (signed)
  - Real-time scan progress (SSE)
  - Differential report (delta only ke server)

  ---

  ## Environment

  ### Staging (untuk development & testing)
  - URL: `https://172.22.115.76`
  - Login: `superadmin` / `Admin1234`
  - Lokasi: WSL Ubuntu di mesin lokal
  - Docker: `wsl -e sh -c "cd /opt/batarasec-staging && docker compose up -d"`
  - Agent endpoint: `https://172.22.115.76/api/agent/v1/`

  ### Production
  - URL: `https://103.93.160.112`
  - URL: `https://172.22.115.76`
  - Login: `superadmin` / `Admin1234`
  - Lokasi: WSL Ubuntu di mesin lokal
  - Docker: `wsl -e sh -c "cd /opt/batarasec-staging && docker compose up -d"`
  - Agent endpoint: `https://172.22.115.76/api/agent/v1/`

  ### Production
  - URL: `https://103.93.160.112`
  - SSH: `ssh -i ~/.ssh/batarasec_prod novanovn@103.93.160.112`
  - Docker: `cd /opt/batarasec && docker compose up -d`

  ### Platform repo
  - Path: `D:\Ngoprek\ngulik\BataraSec`
  - Beberapa task (API endpoints, worker) dikerjakan di repo platform, bukan di sini