# batarasec-agent — TODO

> Agent: Go security agent binary untuk BataraSec platform
> Last updated: 2026-05-13
> Phase 1: Direct mode only (no relay)

---

## Legend
- **Priority**: P1 critical · P2 high · P3 nice-to-have
- **Status**: `backlog` · `in_progress` · `in_review` · `obsolete` · `done ✅`
- **Est**: rough estimate assuming no blockers

---

## Phase 1 — Core Agent

### ✅ [CORE] CLI skeleton (cobra + viper)
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Entry point `cmd/batarasec-agent/main.go`. Sub-commands: `enroll`, `scan`, `status`, `version`. Config loader via viper dari `/etc/batarasec/agent.yaml` (mode 0600). Structured logging via `zap`. bbolt init di `/var/lib/batarasec/cache.db`.
- **Done when**: `batarasec-agent scan --dry-run` jalan, config loaded, log output JSON

### ✅ [CORE] Manifest parsers — npm, Go, Python
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~4 jam
- **Depends on**: CLI skeleton
- **Scope**: Native parser tanpa external binary. (1) npm: `package-lock.json` v2/v3 → `{name, version}[]`. (2) Go: `go.sum` + `go.mod` → module list. (3) Python: `requirements.txt`, `Pipfile.lock`, `poetry.lock`. Output unified: `{ecosystem, name, version, filePath}[]`.
- **Done when**: Parser test pass untuk semua format; edge cases handled (monorepo, nested node_modules)

### ✅ [CORE] bbolt hash cache + delta detection
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~2 jam
- **Depends on**: CLI skeleton
- **Scope**: bbolt bucket `file_hashes`: key=`sha256(projectId+path)`, value=`{contentHash, scannedAt, sentAt}`. Delta logic: hanya proses file yang contentHash berubah sejak scan terakhir. Auto-purge entries >90 hari.
- **Done when**: Scan kedua hanya proses file yang berubah; bandwidth turun drastis untuk codebase statis

### ✅ [CORE] Offline queue (bbolt)
- **Status**: done ✅
- **Priority**: P2
- **Est**: ~2 jam
- **Depends on**: bbolt hash cache
- **Scope**: bbolt bucket `send_queue`: simpan findings yang gagal dikirim. Retry dengan exponential backoff. Drop setelah 7 hari. Diproses saat koneksi kembali tersedia.
- **Done when**: Agent tidak kehilangan findings saat API tidak reachable; auto-sync saat online kembali

---

## Phase 1 — API Integration

### ✅ [API] HTTP client ke BataraSec platform
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~2 jam
- **Depends on**: CLI skeleton
- **Scope**: HTTP client dengan timeout, retry (3x), exponential backoff. Endpoints: `POST /api/agent/v1/heartbeat`, `POST /api/agent/v1/scan/start`, `POST /api/agent/v1/scan/:jobId/push`, `POST /api/agent/v1/scan/:jobId/done`. Auth: JWT dari config.
- **Done when**: Agent bisa kirim heartbeat dan chunk findings ke staging API

### ✅ [API] Enroll flow
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~1.5 jam
- **Depends on**: HTTP client
- **Scope**: `batarasec-agent enroll --token <enrollment-token>`. Project-scoped API key masuk Authorization header. Simpan JWT + agentId + projectId ke config (mode 0600). Print success dengan agent ID.
- **Done when**: Agent ter-enroll ke platform, token tersimpan di config, bisa langsung scan

### ✅ [API] /agent/v1/ endpoints di platform (Node.js)
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~3 jam
- **Scope**: Buat di repo BataraSec (`D:\Ngoprek\ngulik\BataraSec`). Router `apps/api/src/routes/agentV1.ts`. Endpoints: enroll, heartbeat, scan/start, scan/:jobId/push (chunk 100 findings), scan/:jobId/done, vuln-db/pack, config. Live di staging — semua endpoint return 401 (auth middleware aktif).
- **Done when**: Agent bisa kirim scan results; semua request authenticated ✅

### ✅ [API] Async scan worker di platform
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~3 jam
- **Depends on**: /agent/v1/ endpoints
- **Scope**: Worker di platform: dequeue dari Redis, fingerprint findings, batch upsert ke PostgreSQL `vulnerabilities` table. Handle dedup via `ON CONFLICT DO NOTHING`.
- **Done when**: Findings dari agent tampil di dashboard BataraSec
- **Commit**: `34eaf03` (`BataraSec`)
- **Verified**: staging E2E 2026-05-13: `scan/:jobId/push` returned `202 { accepted: 1, queued: true }`, `scan/:jobId/done` returned `202 { ok: true, queued: true }`, Redis queues drained to 0, worker inserted 1 finding and completed scan job.
- **Evidence**: `apps/api/src/services/agentQueue.ts`, `apps/api/src/workers/agentWorker.ts`, `apps/api/src/index.ts`, `apps/api/src/routes/agentV1.ts`

---

## Phase 1 — Vulnerability Matching

### [VULN] Trivy-DB mirror di platform — OBSOLETE
- **Status**: obsolete
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Arsitektur Trivy-DB mirror diganti oleh OSV.dev bulk download + vuln packs di platform.
- **Done when**: Replaced by `[VULN] OSV.dev bulk download + vuln packs di platform`

### ✅ [VULN] OSV.dev bulk download + vuln packs di platform
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~3 jam
- **Scope**: Di repo BataraSec. Download OSV.dev `all.zip` per ecosystem, parse menjadi `npm.json.gz`, `go.json.gz`, `python.json.gz`, `packagist.json.gz`, serve via `GET /api/agent/v1/vuln-db/pack?eco=npm|go|python|packagist`. Agent tidak query internet langsung.
- **Done when**: Platform serve vuln DB pack; agent bisa download dan match CVEs
- **Commit**: `69f7008` (`BataraSec` persistence follow-up)
- **Verified**: staging 2026-05-13: admin status pack sizes > 0 for npm/go/python/packagist; agent JWT `GET /api/agent/v1/vuln-db/pack?eco=npm` returned `200 application/gzip`; API force-recreate kept packs via `vulndb_data` and logged `Packs exist: true`.
- **Evidence**: `apps/api/src/services/osvDbSync.ts`, `docs/VULN_DB_SYNC.md`, `apps/api/src/routes/agentV1.ts`, `docker-compose.full.yml`

### ✅ [VULN] Local vuln matching engine
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~3 jam
- **Depends on**: Manifest parsers, Trivy-DB mirror
- **Scope**: Download vuln pack dari platform, simpan di `/var/lib/batarasec/vuln-db/`. Matching: `{ecosystem, name, version}` → `[]CVEMatch{cveId, severity, fixedIn}`. Semver range comparison via `Masterminds/semver/v3`.
- **Done when**: Agent scan npm project → temukan CVEs tanpa koneksi ke NVD/ghcr.io

---

## Phase 1 — Distribution

### ✅ [DIST] Install script + systemd
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: `scripts/install.sh` — detect OS+arch, download binary, verify checksum, create config, install systemd timer. `scripts/systemd/batarasec-agent.{service,timer}`.
- **Done when**: `curl https://platform/agent/install.sh | sudo bash` works on Ubuntu 22.04

### ✅ [DIST] Cross-compile + release pipeline
- **Status**: done ✅
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: `.goreleaser.yaml` untuk build `linux/amd64` + `linux/arm64`. `Makefile` dengan target `build`, `cross`, `release`. SHA256 checksums per binary.
- **Done when**: `git tag v0.1.0 && git push --tags` trigger release otomatis

---

---

## Bug Fixes & Tech Debt
> Ditemukan saat code review — 2026-05-11. Semua sudah di-fix oleh Claude Code kecuali unit tests.

### ✅ [BUG] parseGoMod single-line require silently dropped — FIXED
- **File**: `internal/scanner/gomod.go`

### ✅ [BUG] Cache di-mark scanned meski send findings gagal sebagian — FIXED
- **File**: `cmd/batarasec-agent/scan.go`

### ✅ [BUG] Duplicate findings dari go.mod + go.sum — FIXED
- **File**: `cmd/batarasec-agent/scan.go` — fungsi `deduplicateFindings` ditambahkan.

### ✅ [SECURITY] Tidak ada size limit saat download vuln DB — FIXED
- **File**: `internal/client/client.go` — `io.LimitReader` 500 MB ditambahkan.

### ✅ [SECURITY] Queue entry ID collision risk — FIXED
- **File**: `internal/queue/queue.go` — ID sekarang pakai `UnixNano + rand.Int63`.

### ✅ [REFACTOR] Ganti `dirOf` dengan `filepath.Dir` — FIXED
- **File**: `cmd/batarasec-agent/scan.go`

### ✅ [REFACTOR] Log warning saat TLS verify dinonaktifkan — FIXED
- **File**: `internal/client/client.go` — `zap.L().Warn(...)` ditambahkan.

### [TEST] Unit tests untuk parser dan vuln matching
- **Status**: done ✅
- **Priority**: P2
- **Scope**: Unit tests untuk parser dan vuln matching. Prioritas:
  1. `internal/scanner/gomod_test.go` — test go.sum, go.mod (termasuk single-line require)
  2. `internal/scanner/npm_test.go` — test lockfile v1, v2, v3
  3. `internal/scanner/python_test.go` — test requirements.txt, Pipfile.lock, poetry.lock
  4. `internal/vulndb/vulndb_test.go` — test semver matching
- **Done when**: `go test ./...` pass dengan coverage >70% untuk scanner dan vulndb.
- **Commit**: `c0c5e93`
- **Verified**: `go test ./...` pass; `go test ./internal/scanner ./internal/vulndb -cover` => scanner 71.5%, vulndb 86.3%
- **Evidence**: `internal/scanner/gomod_test.go`, `internal/scanner/npm_test.go`, `internal/scanner/python_test.go`, `internal/vulndb/vulndb_test.go`

---

## Ringkasan Progress Phase 1

| Area | Selesai | Total |
|------|---------|-------|
| Core Agent | 4/4 | ✅ |
| API Integration | 4/4 | ✅ |
| Vuln Matching | 2/2 | ✅ |
| Distribution | 2/2 | ✅ |
| **Total** | **Phase 1 core + integration verified on staging** | ✅ |

**Blocking sekarang**: Agent UI/management scope masih menunggu keputusan backend schema/API (`agent_enrollment_tokens`, `agent_commands`, `posture_findings`, dan `scan_jobs.agent_id`). Trivy-DB mirror obsolete; OSV.dev vuln packs verified on staging with persistent volume.

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
- Redeploy: `wsl -e sh -c "cd /opt/batarasec-staging && docker compose up -d"`
- Agent endpoint: `https://172.22.115.76/api/agent/v1/`

### Production
- URL: `https://103.93.160.112`
- SSH: `ssh -i ~/.ssh/batarasec_prod novanovn@103.93.160.112`
- Redeploy: `cd /opt/batarasec && docker compose pull && docker compose up -d`

### Platform repo
- Path: `D:\Ngoprek\ngulik\BataraSec`
- Beberapa task (API endpoints, worker, vuln DB mirror) dikerjakan di repo platform, bukan di sini
