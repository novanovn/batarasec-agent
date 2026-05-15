# batarasec-agent

Go security agent untuk [BataraSec Platform](https://github.com/batarasec).

---

## Apa Ini?

`batarasec-agent` adalah daemon ringan yang di-install di VM customer. Agent menjalankan security scan secara otomatis dan mengirim hasilnya ke BataraSec dashboard — **tanpa perlu CI/CD pipeline**.

**Tujuan utama**: Mengakomodir customer yang belum mengimplementasi CI/CD (GitLab CI, GitHub Actions, Jenkins). Dengan agent, mereka tetap bisa menikmati manfaat security scanning otomatis seperti tim yang sudah punya pipeline.

```
Tanpa agent (butuh CI/CD):          Dengan agent:
GitLab CI → trivy scan              batarasec-agent scan
         → POST /scan/upload   VS            → POST /agent/v1/scan/push
         → Dashboard ✅                      → Dashboard ✅
```

---

## Cara Kerja

```
VM Customer
├── batarasec-agent (daemon, systemd timer setiap 6 jam)
│   ├── Scan manifest files (package-lock.json, go.sum, composer.lock, dll)
│   ├── Download vuln-db dari platform (BataraSec Intelligence)
│   ├── Match packages → CVE findings
│   ├── Hardening checks (SSH, firewall, permissions)
│   ├── Secret detection (hardcoded credentials)
│   └── Kirim findings → BataraSec API
│
└── Tidak ada Trivy, tidak ada binary dependency lain
    Hanya satu binary Go ~15MB
```

**Komunikasi**: semua HTTPS, agent-initiated. Tidak ada inbound connection ke VM.

---

## Quick Start

### Install (satu command)

```bash
curl -sSL https://your-batarasec-instance.com/agent/install.sh | sudo bash
```

### Manual install

```bash
# Download binary
wget https://github.com/batarasec/batarasec-agent/releases/latest/download/batarasec-agent_linux_amd64.tar.gz
tar -xzf batarasec-agent_linux_amd64.tar.gz
sudo mv batarasec-agent /usr/local/bin/

# Enroll ke platform
batarasec-agent enroll --token <enrollment-token-dari-dashboard>

# Test scan
batarasec-agent scan --dry-run

# Lihat status
batarasec-agent status
```

---

## Commands

```bash
batarasec-agent enroll --token <TOKEN>   # Daftarkan agent ke platform
batarasec-agent scan                     # Jalankan scan sekarang
batarasec-agent scan --dry-run           # Scan tanpa kirim ke platform
batarasec-agent status                   # Lihat status terakhir
batarasec-agent version                  # Versi binary
```

---

## Konfigurasi

Config disimpan di `/etc/batarasec/agent.yaml` (mode 0600, owner root):

```yaml
platform_url: "https://batarasec.example.com"
agent_id: <uuid>          # diisi otomatis saat enroll
project_id: <uuid>        # diisi otomatis saat enroll
token: <jwt>              # diisi otomatis saat enroll

scan_paths:
  - /home
  - /opt
  - /srv
  - /var/www

log_level: info
tls_skip_verify: false    # set true hanya untuk self-signed cert
```

---

## Modules

### Phase 1 (tersedia sekarang)

| Module | Fungsi |
|--------|--------|
| `dependency_scan` | Scan manifest files → match CVE via BataraSec Intelligence |
| `hardening_lite` | 15 CIS benchmark checks (SSH, firewall, permissions, dll) |
| `secret_detection` | Detect hardcoded credentials, API keys, private keys *(coming soon)* |
| `exposed_files` | Detect .env, .git, backup files yang exposed *(coming soon)* |
| `ssl_expiry` | Cek sertifikat SSL yang akan expired *(coming soon)* |

### Phase 2 (roadmap)

| Module | Fungsi |
|--------|--------|
| `file_watcher` | File integrity monitoring — detect perubahan file kritis |
| `log_monitor` | Parse auth.log, syslog — detect brute force, intrusion |
| `session_tracker` | Audit siapa login ke server, dari IP mana |
| `container_scan` | Scan Docker images (butuh grype/trivy di VM) |
| `os_package_scan` | Scan OS packages via apt/rpm |

Lihat [ROADMAP.md](docs/ROADMAP.md) untuk detail lengkap.

---

## Supported Ecosystems

| Ecosystem | File | Status |
|-----------|------|--------|
| npm / Node.js | `package-lock.json` v1/v2/v3 | ✅ |
| Go | `go.sum` + `go.mod` | ✅ |
| Python | `requirements.txt`, `Pipfile.lock`, `poetry.lock` | ✅ |
| PHP | `composer.lock` | ⏳ Coming soon |
| Ruby | `Gemfile.lock` | 📋 Roadmap |
| Java | `pom.xml`, `build.gradle` | 📋 Roadmap |

---

## Supported Platforms

| OS | Arch | Status |
|----|------|--------|
| Ubuntu 20.04+ | amd64, arm64 | ✅ |
| Debian 11+ | amd64, arm64 | ✅ |
| RHEL / Rocky / Alma 8+ | amd64, arm64 | ✅ |
| CentOS 7+ | amd64 | ✅ |
| Windows Server | amd64 | 📋 Phase 3 |
| macOS | amd64, arm64 | 📋 Phase 3 |

---

## Tech Stack

- **Language**: Go 1.22+
- **CLI**: cobra + viper
- **Logging**: zap (structured JSON)
- **Local storage**: bbolt (embedded KV, no server)
- **HTTP**: stdlib `net/http`
- **Build**: goreleaser

**Zero external runtime dependency** — pure static binary, tidak butuh runtime apapun di VM.

---

## Development

```bash
# Build
make build

# Cross-compile (linux/amd64 + linux/arm64)
make cross

# Test
go test ./...

# Run locally
go run ./cmd/batarasec-agent scan --dry-run
```

### Struktur Folder

```
batarasec-agent/
├── cmd/batarasec-agent/     ← entry point + subcommands
├── internal/
│   ├── cache/               ← bbolt hash cache (delta detection)
│   ├── client/              ← HTTP client ke BataraSec API
│   ├── config/              ← viper config loader
│   ├── queue/               ← offline queue (retry saat API down)
│   ├── scanner/             ← manifest parsers (npm, go, python)
│   └── vulndb/              ← local vuln DB matching
├── pkg/findings/            ← shared Finding type
└── scripts/
    ├── install.sh           ← one-liner installer
    └── systemd/             ← service + timer units
```

---

## Runtime Paths (di VM customer)

```
/usr/local/bin/batarasec-agent    ← binary
/etc/batarasec/agent.yaml         ← config + token (mode 0600)
/var/lib/batarasec/cache.db       ← bbolt cache
/var/lib/batarasec/vuln-db/       ← vulnerability packs dari platform
/var/lib/batarasec/queue/         ← offline queue
/var/log/batarasec/agent.log      ← logs (rotated 7 hari)
```

---

## Security

- Config file mode 0600 (credentials di dalamnya)
- Token tidak pernah di-log (di-replace dengan `***`)
- Agent tidak pernah kirim file content ke platform — hanya path dan metadata
- Scan berjalan dengan nice 19 + ionice idle — tidak mengganggu workload lain
- Scan timeout 30 menit (hard kill)
- Offline queue max 7 hari, auto-purge

---

## Koneksi ke Platform

```
POST /api/agent/v1/enroll          ← daftar agent, dapat JWT
POST /api/agent/v1/heartbeat       ← ping setiap 30 menit
POST /api/agent/v1/scan/start      ← buat scan job
POST /api/agent/v1/scan/:id/push   ← kirim findings (chunk 100)
POST /api/agent/v1/scan/:id/done   ← finalize scan
GET  /api/agent/v1/vuln-db/pack    ← download vuln DB pack
GET  /api/agent/v1/config          ← pull config dari platform
```

Auth: JWT Bearer token (365 hari, disimpan di config setelah enroll).

---

## Docs

- [ROADMAP.md](docs/ROADMAP.md) — Phase 1, 2, 3 roadmap
- [TODO.md](TODO.md) — Task backlog
- [CLAUDE.md](CLAUDE.md) — Instruksi untuk AI agent

---

## License

Apache 2.0 — lihat [LICENSE](LICENSE)
