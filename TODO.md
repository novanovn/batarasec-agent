# batarasec-agent — TODO
> Managed by: **Bisma/Yudhistira**
> Last updated: 2026-05-25
> Phase 1: Direct mode only (no relay)

---

## Legend
- **Main task**: parent `##` group that owns the work item. Example: `Phase 1 — Core Agent`.
- **Subtask**: stable ID within the main task, formatted as `<GROUP>-<NN>`. Example: `CORE-01`.
- **Priority**: P1 critical · P2 high · P3 nice-to-have
- **Status**: `backlog` · `in_progress` · `obsolete` · `done`
- **Est**: rough estimate assuming no blockers

### Required task format
```md
### [CATEGORY] Short task title
- **Main task**: Parent `##` section name
- **Subtask**: GROUP-01
- **Owner**: Agent name(s)
- **Status**: backlog
- **Priority**: P1
- **Est**: ~1 jam
- **Scope**: What will be changed
- **Done when**: Clear completion criteria
```

---

## Phase 1 — Core Agent

### [CORE] CLI skeleton (cobra + viper)
- **Main task**: Phase 1 — Core Agent
- **Subtask**: CORE-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Entry point `cmd/batarasec-agent/main.go`; subcommands `enroll`, `scan`, `status`, `version`; config loader via viper from `/etc/batarasec/agent.yaml`; structured `zap` logging; bbolt cache at `/var/lib/batarasec/cache.db`.
- **Done when**: `batarasec-agent scan --dry-run` runs, config loads, and logs are structured.
- **Commit**: `f4dd83d` Phase 1 implementation; `b9857f5` multi-agent workflow docs.
- **Verified**: 2026-05-13 `go run ./cmd/batarasec-agent version`, `go run ./cmd/batarasec-agent scan --dry-run`, and `go test ./...` passed.
- **Evidence**: `cmd/batarasec-agent/main.go`, `scan.go`, `enroll.go`, `status.go`, `version.go`, `internal/config/config.go`, `go.mod`.

### [CORE] Manifest parsers — npm, Go, Python
- **Main task**: Phase 1 — Core Agent
- **Subtask**: CORE-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~4 jam
- **Depends on**: CORE-01
- **Scope**: Native parser without external binaries for npm lockfiles, Go modules, and Python requirements/lockfiles. Output unified package records `{ecosystem, name, version, filePath}`.
- **Done when**: Parser tests pass for all supported formats and monorepo/nested edge cases are handled.
- **Commit**: `f4dd83d` Phase 1 implementation; `c0c5e93` scanner/vulndb unit coverage.
- **Verified**: 2026-05-13 `go test ./...` passed; parser tests cover npm, Go, and Python formats.
- **Evidence**: `internal/scanner/npm.go`, `gomod.go`, `python.go`, `scanner.go`, `npm_test.go`, `gomod_test.go`, `python_test.go`.

### [CORE] bbolt hash cache + delta detection
- **Main task**: Phase 1 — Core Agent
- **Subtask**: CORE-03
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~2 jam
- **Depends on**: CORE-01
- **Scope**: Store file hashes in bbolt bucket `file_hashes`; process only changed manifests; auto-purge stale entries older than 90 days.
- **Done when**: Second scan only processes changed files and reduces bandwidth for static codebases.
- **Commit**: `f4dd83d` Phase 1 implementation.
- **Verified**: 2026-05-13 code inspection + `go test ./...` passed; scan path uses `db.IsChanged`, `MarkScanned`, `MarkSent`, and `PruneOlderThan`.
- **Evidence**: `internal/cache/cache.go`, `cmd/batarasec-agent/scan.go`.

### [CORE] Offline queue (bbolt)
- **Main task**: Phase 1 — Core Agent
- **Subtask**: CORE-04
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~2 jam
- **Depends on**: CORE-03
- **Scope**: Store unsent findings in bbolt bucket `send_queue`; retry with exponential backoff; drop entries after 7 days.
- **Done when**: Agent does not lose findings when API is unreachable and syncs automatically after connectivity returns.
- **Evidence**: `internal/queue/queue.go`.

---

## Phase 1 — API Integration

### [API] HTTP client to BataraSec platform
- **Main task**: Phase 1 — API Integration
- **Subtask**: API-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~2 jam
- **Depends on**: CORE-01
- **Scope**: HTTP client with timeout, retry, backoff, JWT auth, and `/api/agent/v1/*` endpoint support for heartbeat, scan start, chunk push, scan done, commands, vuln DB pack download, and config.
- **Done when**: Agent can send heartbeat and chunk findings to staging API.
- **Evidence**: `internal/client/client.go`.

### [API] Enroll flow
- **Main task**: Phase 1 — API Integration
- **Subtask**: API-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~1.5 jam
- **Depends on**: API-01
- **Scope**: `batarasec-agent enroll --token <enrollment-token>` sends the project-scoped enrollment token in the Authorization header and stores JWT, agent ID, and project ID in config mode 0600.
- **Done when**: Agent enrolls to platform, token is stored, and scan can run immediately.
- **Evidence**: `cmd/batarasec-agent/enroll.go`, `internal/client/client.go`.

### [API] Platform `/agent/v1` endpoints
- **Main task**: Phase 1 — API Integration
- **Subtask**: API-03
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~3 jam
- **Scope**: Implemented in BataraSec platform repo: enroll, heartbeat, scan start, scan push, scan done, vuln DB pack, and config endpoints.
- **Done when**: Agent can send scan results and all requests are authenticated.
- **Evidence**: `D:\Ngoprek\ngulik\BataraSec\apps\api\src\routes\agentV1.ts`.

### [API] Async scan worker in platform
- **Main task**: Phase 1 — API Integration
- **Subtask**: API-04
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~3 jam
- **Depends on**: API-03
- **Scope**: Platform Redis worker dequeues agent scan pushes, fingerprints findings, and batch upserts to PostgreSQL vulnerabilities.
- **Done when**: Findings from agent appear in BataraSec dashboard.
- **Commit**: `450806c` agent TODO sync plus platform async queue commits.
- **Verified**: Staging E2E 2026-05-13: push returned `202`, queues drained to 0, worker inserted findings, and scan job completed.
- **Evidence**: `D:\Ngoprek\ngulik\BataraSec\apps\api\src\services\agentQueue.ts`, `apps/api/src/workers/agentWorker.ts`, `apps/api/src/routes/agentV1.ts`.

---

## Phase 1 — Vulnerability Matching

### [VULN] Trivy-DB mirror in platform
- **Main task**: Phase 1 — Vulnerability Matching
- **Subtask**: VULN-01
- **Owner**: Yudhistira
- **Status**: obsolete
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Trivy-DB mirror architecture was replaced by OSV.dev bulk download + platform-served vuln packs.
- **Done when**: Replaced by VULN-02.

### [VULN] OSV.dev bulk download + vuln packs in platform
- **Main task**: Phase 1 — Vulnerability Matching
- **Subtask**: VULN-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~3 jam
- **Scope**: Platform downloads OSV.dev `all.zip` per ecosystem, parses packs into gzip JSON, and serves them through `/api/agent/v1/vuln-db/pack?eco=npm|go|python|packagist`.
- **Done when**: Platform serves vuln DB packs and agent downloads/matches CVEs without direct internet access.
- **Verified**: Staging 2026-05-13 returned pack sizes > 0; agent JWT pack download returned `200 application/gzip`; API force-recreate preserved packs.
- **Evidence**: Platform `apps/api/src/services/osvDbSync.ts`, `docs/VULN_DB_SYNC.md`, `apps/api/src/routes/agentV1.ts`, `docker-compose.full.yml`.

### [VULN] Local vulnerability matching engine
- **Main task**: Phase 1 — Vulnerability Matching
- **Subtask**: VULN-03
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~3 jam
- **Depends on**: CORE-02, VULN-02
- **Scope**: Download vuln packs, load gzip JSON from `/var/lib/batarasec/vuln-db/`, and match package/version records to CVE findings via semver constraints or fixed versions.
- **Done when**: Agent scan on npm/Go/Python projects finds CVEs from local packs.
- **Evidence**: `internal/vulndb/vulndb.go`, `internal/vulndb/vulndb_test.go`.

---

## Phase 1 — Distribution

### [DIST] Install script + systemd
- **Main task**: Phase 1 — Distribution
- **Subtask**: DIST-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Linux installer detects OS/arch, downloads binary, verifies checksum when available, creates config, and installs systemd service/timer.
- **Done when**: One-line installer flow works on Ubuntu 22.04+.
- **Evidence**: `scripts/install.sh`, `scripts/systemd/batarasec-agent.service`, `scripts/systemd/batarasec-agent.timer`.

### [DIST] Cross-compile + release pipeline
- **Main task**: Phase 1 — Distribution
- **Subtask**: DIST-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Build linux/amd64 and linux/arm64 release artifacts with checksums.
- **Done when**: Tagged release builds reproducible agent binaries.
- **Evidence**: `Makefile`, release/build artifacts.

### [DIST] GitHub Releases manifest artifacts
- **Main task**: Phase 1 — Distribution
- **Subtask**: DIST-03
- **Owner**: Yudhistira + VmAgent
- **Status**: done
- **Worked**: 2026-05-24 — added `scripts/generate-release-manifest.sh` and `make manifest` for GitHub Releases-compatible `manifest.json` generation.
- **Worked**: 2026-05-25 — added GoReleaser `.tar.gz` archives alongside raw binaries and manifest archive metadata (`archiveUrl`, `archiveSha256`, `archiveSizeBytes`) while preserving raw binary fields for older platforms.
- **Priority**: P2
- **Est**: ~2 jam
- **Depends on**: Platform LRG-26 validated in `D:\Ngoprek\ngulik\BataraSec` commit `1c07a5d`; platform archive upload/sync validated in commit `176969c`.
- **Scope**: Publish release assets in GitHub Releases-compatible layout and generate `manifest.json` with `githubReleases[].assets[]` entries for Linux amd64/arm64 and future Windows amd64. Include `version`, `releaseDate`, `channel`, release notes, filename, URL, SHA256, sizeBytes, and optional archive metadata for `.tar.gz` assets.
- **Done when**: A tagged agent release exposes `manifest.json`, raw binaries, and `.tar.gz` archives; BataraSec platform worker sync imports the manifest, prefers archives when available, validates checksum and ELF/PE magic, and caches the extracted raw binary without requiring MinIO.
- **Platform contract**: `AGENT_RELEASE_MANIFEST_URL=https://github.com/<org>/batarasec-agent/releases/latest/download/manifest.json`; asset URLs should point to GitHub release downloads; flat platform `releases[]` remains supported but official agent releases should use `githubReleases[].assets[]`.
- **Testing gate**: PASS — `bash -n scripts/generate-release-manifest.sh`; temp-dist generator smoke produced valid JSON for `v1.2.3` with GitHub asset URL, SHA256, and sizeBytes; `go test ./...` passed. Follow-up PASS: platform WSL staging commit `176969c` accepted `.tar.gz` Admin upload, stored extracted raw Linux binary with ELF magic `7f454c46`, and user manually confirmed latest agent install succeeds. Generated `dist/manifest*.json` and binary/archive artifacts are not intended for normal docs/source commits.

---

## Bug Fixes & Tech Debt

### [BUG] parseGoMod single-line require silently dropped
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: BUG-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~30 menit
- **Scope**: Fix Go module parser to support single-line `require`.
- **Done when**: Go parser tests include and pass single-line require coverage.
- **Evidence**: `internal/scanner/gomod.go`, `internal/scanner/gomod_test.go`.

### [BUG] Cache marked scanned despite partial send failure
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: BUG-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~30 menit
- **Scope**: Only mark cache entries as sent/scanned when send succeeds.
- **Done when**: Failed send does not hide findings from future retries.
- **Evidence**: `cmd/batarasec-agent/scan.go`.

### [BUG] Duplicate findings from go.mod + go.sum
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: BUG-03
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~30 menit
- **Scope**: Deduplicate findings generated from overlapping Go manifest sources.
- **Done when**: Same package/version finding is not sent twice from one scan.
- **Evidence**: `cmd/batarasec-agent/scan.go`.

### [SECURITY] Limit vuln DB download size
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: SEC-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~20 menit
- **Scope**: Add a 500MB limit while downloading vulnerability DB packs.
- **Done when**: A malicious or broken server response cannot fill disk indefinitely.
- **Evidence**: `internal/client/client.go`.

### [SECURITY] Reduce queue entry ID collision risk
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: SEC-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~20 menit
- **Scope**: Include random suffix in queue entry IDs instead of relying only on `UnixNano`.
- **Done when**: High-frequency enqueues have lower collision risk.
- **Evidence**: `internal/queue/queue.go`.

### [REFACTOR] Use `filepath.Dir`
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: REF-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P3
- **Est**: ~15 menit
- **Scope**: Replace custom path directory helper with `filepath.Dir`.
- **Done when**: Path handling uses standard library helper.
- **Evidence**: `cmd/batarasec-agent/scan.go`.

### [SECURITY] Warn when TLS verify is disabled
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: SEC-03
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~15 menit
- **Scope**: Log an explicit warning when `tls_skip_verify` is enabled.
- **Done when**: Insecure TLS mode is visible in logs.
- **Evidence**: `internal/client/client.go`.

### [TEST] Unit tests for parser and vuln matching
- **Main task**: Bug Fixes & Tech Debt
- **Subtask**: TEST-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~2 jam
- **Scope**: Add unit tests for Go/npm/Python parsers and vuln matching.
- **Done when**: `go test ./...` passes with scanner and vulndb coverage above 70%.
- **Commit**: `c0c5e93`.
- **Verified**: `go test ./...` passed; `go test ./internal/scanner ./internal/vulndb -cover` showed scanner 71.5%, vulndb 86.3%.
- **Evidence**: `internal/scanner/gomod_test.go`, `internal/scanner/npm_test.go`, `internal/scanner/python_test.go`, `internal/vulndb/vulndb_test.go`.

---

## Phase 2 — Backlog
> Do not start before Phase 1 stays stable after partner/customer feedback.
> Handoff 2026-05-23 from platform repo `D:\Ngoprek\ngulik\BataraSec` branch `feat/next-features-p2-k8s`: next requested agent-Go-first work is loaded kernel modules audit, Lynis/OpenSCAP CIS checks, and differential report. Keep platform changes limited to API/UI compatibility follow-up only if the agent payload needs it.

### [CORE] Platform-triggered agent uninstall
- **Main task**: Phase 2 — Backlog
- **Subtask**: CORE-05
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~1 jam
- **Scope**: Recognize `uninstall_agent` command in poll loop. Report completion to API, then execute self-deletion script (background shell) to stop/disable systemd service/timer and remove `/etc/batarasec`, `/var/lib/batarasec`, and binary.
- **Done when**: Agent picks up `uninstall_agent` command, reports it, and successfully removes its own files and service.
- **Evidence**: `cmd/batarasec-agent/poll.go`.

### [CORE] Configurable scan paths
- **Main task**: Phase 2 — Backlog
- **Subtask**: CORE-06
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~1 jam
- **Scope**: Support `--scan-paths` in `install.sh` and `enroll` command. Persist custom paths in config. Fallback to defaults if none configured. Validate absolute paths in `enroll`.
- **Done when**: Agent can be installed/enrolled with custom paths, and both `scan` and `watch` use those paths correctly.
- **Evidence**: `scripts/install.sh`, `cmd/batarasec-agent/enroll.go`, `scan.go`, `watch.go`.

### [AGENT-P2] Lynis/OpenSCAP CIS checks
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-01
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~4 jam
- **Scope**: Detect Lynis/OpenSCAP availability, run safe non-interactive CIS-style checks with timeouts, parse reports into unified posture findings with ruleId/evidence/severity/remediation. Prefer Lynis first if both tools are too large for one pass.
- **Done when**: CIS findings from Lynis/OpenSCAP are emitted as posture findings and displayed by the platform without breaking existing hardening_lite output.
- **Worked**: 2026-05-23 — Implemented `checkCISTools()` in `internal/scanner/cis.go`. Lynis preferred, OpenSCAP fallback. Both use 2-minute timeout. Lynis: parses bracket `[SSH-7408]` and pipe `FINT-4350|desc|-|-|` formats. OpenSCAP: no `--fetch-remote-resources`. Verified on `awan-vm-bastion` customer: 56 LYNIS-* posture findings sent.
- **Commit**: `2798159` feat: add AP2 posture checks and safe delta baseline
- **Improvement**: 2026-05-23 — Added `parseLynisValue()` to handle pipe-delimited Lynis format (`FINT-4350|description|...`), producing specific rule IDs (e.g., `LYNIS-FINT-4350`) and clean titles instead of `LYNIS-GENERIC`. Tests added in `cis_test.go`.

### [AGENT-P2] Docker/container runtime audit
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-02
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P1
- **Est**: ~2 jam
- **Scope**: Detect privileged containers (DKR-002), host networking (DKR-004), Docker socket mounts (DKR-001), root users (DKR-005), sensitive host mounts (DKR-003), and insecure port bindings (DKR-006).
- **Done when**: Misconfigured containers are reported as posture findings with RuleIDs DKR-001 to DKR-006.
- **Worked**: 2026-05-16 — Implemented DKR-001..DKR-006 using `docker inspect` parsing. Verified with local vulnerable containers (privileged, socket mount, shadow mount, root user, host network, public port binding).
- **Commit**: `feat: implement AP2-02 Docker runtime audit (DKR-001..006)`

### [AGENT-P2] File integrity monitoring
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-03
- **Owner**: Yudhistira
- **Status**: backlog
- **Priority**: P2
- **Est**: ~3 jam
- **Scope**: Baseline hashes for critical files and report unexpected changes.
- **Done when**: Changes to critical system files are detected between scans.

### [AGENT-P2] Loaded kernel modules audit
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-04
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~1.5 jam
- **Scope**: Collect `lsmod`, enrich modules with `modinfo`, check package ownership with `dpkg -S` or `rpm -qf` when available, and flag unsigned/unknown/suspicious modules as posture findings. Use strict command timeouts and skip gracefully when commands are unavailable.
- **Done when**: Unsigned, unknown, or suspicious kernel modules are reported with evidence and normal distro modules do not create noisy false positives.
- **Worked**: 2026-05-23 — Implemented `checkKernelModules()` in `internal/scanner/kernel.go`. Rules: KMOD-001 (suspicious name/path, high), KMOD-002 (missing modinfo metadata, medium), KMOD-003 (no package owner, medium), KMOD-004 (unsigned, low). Graceful skip when `lsmod` unavailable. Verified: no false positives on normal VM (expected behavior).
- **Commit**: `2798159` feat: add AP2 posture checks and safe delta baseline

### [AGENT-P2] Windows agent
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-05
- **Owner**: Yudhistira
- **Status**: backlog
- **Priority**: P3
- **Est**: ~8 jam
- **Scope**: Add Windows agent support using PowerShell/Scheduled Task and Windows hardening checks.
- **Done when**: Agent installs and scans on Windows Server 2019/2022.

### [AGENT-P2] macOS agent
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-06
- **Owner**: Yudhistira
- **Status**: backlog
- **Priority**: P3
- **Est**: ~4 jam
- **Scope**: Add macOS install/run support via LaunchDaemon and macOS hardening checks.
- **Done when**: Agent installs and scans on macOS 13+.

### [AGENT-P2] mTLS mutual authentication
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-07
- **Owner**: Yudhistira
- **Status**: backlog
- **Priority**: P2
- **Est**: ~4 jam
- **Scope**: Add certificate-based agent authentication in addition to JWT.
- **Done when**: Platform can require mTLS for agent traffic.

### [AGENT-P2] Signed auto-update
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-08
- **Owner**: Yudhistira
- **Status**: backlog
- **Priority**: P2
- **Est**: ~4 jam
- **Scope**: Download approved updates, verify signature/checksum, and apply only after platform approval.
- **Done when**: Admin-approved agent updates are verified before execution.

### [AGENT-P2] Real-time scan progress
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-09
- **Owner**: Yudhistira
- **Status**: backlog
- **Priority**: P3
- **Est**: ~6 jam
- **Scope**: Emit per-stage progress events for API/UI real-time display.
- **Done when**: UI can show module-level scan progress without guessing from status only.

### [AGENT-P2] Differential report (delta only)
- **Main task**: Phase 2 — Backlog
- **Subtask**: AP2-10
- **Owner**: Yudhistira
- **Status**: done
- **Priority**: P2
- **Est**: ~3 jam
- **Scope**: Send a full baseline on first scan, then send only new/resolved findings on follow-up scans when the platform supports delta merge. Keep a full-report fallback for incompatible servers or cache reset.
- **Done when**: Follow-up scans send much smaller payloads while server state remains accurate, and first scan/server-incompatible cases still work with full reports.
- **Worked**: 2026-05-23 — Implemented `shouldUpdateVulnerabilityBaseline()` in `cmd/batarasec-agent/scan.go`. Partial/manifest-delta scans skip baseline update (returns false), preventing incorrect baseline from partial data. Full scans update baseline as before. Verified: log showed `"vulnerability delta baseline skipped because scan used partial manifest delta"` on partial scan.
- **Commit**: `2798159` feat: add AP2 posture checks and safe delta baseline

---

## Progress Summary

| Area | Status |
|------|--------|
| Core Agent | Phase 1 done |
| API Integration | Phase 1 done |
| Vulnerability Matching | Phase 1 done |
| Distribution | Phase 1 done |
| Phase 2 | Backlog |

**Current note**: Phase 1 direct-mode agent verified on staging. DIST-03 now publishes raw binaries plus `.tar.gz` archives with manifest archive metadata, validated through platform WSL staging and user install on 2026-05-25. AP2-01 (CIS/Lynis), AP2-04 (kernel modules), AP2-10 (delta baseline) implemented and verified on customer `192.168.132.233`. Lynis pipe-delimited parser improvement added 2026-05-23 for specific rule IDs (`LYNIS-FINT-4350`, etc.) instead of `LYNIS-GENERIC`.
