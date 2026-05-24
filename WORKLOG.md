# batarasec-agent Worklog

## Active Work
- Task group: Phase 2 — AP2-01 Lynis/OpenSCAP CIS checks, AP2-04 Kernel modules audit, AP2-10 Delta baseline + Lynis parser improvement
- Branch: feat/next-features
- Last worked: 2026-05-24 docs sync after platform installer staging validation; AP2 implementation status unchanged from 2026-05-23
- Related platform repo: `D:\Ngoprek\ngulik\BataraSec` branch `feat/next-features-p2-k8s`

## Current State
- Phase 1 agent scope is complete for direct mode: CLI, manifest parsers, local cache, offline queue, enrollment, scan push, command polling, watcher-triggered scans, local vuln matching, and Linux distribution artifacts.
- **AP2-01** (CIS checks): `checkCISTools()` implemented in `internal/scanner/cis.go`. Lynis preferred over OpenSCAP. 2-minute timeout. Handles two Lynis report formats: bracket (`[SSH-7408]`) and pipe-delimited (`FINT-4350|description|-|-|`). Verified: 56 LYNIS-* posture findings on `awan-vm-bastion` (customer `192.168.132.233`).
- **AP2-04** (Kernel modules): `checkKernelModules()` in `internal/scanner/kernel.go`. Rules KMOD-001..004. Graceful skip when `lsmod` unavailable. No false positives on normal customer VM.
- **AP2-10** (Delta baseline): `shouldUpdateVulnerabilityBaseline()` in `cmd/batarasec-agent/scan.go`. Skips baseline update on partial/manifest-delta scans; only updates on full scans.
- **Lynis parser improvement** (2026-05-23): Added `parseLynisValue()` and `lynisRuleID` regex in `cis.go`. Pipe-delimited format now produces `LYNIS-FINT-4350`, `LYNIS-KRNL-5830`, etc. instead of `LYNIS-GENERIC`. Tests added: `TestParseLynisValue`, `TestParseLynisReportPipeFormat`. All 28 tests pass.
- Platform installer follow-up committed in `D:\Ngoprek\ngulik\BataraSec` as `0dd9f4f`: fresh setup warns+continues when no local agent binary is seeded, writes `INSTALL_SUMMARY.txt`, clarifies OSV skip guidance, and passed WSL staging clean reinstall. This does not change AP2 agent code status.
- Platform LRG-26 committed in `D:\Ngoprek\ngulik\BataraSec` as `1c07a5d`: worker now consumes GitHub Releases-style `githubReleases[].assets[]` manifests and WSL staging validated sync of `github-69a5d06`.
- DIST-03 completed 2026-05-24: added `scripts/generate-release-manifest.sh`, `make manifest`, README contract docs, and roadmap/TODO updates for GitHub Releases manifest generation. Validation PASS: `bash -n scripts/generate-release-manifest.sh`, temp-dist manifest smoke with `v1.2.3`, and `go test ./...`.

## Files Changed (AP2 + Lynis improvement)
- `internal/scanner/cis.go` — AP2-01: `checkCISTools`, `runLynis`, `parseLynisReport`, `parseLynisValue`, `runOpenSCAP`, `parseOpenSCAPOutput`
- `internal/scanner/cis_test.go` — tests for CIS tools, Lynis bracket format, Lynis pipe format, OpenSCAP, no-fetch-remote-resources guard
- `internal/scanner/kernel.go` — AP2-04: `checkKernelModules`, KMOD-001..004
- `internal/scanner/posture.go` — wires `checkKernelModules` and `checkCISTools` into `RunPostureChecks`
- `cmd/batarasec-agent/scan.go` — AP2-10: `shouldUpdateVulnerabilityBaseline` skips partial scans
- `TODO.md` — AP2-01, AP2-04, AP2-10 marked done; Lynis parser improvement noted
- `WORKLOG.md` — this file

## Last Verification
- 2026-05-23: `go test ./...` — 28/28 pass after Lynis pipe-delimited parser improvement.
- 2026-05-23: Agent binary `0.1.0-ap2` deployed to customer `192.168.132.233` (`awan-vm-bastion`). Scan sent 58 posture findings: 56 `LYNIS-*`, 2 `SSH-*`. Platform posture_findings table confirmed.
- 2026-05-23: Delta baseline skip confirmed in agent log: `"vulnerability delta baseline skipped because scan used partial manifest delta"`.
- 2026-05-23: KMOD-* rules produced no false positives on normal customer VM (expected: only flagged when truly suspicious modules present).
- 2026-05-16: `go build ./cmd/batarasec-agent/` passed; LRG-20 (uninstall) and LRG-21 (configurable paths) verified.
- 2026-05-15: Phase 1 staging E2E fully verified.

## Blockers / Decisions
- Direct mode remains the focus; relay node is not planned for now.
- Built binaries and `dist/` are local artifacts; do not commit them unless preparing a formal release artifact commit/tag.
- Do not commit `.claude/settings.local.json`, `batarasec-agent.exe`, or `batarasec-agent_linux_amd64` to git.

## Next Step
- Commit agent repo release-manifest source/doc changes if approved: `Makefile`, `scripts/generate-release-manifest.sh`, `README.md`, `TODO.md`, `WORKLOG.md`, and `docs/ROADMAP.md`; do not commit binaries or `.claude/settings.local.json`.
- Commit AP2 source/test changes separately if still uncommitted: `cis.go`, `cis_test.go`, `kernel.go`, `posture.go`, `scan.go`, `TODO.md`, and `WORKLOG.md`; do not sweep unrelated artifacts.
- Rebuild agent binary and redeploy only when preparing a formal agent release or customer retest.
- Remaining P2 backlog: AP2-06 cloud metadata exposure, AP2-07 file integrity monitoring lite, AP2-08 TLS certificate expiry, AP2-12 signed auto-update, AP2-13 real-time progress, AP2-14 Windows agent, AP2-15 macOS agent.
- Platform repo is synced for installer behavior as of commit `0dd9f4f`; customer redeploy should use a later approved commit/tag, not the older blocked `e7364cd` attempt.
