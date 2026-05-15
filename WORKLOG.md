# batarasec-agent Worklog

## Active Work
- Task group: Phase 1 direct-mode agent stabilization and BataraSec platform integration
- Branch: feat/next-features
- Last worked: 2026-05-15 final staging validation with BataraSec platform branch `feat/next-features-worker`
- Related platform repo: `D:\Ngoprek\ngulik\BataraSec`

## Current State
- Phase 1 agent scope is complete for direct mode: CLI, manifest parsers, local cache, offline queue, enrollment, scan push, command polling, watcher-triggered scans, local vuln matching, and Linux distribution artifacts.
- Agent API paths use the BataraSec platform `/api/agent/v1/*` prefix.
- Enrollment uses the project-scoped enrollment token in the Authorization header; the token is not duplicated in the JSON body.
- Scan Now support exists through command polling and command completion reporting.
- Watcher-triggered scans and command-triggered full scans were validated against local/staging BataraSec.
- Local vulnerability DB loading supports both wrapped pack JSON and platform-generated raw entry arrays, with ecosystem fallback from pack filename.
- Vulnerability matching uses `fixedIn` as `<fixedIn` when affected range is absent.
- Vuln DB pack downloads are capped at 500MB.
- Queue entry IDs include a random suffix to reduce collision risk.
- `TODO.md` now follows the BataraSec project format with `Main task`, `Subtask`, `Owner`, `Status`, `Priority`, `Scope`, and `Done when` fields.

## Files In Progress
- `README.md`
- `TODO.md`
- `WORKLOG.md`
- `cmd/batarasec-agent/enroll.go`
- `go.mod`
- `go.sum`
- `internal/client/client.go`
- `internal/queue/queue.go`
- `internal/vulndb/vulndb.go`
- `internal/vulndb/vulndb_test.go`

## Last Verification
- 2026-05-13: `go run ./cmd/batarasec-agent version`, `go run ./cmd/batarasec-agent scan --dry-run`, and `go test ./...` passed for Phase 1 baseline.
- 2026-05-13: parser and vuln DB tests passed; scanner coverage was 71.5% and vuln DB coverage was 86.3%.
- 2026-05-15: BataraSec platform served `https://localhost/agent-binaries/batarasec-agent_linux_amd64` as `200 application/octet-stream` with ELF magic `7f 45 4c 46`.
- 2026-05-15: Fresh WSL install enrolled agent `8263266e-f640-44f1-9ef8-2768085060e9` successfully against BataraSec staging/local HTTPS.
- 2026-05-15: Manual full scan sent findings and completed scan job `ef17f81e-f959-4d6f-bb8f-aba8d6b8b4ae`.
- 2026-05-15: Watcher E2E triggered scans from manifest changes and sent findings in jobs `d3091882-f012-440c-862b-48ecd5662470` and `4d7e886d-8428-49ea-86e4-f2e23ca07ff5`.
- 2026-05-15: UI Scan Now command was picked up by poll timer, forced a full scan, sent 164 findings, and completed job `c88d0e95-2b86-41e7-a84d-3b206dfa4406`.

## Blockers / Decisions
- Direct mode remains the focus; relay node is not planned for now.
- Phase 2 modules should wait until Phase 1 has customer/partner feedback.
- Platform-triggered uninstall and Windows/macOS support are tracked in the BataraSec monorepo TODO rather than active work in this repo.
- Built binaries and `dist/` are local artifacts; do not commit them unless preparing a formal release artifact commit/tag.

## Next Step
- Commit and push Phase 1 stabilization/docs changes from this repo.
- Next feature work should be driven from the BataraSec monorepo TODO: Windows PowerShell install command (`QW-02`) or agent detail/rescan UI (`LRG-12`).
