package main

import (
	"context"
	"crypto/sha1"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/batarasec/agent/internal/cache"
	"github.com/batarasec/agent/internal/client"
	"github.com/batarasec/agent/internal/config"
	"github.com/batarasec/agent/internal/queue"
	"github.com/batarasec/agent/internal/scanner"
	"github.com/batarasec/agent/internal/vulndb"
	"github.com/batarasec/agent/pkg/findings"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Run a security scan immediately",
	Long: `Scans configured paths for vulnerable dependencies.
New findings are chunked (100/request) and sent to BataraSec.
Failed sends are queued locally and retried automatically.`,
	RunE: runScan,
}

var scanDryRun bool
var scanFullScan bool
var fullScanOverride bool

func init() {
	scanCmd.Flags().BoolVar(&scanDryRun, "dry-run", false, "print findings without sending to platform")
	scanCmd.Flags().BoolVar(&scanFullScan, "full-scan", false, "process all manifests without delta cache filtering")
}

func runScan(cmd *cobra.Command, args []string) error {
	_, err := executeScan(scanDryRun)
	return err
}

func executeScan(dryRun bool) (string, error) {
	cfg, err := config.Load()
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}

	if cfg.AgentID == "" && !dryRun {
		return "", fmt.Errorf("agent not enrolled — run: batarasec-agent enroll --token <TOKEN>")
	}

	// Ensure data dirs exist.
	for _, dir := range []string{filepath.Dir(cfg.CachePath), cfg.VulnDBPath} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create dir %s: %w", dir, err)
		}
	}

	db, err := cache.Open(cfg.CachePath)
	if err != nil {
		return "", fmt.Errorf("open cache: %w", err)
	}
	defer db.Close()

	// Send heartbeat before scan.
	if !dryRun && cfg.Token != "" {
		c := client.New(cfg.PlatformURL, cfg.Token, cfg.AgentID, cfg.TLSSkipVerify)
		hbCtx, hbCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer hbCancel()
		if err := c.Heartbeat(hbCtx); err != nil {
			log.Warn("heartbeat failed", zap.Error(err))
		}
	}

	// Load or download vuln DB.
	vdb, err := loadOrDownloadVulnDB(cfg)
	if err != nil {
		log.Warn("failed to load vulnerability database, running posture/hardening checks only", zap.Error(err))
		vdb = nil // Ensure we still run hardening checks
	}

	scanTime := time.Now().UTC()

	scanPaths := cfg.ScanPaths
	if len(scanPaths) == 0 {
		scanPaths = []string{"/home", "/opt", "/srv", "/var/www"}
		log.Info("no scan_paths configured, using defaults", zap.Strings("paths", scanPaths))
	}

	log.Info("scan started", zap.Strings("paths", scanPaths))

	// Discover manifests.
	sc := scanner.New(scanPaths, log)
	results := sc.Scan()
	log.Info("manifests discovered", zap.Int("files", len(results)))

	// Delta: only process files whose content changed.
	var allFindings []findings.Finding
	var changedFiles []scanner.Result

	for _, r := range results {
		changed := scanFullScan || fullScanOverride
		if !changed {
			var err error
			changed, err = db.IsChanged(cfg.ProjectID, r.FilePath, r.ContentHash)
			if err != nil {
				log.Warn("cache check error", zap.String("file", r.FilePath), zap.Error(err))
				changed = true
			}
		}
		if !changed {
			log.Debug("file unchanged, skipping", zap.String("file", r.FilePath))
			continue
		}
		changedFiles = append(changedFiles, r)

		if vdb != nil {
			for _, pkg := range r.Packages {
				allFindings = append(allFindings, vdb.Match(pkg)...)
			}
		}
	}

	// Deduplicate findings by cve_id + package_name + version
	allFindings = deduplicateFindings(allFindings)

	fullVulnerabilitySnapshot := shouldUpdateVulnerabilityBaseline(scanFullScan || fullScanOverride, len(results), len(changedFiles))
	fingerprints := vulnerabilityFingerprints(cfg.ProjectID, allFindings)
	findingDelta := cache.FindingDelta{}
	if fullVulnerabilitySnapshot {
		findingDelta, err = db.FindingDelta(cfg.ProjectID, fingerprints)
		if err != nil {
			log.Warn("finding delta check failed, using full report", zap.Error(err))
		}
	} else {
		log.Info("vulnerability delta baseline skipped because scan used partial manifest delta",
			zap.Int("manifests", len(results)),
			zap.Int("changed_files", len(changedFiles)),
		)
	}

	log.Info("delta detection complete",
		zap.Int("changed_files", len(changedFiles)),
		zap.Int("findings", len(allFindings)),
		zap.Bool("full_vulnerability_snapshot", fullVulnerabilitySnapshot),
		zap.Bool("first_finding_baseline", findingDelta.FirstScan),
		zap.Int("new_finding_fingerprints", len(findingDelta.New)),
		zap.Int("resolved_finding_fingerprints", len(findingDelta.Resolved)),
	)

	// Run posture/hardening checks.
	postureResults := scanner.RunPostureChecks()
	log.Info("posture checks complete", zap.Int("findings", len(postureResults)))

	if len(allFindings) == 0 {
		fmt.Println("No new findings.")
	} else {
		fmt.Printf("Found %d finding(s) across %d changed file(s).\n",
			len(allFindings), len(changedFiles))
	}
	if len(postureResults) > 0 {
		fmt.Printf("Found %d posture finding(s).\n", len(postureResults))
	}

	if dryRun {
		printFindings(allFindings)
		return "", nil
	}

	var jobID string
	if jobID, err = sendFindings(cfg, allFindings, postureResults, changedFiles, db); err != nil {
		log.Error("send failed, queuing", zap.Error(err))
	} else {
		for _, r := range changedFiles {
			_ = db.MarkScanned(cfg.ProjectID, r.FilePath, r.ContentHash)
		}
		if fullVulnerabilitySnapshot {
			_ = db.SetFindingBaseline(cfg.ProjectID, fingerprints)
		}
	}

	// Prune stale cache entries (>90 days).
	pruned, _ := db.PruneOlderThan(90 * 24 * time.Hour)
	if pruned > 0 {
		log.Debug("pruned stale cache entries", zap.Int("count", pruned))
	}

	_ = db.SetMeta("last_scan", scanTime.Format(time.RFC3339))

	// Drain offline queue.
	drainOfflineQueue(cfg)

	return jobID, nil
}

func sendFindings(cfg *config.Config, all []findings.Finding, posture []findings.PostureFinding, changedFiles []scanner.Result, db *cache.DB) (string, error) {
	c := client.New(cfg.PlatformURL, cfg.Token, cfg.AgentID, cfg.TLSSkipVerify)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	jobID, err := c.ScanStart(ctx, cfg.ProjectID)
	if err != nil {
		return "", fmt.Errorf("scan/start: %w", err)
	}

	log.Info("scan job started", zap.String("job_id", jobID))

	// Send vulnerabilities (if any)
	if len(all) > 0 {
		if err := c.SendChunked(ctx, jobID, all); err != nil {
			// Queue the failed chunk for later retry.
			q, qErr := queue.Open(cfg.CachePath + ".queue")
			if qErr == nil {
				defer q.Close()
				_ = q.Push(queue.Entry{
					JobID:    jobID,
					Findings: all,
				})
			}
			return "", fmt.Errorf("send chunks: %w", err)
		}
	}

	// Send posture findings (if any)
	if len(posture) > 0 {
		if err := c.ScanPosturePush(ctx, jobID, posture); err != nil {
			log.Warn("posture push failed", zap.Error(err))
		}
	}

	if err := c.ScanDone(ctx, jobID, len(all)); err != nil {
		return "", fmt.Errorf("scan/done: %w", err)
	}

	log.Info("scan complete", zap.Int("findings_sent", len(all)), zap.Int("posture_sent", len(posture)), zap.String("job_id", jobID))
	fmt.Printf("Sent %d vulnerability and %d posture findings to BataraSec (job: %s)\n", len(all), len(posture), jobID)

	// Mark files as sent.
	for _, r := range changedFiles {
		_ = db.MarkSent(cfg.ProjectID, r.FilePath)
	}
	return jobID, nil
}

func loadOrDownloadVulnDB(cfg *config.Config) (*vulndb.DB, error) {
	vdb, err := vulndb.LoadDir(cfg.VulnDBPath)
	if err == nil {
		return vdb, nil
	}

	if cfg.Token == "" {
		log.Warn("vuln DB missing and agent not enrolled; skipping vuln matching")
		return nil, nil
	}

	log.Info("vuln DB missing, downloading from platform")
	c := client.New(cfg.PlatformURL, cfg.Token, cfg.AgentID, cfg.TLSSkipVerify)

	for _, eco := range []string{"npm", "go", "python"} {
		dest := cfg.VulnDBPath + "/" + eco + ".json.gz"
		dlCtx, dlCancel := context.WithTimeout(context.Background(), 120*time.Second)
		if err := c.DownloadVulnDBPack(dlCtx, eco, dest); err != nil {
			log.Warn("download vuln pack failed", zap.String("ecosystem", eco), zap.Error(err))
		}
		dlCancel()
	}

	vdb, err = vulndb.LoadDir(cfg.VulnDBPath)
	if err != nil {
		log.Warn("vuln packs not available after download attempt; posture checks will still run", zap.Error(err))
		return nil, nil
	}
	return vdb, nil
}

func drainOfflineQueue(cfg *config.Config) {
	q, err := queue.Open(cfg.CachePath + ".queue")
	if err != nil {
		return
	}
	defer q.Close()

	pruned, _ := q.Prune()
	if pruned > 0 {
		log.Info("pruned expired queue entries", zap.Int("count", pruned))
	}

	c := client.New(cfg.PlatformURL, cfg.Token, cfg.AgentID, cfg.TLSSkipVerify)

	_ = q.Drain(func(e queue.Entry) error {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		return c.SendChunked(ctx, e.JobID, e.Findings)
	})
}

func printFindings(fs []findings.Finding) {
	for _, f := range fs {
		fix := f.FixedIn
		if fix == "" {
			fix = "no fix"
		}
		fmt.Printf("  [%-8s] %-20s  %s@%s  fix: %s\n",
			f.Severity, f.CVEID, f.PackageName, f.Version, fix)
	}
}

// deduplicateFindings removes duplicate findings by cve_id + package_name + version
func deduplicateFindings(fs []findings.Finding) []findings.Finding {
	seen := make(map[string]struct{})
	var result []findings.Finding

	for _, f := range fs {
		key := f.CVEID + "|" + f.PackageName + "|" + f.Version
		if _, ok := seen[key]; !ok {
			seen[key] = struct{}{}
			result = append(result, f)
		}
	}
	return result
}

func vulnerabilityFingerprints(projectID string, fs []findings.Finding) []string {
	fingerprints := make([]string, 0, len(fs))
	for _, f := range fs {
		fingerprints = append(fingerprints, vulnerabilityFingerprint(projectID, f))
	}
	return fingerprints
}

func shouldUpdateVulnerabilityBaseline(fullScan bool, manifestCount, changedCount int) bool {
	return fullScan || manifestCount == changedCount
}

func vulnerabilityFingerprint(projectID string, f findings.Finding) string {
	sum := sha1.Sum([]byte(projectID + "|agent|" + f.CVEID + "|" + f.PackageName + "|" + f.Ecosystem))
	return fmt.Sprintf("%x", sum)
}
