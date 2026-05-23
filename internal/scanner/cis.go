package scanner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/batarasec/agent/pkg/findings"
)

const cisCommandTimeout = 2 * time.Minute

var lynisSuggestionID = regexp.MustCompile(`\[([A-Z0-9-]+)\]`)

type fileReader func(string) ([]byte, error)
type fileRemover func(string) error
type tempDirFunc func() string

func checkCISTools() []findings.PostureFinding {
	return checkCISToolsWithRunner(runCommandWithTimeout, os.ReadFile, os.Remove, os.TempDir, exec.LookPath)
}

func checkCISToolsWithRunner(run commandRunner, readFile fileReader, remove fileRemover, tempDir tempDirFunc, lookPath func(string) (string, error)) []findings.PostureFinding {
	if _, err := lookPath("lynis"); err == nil {
		return runLynis(run, readFile, remove, tempDir)
	}
	if _, err := lookPath("oscap"); err == nil {
		return runOpenSCAP(run)
	}
	return nil
}

func runLynis(run commandRunner, readFile fileReader, remove fileRemover, tempDir tempDirFunc) []findings.PostureFinding {
	reportPath := filepath.Join(tempDir(), fmt.Sprintf("batarasec-lynis-%d.dat", time.Now().UnixNano()))
	defer remove(reportPath)

	ctx, cancel := context.WithTimeout(context.Background(), cisCommandTimeout)
	defer cancel()

	_, _ = run(ctx, "lynis", "audit", "system", "--quick", "--no-colors", "--quiet", "--report-file", reportPath)
	data, err := readFile(reportPath)
	if err != nil {
		return nil
	}
	return parseLynisReport(string(data))
}

func parseLynisReport(report string) []findings.PostureFinding {
	var posture []findings.PostureFinding
	for _, line := range strings.Split(report, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "warning[]=") && !strings.HasPrefix(line, "suggestion[]=") {
			continue
		}

		kind, value, _ := strings.Cut(line, "=")
		severity := "low"
		titlePrefix := "Lynis suggestion"
		if kind == "warning[]" {
			severity = "medium"
			titlePrefix = "Lynis warning"
		}

		ruleID := "LYNIS-GENERIC"
		if match := lynisSuggestionID.FindStringSubmatch(value); len(match) == 2 {
			ruleID = "LYNIS-" + match[1]
		}

		posture = append(posture, findings.PostureFinding{
			RuleID:      ruleID,
			Category:    "cis",
			Severity:    severity,
			Title:       titlePrefix + ": " + trimLynisMarker(value),
			Description: "Lynis reported a CIS-style hardening issue.",
			Evidence:    map[string]interface{}{"tool": "lynis", "report_line": value},
			Remediation: "Review the Lynis finding and apply the recommended hardening control where appropriate.",
		})
	}
	return posture
}

func trimLynisMarker(value string) string {
	return strings.TrimSpace(lynisSuggestionID.ReplaceAllString(value, ""))
}

func runOpenSCAP(run commandRunner) []findings.PostureFinding {
	ctx, cancel := context.WithTimeout(context.Background(), cisCommandTimeout)
	defer cancel()

	out, err := run(ctx, "oscap", "xccdf", "eval", "--profile", "xccdf_org.ssgproject.content_profile_cis")
	if err != nil && len(out) == 0 {
		return nil
	}
	return parseOpenSCAPOutput(string(out))
}

func parseOpenSCAPOutput(output string) []findings.PostureFinding {
	var posture []findings.PostureFinding
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(strings.ToLower(line), "fail") {
			continue
		}

		ruleID := "OSCAP-GENERIC"
		fields := strings.Fields(line)
		for _, field := range fields {
			if strings.Contains(field, "xccdf_") || strings.HasPrefix(field, "rule_") {
				ruleID = "OSCAP-" + strings.Trim(field, ":")
				break
			}
		}

		posture = append(posture, findings.PostureFinding{
			RuleID:      ruleID,
			Category:    "cis",
			Severity:    "medium",
			Title:       "OpenSCAP CIS check failed",
			Description: "OpenSCAP reported a failed CIS-style compliance rule.",
			Evidence:    map[string]interface{}{"tool": "openscap", "output_line": line},
			Remediation: "Review the OpenSCAP rule output and apply the corresponding CIS remediation.",
		})
	}
	return posture
}
