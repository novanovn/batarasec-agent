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
var lynisRuleID = regexp.MustCompile(`^([A-Z0-9]+-[0-9]+)\|`)

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

// parseLynisValue handles two Lynis report formats:
//   - Pipe-delimited: FINT-4350|description|detail|-|
//   - Bracket:        some description text [SSH-7408]
func parseLynisValue(value string) (ruleID, description, detail string) {
	if match := lynisRuleID.FindStringSubmatch(value); len(match) == 2 {
		ruleID = "LYNIS-" + match[1]
		parts := strings.SplitN(value, "|", 4)
		if len(parts) >= 2 {
			description = strings.TrimSpace(parts[1])
		}
		if len(parts) >= 3 && parts[2] != "-" && parts[2] != "" {
			detail = strings.TrimSpace(parts[2])
		}
		return
	}
	if match := lynisSuggestionID.FindStringSubmatch(value); len(match) == 2 {
		ruleID = "LYNIS-" + match[1]
		description = strings.TrimSpace(lynisSuggestionID.ReplaceAllString(value, ""))
		return
	}
	ruleID = "LYNIS-GENERIC"
	description = value
	return
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

		ruleID, description, detail := parseLynisValue(value)
		evidence := map[string]interface{}{"tool": "lynis", "report_line": value}
		if detail != "" {
			evidence["detail"] = detail
		}

		posture = append(posture, findings.PostureFinding{
			RuleID:      ruleID,
			Category:    "cis",
			Severity:    severity,
			Title:       titlePrefix + ": " + description,
			Description: "Lynis reported a CIS-style hardening issue.",
			Evidence:    evidence,
			Remediation: "Review the Lynis finding and apply the recommended hardening control where appropriate.",
		})
	}
	return posture
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
