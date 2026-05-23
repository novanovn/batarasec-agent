package scanner

import (
	"bufio"
	"os"
	"strings"

	"github.com/batarasec/agent/pkg/findings"
)

// RunPostureChecks executes all hardening checks and returns findings.
func RunPostureChecks() []findings.PostureFinding {
	var result []findings.PostureFinding
	result = append(result, checkSSHConfig()...)
	result = append(result, checkDockerRuntime()...)
	result = append(result, checkKernelModules()...)
	result = append(result, checkCISTools()...)
	return result
}

func checkSSHConfig() []findings.PostureFinding {
	const configPath = "/etc/ssh/sshd_config"
	f, err := os.Open(configPath)
	if err != nil {
		// File does not exist — nothing to check.
		return nil
	}
	defer f.Close()

	settings := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			settings[strings.ToLower(parts[0])] = strings.ToLower(parts[1])
		}
	}

	var posture []findings.PostureFinding

	if v, ok := settings["permitrootlogin"]; ok && v != "no" && v != "prohibit-password" {
		posture = append(posture, findings.PostureFinding{
			RuleID:   "SSH-001",
			Category: "ssh",
			Severity: "high",
			Title:    "SSH PermitRootLogin is not disabled",
			Description: "sshd_config has PermitRootLogin set to a permissive value (" + v + "). " +
				"Direct root login increases attack surface.",
			Evidence:    map[string]interface{}{"current_value": v, "file": configPath},
			Remediation: "Set 'PermitRootLogin no' or 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config and restart sshd.",
		})
	}

	if v, ok := settings["passwordauthentication"]; ok && v == "yes" {
		posture = append(posture, findings.PostureFinding{
			RuleID:   "SSH-002",
			Category: "ssh",
			Severity: "medium",
			Title:    "SSH PasswordAuthentication is enabled",
			Description: "sshd_config has PasswordAuthentication yes. " +
				"Password-based login is susceptible to brute-force attacks.",
			Evidence:    map[string]interface{}{"current_value": v, "file": configPath},
			Remediation: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and configure SSH key-based authentication.",
		})
	}

	if v, ok := settings["permitemptypasswords"]; ok && v == "yes" {
		posture = append(posture, findings.PostureFinding{
			RuleID:   "SSH-003",
			Category: "ssh",
			Severity: "critical",
			Title:    "SSH PermitEmptyPasswords is enabled",
			Description: "sshd_config allows empty passwords, enabling unauthenticated access.",
			Evidence:    map[string]interface{}{"current_value": v, "file": configPath},
			Remediation: "Set 'PermitEmptyPasswords no' in /etc/ssh/sshd_config and restart sshd.",
		})
	}

	if v, ok := settings["x11forwarding"]; ok && v == "yes" {
		posture = append(posture, findings.PostureFinding{
			RuleID:   "SSH-004",
			Category: "ssh",
			Severity: "low",
			Title:    "SSH X11Forwarding is enabled",
			Description: "X11Forwarding creates an additional attack surface for X11 channel hijacking.",
			Evidence:    map[string]interface{}{"current_value": v, "file": configPath},
			Remediation: "Set 'X11Forwarding no' in /etc/ssh/sshd_config unless required.",
		})
	}

	return posture
}
