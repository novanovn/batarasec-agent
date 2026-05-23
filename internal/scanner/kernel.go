package scanner

import (
	"context"
	"fmt"
	"os/exec"
	"path"
	"strings"
	"time"

	"github.com/batarasec/agent/pkg/findings"
)

const commandTimeout = 10 * time.Second

type commandRunner func(ctx context.Context, name string, args ...string) ([]byte, error)

type kernelModule struct {
	Name string
	Size string
	Used string
	By   string
}

type moduleInfo struct {
	Filename string
	Signer   string
	SigKey   string
	License  string
	Version  string
}

func checkKernelModules() []findings.PostureFinding {
	return checkKernelModulesWithRunner(runCommandWithTimeout, exec.LookPath)
}

func checkKernelModulesWithRunner(run commandRunner, lookPath func(string) (string, error)) []findings.PostureFinding {
	if _, err := lookPath("lsmod"); err != nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := run(ctx, "lsmod")
	if err != nil {
		return nil
	}

	modules := parseLSMod(string(out))
	if len(modules) == 0 {
		return nil
	}

	_, hasModinfo := lookPath("modinfo")
	_, hasDpkg := lookPath("dpkg")
	_, hasRPM := lookPath("rpm")

	var posture []findings.PostureFinding
	for _, m := range modules {
		info := moduleInfo{}
		if hasModinfo == nil {
			info = getModuleInfo(run, m.Name)
		}

		owner := ""
		if info.Filename != "" {
			switch {
			case hasDpkg == nil:
				owner = packageOwner(run, "dpkg", "-S", info.Filename)
			case hasRPM == nil:
				owner = packageOwner(run, "rpm", "-qf", info.Filename)
			}
		}

		posture = append(posture, moduleFindings(m, info, owner)...)
	}

	return posture
}

func runCommandWithTimeout(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Output()
}

func parseLSMod(output string) []kernelModule {
	lines := strings.Split(output, "\n")
	modules := make([]kernelModule, 0, len(lines))
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || i == 0 && strings.HasPrefix(line, "Module") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		m := kernelModule{Name: fields[0], Size: fields[1], Used: fields[2]}
		if len(fields) > 3 {
			m.By = strings.Join(fields[3:], " ")
		}
		modules = append(modules, m)
	}
	return modules
}

func getModuleInfo(run commandRunner, moduleName string) moduleInfo {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := run(ctx, "modinfo", moduleName)
	if err != nil {
		return moduleInfo{}
	}
	return parseModinfo(string(out))
}

func parseModinfo(output string) moduleInfo {
	info := moduleInfo{}
	for _, line := range strings.Split(output, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "filename":
			info.Filename = value
		case "signer":
			info.Signer = value
		case "sig_key":
			info.SigKey = value
		case "license":
			info.License = value
		case "version":
			info.Version = value
		}
	}
	return info
}

func packageOwner(run commandRunner, name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()

	out, err := run(ctx, name, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func moduleFindings(m kernelModule, info moduleInfo, owner string) []findings.PostureFinding {
	var posture []findings.PostureFinding
	evidence := moduleEvidence(m, info, owner)

	if suspiciousModuleName(m.Name) || suspiciousModulePath(info.Filename) {
		posture = append(posture, findings.PostureFinding{
			RuleID:      "KMOD-001",
			Category:    "kernel_modules",
			Severity:    "high",
			Title:       "Suspicious kernel module loaded",
			Description: fmt.Sprintf("Kernel module '%s' has a suspicious name or path.", m.Name),
			Evidence:    evidence,
			Remediation: "Investigate the module origin, unload it if unauthorized, and verify the host for rootkit activity.",
		})
	}

	if info.Filename == "" {
		posture = append(posture, findings.PostureFinding{
			RuleID:      "KMOD-002",
			Category:    "kernel_modules",
			Severity:    "medium",
			Title:       "Loaded kernel module has unknown metadata",
			Description: fmt.Sprintf("Kernel module '%s' is loaded but modinfo did not return metadata.", m.Name),
			Evidence:    evidence,
			Remediation: "Confirm the module exists on disk and is expected for this kernel. Investigate hidden or tampered modules.",
		})
		return posture
	}

	if !moduleInKernelTree(info.Filename) || owner == "" {
		posture = append(posture, findings.PostureFinding{
			RuleID:      "KMOD-003",
			Category:    "kernel_modules",
			Severity:    "medium",
			Title:       "Kernel module is not owned by a system package",
			Description: fmt.Sprintf("Kernel module '%s' is loaded from a path that is not clearly owned by a distro package.", m.Name),
			Evidence:    evidence,
			Remediation: "Verify the module source and install it through trusted OS packages when possible.",
		})
	}

	if info.Signer == "" && info.SigKey == "" {
		posture = append(posture, findings.PostureFinding{
			RuleID:      "KMOD-004",
			Category:    "kernel_modules",
			Severity:    "low",
			Title:       "Unsigned kernel module loaded",
			Description: fmt.Sprintf("Kernel module '%s' does not expose signature metadata.", m.Name),
			Evidence:    evidence,
			Remediation: "Prefer signed kernel modules and enable module signature enforcement where supported.",
		})
	}

	return posture
}

func moduleEvidence(m kernelModule, info moduleInfo, owner string) map[string]interface{} {
	evidence := map[string]interface{}{
		"module": m.Name,
		"size":   m.Size,
		"used":   m.Used,
	}
	if m.By != "" {
		evidence["used_by"] = m.By
	}
	if info.Filename != "" {
		evidence["filename"] = info.Filename
	}
	if info.Signer != "" {
		evidence["signer"] = info.Signer
	}
	if info.SigKey != "" {
		evidence["sig_key"] = info.SigKey
	}
	if info.License != "" {
		evidence["license"] = info.License
	}
	if info.Version != "" {
		evidence["version"] = info.Version
	}
	if owner != "" {
		evidence["package_owner"] = owner
	}
	return evidence
}

func suspiciousModuleName(name string) bool {
	lower := strings.ToLower(name)
	suspicious := []string{"rootkit", "hide", "hidden", "diamorphine", "reptile", "adore", "suterusu"}
	for _, marker := range suspicious {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func suspiciousModulePath(modulePath string) bool {
	if modulePath == "" {
		return false
	}
	clean := path.Clean(modulePath)
	return strings.HasPrefix(clean, "/tmp/") || strings.HasPrefix(clean, "/var/tmp/") || strings.HasPrefix(clean, "/dev/shm/")
}

func moduleInKernelTree(modulePath string) bool {
	clean := path.Clean(modulePath)
	return strings.HasPrefix(clean, "/lib/modules/") || strings.HasPrefix(clean, "/usr/lib/modules/")
}
