package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/batarasec/agent/pkg/findings"
)

// dockerInspect represents the subset of docker inspect output we need
type dockerInspect struct {
	ID      string `json:"Id"`
	Name    string `json:"Name"`
	Config  struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged  bool     `json:"Privileged"`
		NetworkMode string   `json:"NetworkMode"`
		Binds       []string `json:"Binds"`
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
}

func checkDockerRuntime() []findings.PostureFinding {
	var posture []findings.PostureFinding

	// 1. Detect if Docker CLI is available
	_, err := exec.LookPath("docker")
	if err != nil {
		return nil
	}

	// 2. List running container IDs
	cmd := exec.Command("docker", "ps", "-q")
	output, err := cmd.Output()
	if err != nil {
		return nil // Daemon unreachable or no permissions
	}

	ids := strings.Fields(string(output))
	if len(ids) == 0 {
		return nil
	}

	// 3. Inspect containers
	args := append([]string{"inspect"}, ids...)
	inspectCmd := exec.Command("docker", args...)
	inspectOutput, err := inspectCmd.Output()
	if err != nil {
		return nil
	}

	var containers []dockerInspect
	if err := json.Unmarshal(inspectOutput, &containers); err != nil {
		return nil
	}

	sensitivePaths := []string{"/var/run/docker.sock", "/etc", "/root", "/proc", "/sys", "/var/lib/docker"}
	sensitivePorts := map[string]string{
		"22":   "SSH",
		"2375": "Docker API",
		"2376": "Docker API (TLS)",
		"3306": "MySQL",
		"5432": "PostgreSQL",
		"6379": "Redis",
		"27017": "MongoDB",
		"9200": "Elasticsearch",
	}

	for _, c := range containers {
		cName := strings.TrimPrefix(c.Name, "/")
		shortID := c.ID
		if len(shortID) > 12 {
			shortID = shortID[:12]
		}

		// DKR-001: Docker Socket Exposed
		for _, bind := range c.HostConfig.Binds {
			if strings.Contains(bind, "/var/run/docker.sock") {
				posture = append(posture, findings.PostureFinding{
					RuleID:      "DKR-001",
					Category:    "docker",
					Severity:    "critical",
					Title:       "Docker socket exposed to container",
					Description: fmt.Sprintf("Container '%s' has the Docker socket mounted. This allows the container to control the host Docker daemon and potentially takeover the host VM.", cName),
					Evidence:    map[string]interface{}{"container_name": cName, "container_id": shortID, "mount": bind},
					Remediation: "Remove the Docker socket mount from the container configuration. If API access is required, use a secure proxy like 'docker-socket-proxy' with restricted permissions.",
				})
				break
			}
		}

		// DKR-002: Privileged Mode
		if c.HostConfig.Privileged {
			posture = append(posture, findings.PostureFinding{
				RuleID:      "DKR-002",
				Category:    "docker",
				Severity:    "high",
				Title:       "Privileged container detected",
				Description: fmt.Sprintf("Container '%s' is running in privileged mode, granting it access to all host devices and kernel capabilities.", cName),
				Evidence:    map[string]interface{}{"container_name": cName, "container_id": shortID},
				Remediation: "Disable privileged mode and use specific kernel capabilities (--cap-add) instead.",
			})
		}

		// DKR-003: Sensitive Host Mounts
		for _, bind := range c.HostConfig.Binds {
			hostPath := strings.Split(bind, ":")[0]
			for _, sp := range sensitivePaths {
				if hostPath == sp || strings.HasPrefix(hostPath, sp+"/") {
					// DKR-001 already covers the socket
					if sp == "/var/run/docker.sock" {
						continue
					}
					posture = append(posture, findings.PostureFinding{
						RuleID:      "DKR-003",
						Category:    "docker",
						Severity:    "high",
						Title:       "Sensitive host path mounted",
						Description: fmt.Sprintf("Container '%s' has a sensitive host path (%s) mounted. This could allow an attacker to access or modify critical host files.", cName, hostPath),
						Evidence:    map[string]interface{}{"container_name": cName, "container_id": shortID, "mount": bind},
						Remediation: "Avoid mounting sensitive host directories. Use Docker volumes or mount specific non-sensitive files instead.",
					})
					break
				}
			}
		}

		// DKR-004: Host Network Mode
		if c.HostConfig.NetworkMode == "host" {
			posture = append(posture, findings.PostureFinding{
				RuleID:      "DKR-004",
				Category:    "docker",
				Severity:    "medium",
				Title:       "Container using host network",
				Description: fmt.Sprintf("Container '%s' is using the host network stack, bypassing network isolation.", cName),
				Evidence:    map[string]interface{}{"container_name": cName, "container_id": shortID},
				Remediation: "Use bridge or overlay networks to maintain network isolation.",
			})
		}

		// DKR-005: Running as Root
		if c.Config.User == "" || c.Config.User == "0" || c.Config.User == "root" {
			posture = append(posture, findings.PostureFinding{
				RuleID:      "DKR-005",
				Category:    "docker",
				Severity:    "medium",
				Title:       "Container running as root",
				Description: fmt.Sprintf("Container '%s' is running as root. If the service inside is compromised, the attacker will have root privileges within the container.", cName),
				Evidence:    map[string]interface{}{"container_name": cName, "container_id": shortID, "user": c.Config.User},
				Remediation: "Define a non-root USER in the Dockerfile or use the '--user' flag at runtime.",
			})
		}

		// DKR-006: Insecure Port Binding
		for containerPort, bindings := range c.HostConfig.PortBindings {
			portOnly := strings.Split(containerPort, "/")[0]
			if service, isSensitive := sensitivePorts[portOnly]; isSensitive {
				for _, b := range bindings {
					if b.HostIP == "0.0.0.0" || b.HostIP == "" {
						posture = append(posture, findings.PostureFinding{
							RuleID:      "DKR-006",
							Category:    "docker",
							Severity:    "medium",
							Title:       fmt.Sprintf("Sensitive port (%s) exposed to public", service),
							Description: fmt.Sprintf("Container '%s' exposes %s port %s to 0.0.0.0. This makes it accessible from the internet if not guarded by a firewall.", cName, service, portOnly),
							Evidence:    map[string]interface{}{"container_name": cName, "container_id": shortID, "binding": b.HostIP + ":" + b.HostPort},
							Remediation: fmt.Sprintf("Bind the port to '127.0.0.1' or use a private network. Ensure firewall rules restrict access to %s.", portOnly),
						})
					}
				}
			}
		}
	}

	return posture
}
