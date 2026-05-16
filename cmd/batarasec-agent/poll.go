package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/batarasec/agent/internal/client"
	"github.com/batarasec/agent/internal/config"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var pollCmd = &cobra.Command{
	Use:   "poll",
	Short: "Poll platform for pending commands",
	RunE:  runPoll,
}

func runPoll(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.AgentID == "" || cfg.Token == "" {
		return fmt.Errorf("agent not enrolled — run: batarasec-agent enroll --token <TOKEN>")
	}

	c := client.New(cfg.PlatformURL, cfg.Token, cfg.AgentID, cfg.TLSSkipVerify)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	commands, err := c.PollCommands(ctx)
	cancel()
	if err != nil {
		return fmt.Errorf("poll commands: %w", err)
	}
	if len(commands) == 0 {
		return nil
	}

	log.Info("commands received", zap.Int("count", len(commands)))
	for _, command := range commands {
		if command.Type == "uninstall_agent" {
			log.Info("uninstall command received, starting uninstall process")
			if err := executeUninstall(c, command.ID); err != nil {
				log.Error("uninstall failed", zap.Error(err))
			}
			// We don't continue the loop here as the binary/service might be gone.
			return nil
		}

		if command.Type != "scan_full" && command.Type != "scan_fs" && command.Type != "scan_hardening" {
			markCommandDone(c, command.ID, "failed", "", "unsupported command type: "+command.Type)
			continue
		}

		previousFullScanOverride := fullScanOverride
		fullScanOverride = command.Type == "scan_full"
		jobID, scanErr := executeScan(false)
		fullScanOverride = previousFullScanOverride
		if scanErr != nil {
			markCommandDone(c, command.ID, "failed", jobID, scanErr.Error())
			return scanErr
		}
		markCommandDone(c, command.ID, "completed", jobID, "")
	}
	return nil
}

func markCommandDone(c *client.Client, commandID, status, scanJobID, errorMessage string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := c.CommandDone(ctx, commandID, status, scanJobID, errorMessage); err != nil {
		log.Warn("failed to mark command done", zap.String("command_id", commandID), zap.Error(err))
	}
}

func executeUninstall(c *client.Client, commandID string) error {
	// 1. Report completion FIRST while we still have access to tokens and network.
	markCommandDone(c, commandID, "completed", "", "")

	// 2. Give some time for the network request to finish and logs to flush.
	time.Sleep(2 * time.Second)

	// 3. Prepare the self-deletion script.
	// Since we are running as a service (likely), we should stop ourselves via systemd
	// but we also need to delete files. A simple way is to use a detached background process
	// or rely on a script.

	// Paths to remove:
	// /usr/local/bin/batarasec-agent
	// /etc/batarasec/ (config)
	// /var/lib/batarasec/ (cache, vuln-db, queue)
	// /etc/systemd/system/batarasec-agent.service
	// /etc/systemd/system/batarasec-agent.timer

	uninstallCmd := `(
		sleep 2;
		systemctl disable --now batarasec-agent.timer || true;
		systemctl stop batarasec-agent.service || true;
		systemctl disable batarasec-agent.service || true;
		rm -f /etc/systemd/system/batarasec-agent.service;
		rm -f /etc/systemd/system/batarasec-agent.timer;
		systemctl daemon-reload;
		rm -rf /etc/batarasec;
		rm -rf /var/lib/batarasec;
		rm -f /usr/local/bin/batarasec-agent;
	) &`

	log.Info("executing self-deletion command")
	// Execute the background shell command.
	// Since we are running as a service (likely), we should stop ourselves via systemd
	// but we also need to delete files. A simple way is to use a detached background process
	// or rely on a script.

	executor := "sh"
	if _, err := os.Stat("/bin/bash"); err == nil {
		executor = "/bin/bash"
	}

	return exec.Command(executor, "-c", uninstallCmd).Start()
}
