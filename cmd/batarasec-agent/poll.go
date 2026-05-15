package main

import (
	"context"
	"fmt"
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
		if command.Type != "scan_full" && command.Type != "scan_fs" {
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
