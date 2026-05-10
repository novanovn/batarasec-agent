package main

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/batarasec/agent/internal/client"
	"github.com/batarasec/agent/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var enrollCmd = &cobra.Command{
	Use:   "enroll",
	Short: "Register this agent with the BataraSec platform",
	Long: `Enrolls this agent using a token from the BataraSec dashboard.
Credentials (agent_id, project_id, token) are saved to the config file.`,
	RunE: runEnroll,
}

var enrollToken string

func init() {
	enrollCmd.Flags().StringVarP(&enrollToken, "token", "t", "", "enrollment token (required)")
	_ = enrollCmd.MarkFlagRequired("token")
}

func runEnroll(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	c := client.New(cfg.PlatformURL, "", "", cfg.TLSSkipVerify)

	hostname, _ := os.Hostname()
	req := client.NewEnrollRequest(enrollToken, hostname, runtime.GOOS, runtime.GOARCH)

	log.Info("enrolling agent",
		zap.String("platform", cfg.PlatformURL),
		zap.String("hostname", hostname),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := c.Enroll(ctx, req)
	if err != nil {
		return fmt.Errorf("enroll: %w", err)
	}

	viper.Set("agent_id", resp.AgentID)
	viper.Set("project_id", resp.ProjectID)
	viper.Set("token", resp.JWT)

	cfg.AgentID = resp.AgentID
	cfg.ProjectID = resp.ProjectID
	cfg.Token = resp.JWT
	if err := config.Save(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}

	fmt.Println("Agent enrolled successfully!")
	fmt.Printf("  Agent ID  : %s\n", resp.AgentID)
	fmt.Printf("  Project ID: %s\n", resp.ProjectID)
	if resp.Message != "" {
		fmt.Printf("  Message   : %s\n", resp.Message)
	}

	log.Info("enrollment complete",
		zap.String("agent_id", resp.AgentID),
		zap.String("project_id", resp.ProjectID),
	)
	return nil
}
