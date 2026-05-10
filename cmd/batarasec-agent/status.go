package main

import (
	"context"
	"fmt"
	"time"

	"github.com/batarasec/agent/internal/cache"
	"github.com/batarasec/agent/internal/client"
	"github.com/batarasec/agent/internal/config"
	"github.com/batarasec/agent/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show agent status and platform connectivity",
	RunE:  runStatus,
}

func runStatus(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	fmt.Println("BataraSec Agent Status")
	fmt.Println("======================")
	fmt.Printf("Version   : %s\n", version.String())
	fmt.Printf("Agent ID  : %s\n", orNA(cfg.AgentID))
	fmt.Printf("Project ID: %s\n", orNA(cfg.ProjectID))
	fmt.Printf("Platform  : %s\n", cfg.PlatformURL)

	// Local cache info.
	db, err := cache.Open(cfg.CachePath)
	if err == nil {
		defer db.Close()
		lastScan, _ := db.GetMeta("last_scan")
		if lastScan != "" {
			t, _ := time.Parse(time.RFC3339, lastScan)
			fmt.Printf("Last Scan : %s\n", t.UTC().Format("2006-01-02 15:04:05 UTC"))
			fmt.Printf("Next Scan : %s  (systemd timer +6h)\n",
				t.Add(6*time.Hour).UTC().Format("2006-01-02 15:04:05 UTC"))
		} else {
			fmt.Printf("Last Scan : never\n")
		}
	}

	// Platform connectivity.
	if cfg.Token != "" {
		c := client.New(cfg.PlatformURL, cfg.Token, cfg.AgentID, cfg.TLSSkipVerify)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := c.Heartbeat(ctx); err != nil {
			fmt.Printf("Platform  : UNREACHABLE (%v)\n", err)
		} else {
			fmt.Printf("Platform  : OK\n")
		}
	} else {
		fmt.Printf("Platform  : not enrolled\n")
	}

	return nil
}

func orNA(s string) string {
	if s == "" {
		return "N/A (not enrolled)"
	}
	return s
}
