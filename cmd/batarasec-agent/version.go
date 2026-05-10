package main

import (
	"fmt"

	"github.com/batarasec/agent/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("batarasec-agent", version.String())
	},
}
