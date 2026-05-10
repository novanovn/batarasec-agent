package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

var (
	cfgFile string
	log     *zap.Logger
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "batarasec-agent",
	Short: "BataraSec security scanning agent",
	Long: `BataraSec Agent scans your system for vulnerable software dependencies
and reports findings to the BataraSec platform automatically.`,
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: /etc/batarasec/agent.yaml)")
	rootCmd.PersistentFlags().String("log-level", "info", "log level: debug, info, warn, error")
	_ = viper.BindPFlag("log_level", rootCmd.PersistentFlags().Lookup("log-level"))

	rootCmd.AddCommand(enrollCmd, scanCmd, statusCmd, versionCmd)
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("agent")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("/etc/batarasec")
		viper.AddConfigPath("$HOME/.batarasec")
		viper.AddConfigPath(".")
	}

	viper.SetEnvPrefix("BATARASEC")
	viper.AutomaticEnv()

	viper.SetDefault("platform_url", "https://103.93.160.112")
	viper.SetDefault("cache_path", "/var/lib/batarasec/cache.db")
	viper.SetDefault("vuln_db_path", "/var/lib/batarasec/vuln-db")
	viper.SetDefault("log_level", "info")
	viper.SetDefault("scan_paths", []string{"/home", "/opt", "/srv", "/var/www"})
	viper.SetDefault("tls_skip_verify", false)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			fmt.Fprintf(os.Stderr, "warning: cannot read config: %v\n", err)
		}
	}

	log = buildLogger(viper.GetString("log_level"))
}

func buildLogger(level string) *zap.Logger {
	cfg := zap.NewProductionConfig()
	if level == "debug" {
		cfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	l, err := cfg.Build()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init logger: %v\n", err)
		os.Exit(1)
	}
	return l
}
