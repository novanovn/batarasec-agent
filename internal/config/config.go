package config

import (
	"fmt"
	"os"

	"github.com/spf13/viper"
)

type Config struct {
	AgentID       string   `mapstructure:"agent_id"`
	ProjectID     string   `mapstructure:"project_id"`
	Token         string   `mapstructure:"token"`
	PlatformURL   string   `mapstructure:"platform_url"`
	CachePath     string   `mapstructure:"cache_path"`
	VulnDBPath    string   `mapstructure:"vuln_db_path"`
	ScanPaths     []string `mapstructure:"scan_paths"`
	LogLevel      string   `mapstructure:"log_level"`
	TLSSkipVerify bool     `mapstructure:"tls_skip_verify"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("unmarshal config: %w", err)
	}
	return &cfg, nil
}

// Save writes agent_id and token back to the config file (called after enroll).
func Save(cfg *Config) error {
	viper.Set("agent_id", cfg.AgentID)
	viper.Set("project_id", cfg.ProjectID)
	viper.Set("token", cfg.Token)

	cfgFile := viper.ConfigFileUsed()
	if cfgFile == "" {
		cfgFile = "/etc/batarasec/agent.yaml"
		if err := os.MkdirAll("/etc/batarasec", 0o755); err != nil {
			return fmt.Errorf("create config dir: %w", err)
		}
		viper.SetConfigFile(cfgFile)
	}

	// Config contains credentials — enforce 0600.
	if err := viper.WriteConfig(); err != nil {
		return err
	}
	return os.Chmod(cfgFile, 0o600)
}
