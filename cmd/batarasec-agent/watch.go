package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/batarasec/agent/internal/config"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Watch configured paths and scan when manifests change",
	RunE:  runWatch,
}

func runWatch(cmd *cobra.Command, args []string) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if cfg.AgentID == "" || cfg.Token == "" {
		return fmt.Errorf("agent not enrolled — run: batarasec-agent enroll --token <TOKEN>")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer watcher.Close()

	for _, root := range cfg.ScanPaths {
		if err := addWatchDirs(watcher, root); err != nil {
			log.Warn("watch path skipped", zap.String("path", root), zap.Error(err))
		}
	}

	debounce := time.NewTimer(time.Hour)
	if !debounce.Stop() {
		<-debounce.C
	}
	pending := false

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if event.Has(fsnotify.Create) {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					_ = addWatchDirs(watcher, event.Name)
				}
			}
			if !isManifestPath(event.Name) {
				continue
			}
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				pending = true
				debounce.Reset(10 * time.Second)
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			log.Warn("watch error", zap.Error(err))
		case <-debounce.C:
			if pending {
				pending = false
				log.Info("manifest change detected, running scan")
				if _, err := executeScan(false); err != nil {
					log.Warn("watch-triggered scan failed", zap.Error(err))
				}
			}
		}
	}
}

func addWatchDirs(watcher *fsnotify.Watcher, root string) error {
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return nil
	}
	return filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		return watcher.Add(path)
	})
}

func isManifestPath(path string) bool {
	switch filepath.Base(path) {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "requirements.txt", "poetry.lock", "Pipfile.lock", "go.mod", "go.sum":
		return true
	default:
		return false
	}
}
