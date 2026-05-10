package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

type packageLock struct {
	LockfileVersion int    `json:"lockfileVersion"`
	Name            string `json:"name"`
	// v2 / v3
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
	// v1
	Dependencies map[string]struct {
		Version string `json:"version"`
	} `json:"dependencies"`
}

func parseNPM(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	var lock packageLock
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, fmt.Errorf("decode package-lock.json: %w", err)
	}

	var pkgs []Package

	if lock.LockfileVersion >= 2 && len(lock.Packages) > 0 {
		for rawName, info := range lock.Packages {
			if rawName == "" || info.Version == "" {
				continue
			}
			// Strip "node_modules/" prefix and handle nested scopes.
			name := rawName
			if idx := strings.LastIndex(name, "node_modules/"); idx != -1 {
				name = name[idx+13:]
			}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   info.Version,
				Ecosystem: "npm",
				FilePath:  filePath,
			})
		}
	} else {
		for name, info := range lock.Dependencies {
			if info.Version == "" {
				continue
			}
			pkgs = append(pkgs, Package{
				Name:      name,
				Version:   info.Version,
				Ecosystem: "npm",
				FilePath:  filePath,
			})
		}
	}

	return pkgs, nil
}
