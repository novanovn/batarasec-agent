package scanner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// PEP 508 package name (letters, numbers, ., -, _).
var pkgNameRe = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?)`)

// parseRequirements parses requirements.txt (and *-requirements.txt variants).
func parseRequirements(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	var pkgs []Package
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments, blank lines, options, VCS URLs.
		if line == "" || strings.HasPrefix(line, "#") ||
			strings.HasPrefix(line, "-") || strings.HasPrefix(line, "git+") {
			continue
		}

		// Strip inline comment.
		if idx := strings.Index(line, " #"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip extras (e.g. requests[security]).
		if idx := strings.Index(line, "["); idx != -1 {
			if end := strings.Index(line[idx:], "]"); end != -1 {
				line = line[:idx] + line[idx+end+1:]
			}
		}

		name := pkgNameRe.FindString(line)
		if name == "" {
			continue
		}

		constraint := strings.TrimSpace(line[len(name):])
		ver := extractExactVersion(constraint)

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   ver,
			Ecosystem: "python",
			FilePath:  filePath,
		})
	}

	return pkgs, scanner.Err()
}

// parsePipfileLock parses Pipfile.lock (JSON).
func parsePipfileLock(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	// Pipfile.lock structure:
	// { "_meta": {...}, "default": { "pkg": { "version": "==1.2.3" } }, "develop": {...} }
	var lock struct {
		Default map[string]struct {
			Version string `json:"version"`
		} `json:"default"`
		Develop map[string]struct {
			Version string `json:"version"`
		} `json:"develop"`
	}
	if err := json.NewDecoder(f).Decode(&lock); err != nil {
		return nil, fmt.Errorf("decode Pipfile.lock: %w", err)
	}

	var pkgs []Package
	for name, info := range lock.Default {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   extractExactVersion(info.Version),
			Ecosystem: "python",
			FilePath:  filePath,
		})
	}
	for name, info := range lock.Develop {
		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   extractExactVersion(info.Version),
			Ecosystem: "python",
			FilePath:  filePath,
		})
	}

	return pkgs, nil
}

// parsePoetryLock parses poetry.lock (TOML-like, line-by-line scan).
// We parse only [[package]] sections to avoid a TOML dependency.
func parsePoetryLock(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	var pkgs []Package
	var curName, curVer string
	inPackage := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[[package]]" {
			if inPackage && curName != "" {
				pkgs = append(pkgs, Package{
					Name:      curName,
					Version:   curVer,
					Ecosystem: "python",
					FilePath:  filePath,
				})
			}
			curName, curVer = "", ""
			inPackage = true
			continue
		}

		if !inPackage {
			continue
		}

		if strings.HasPrefix(line, "name = ") {
			curName = strings.Trim(strings.TrimPrefix(line, "name = "), `"`)
		} else if strings.HasPrefix(line, "version = ") {
			curVer = strings.Trim(strings.TrimPrefix(line, "version = "), `"`)
		}
	}

	// Flush last package.
	if inPackage && curName != "" {
		pkgs = append(pkgs, Package{
			Name:      curName,
			Version:   curVer,
			Ecosystem: "python",
			FilePath:  filePath,
		})
	}

	return pkgs, scanner.Err()
}

// extractExactVersion returns the version string from a pinned constraint
// like "==1.2.3" or "==1.2.3.*". Returns empty string for non-pinned specs.
func extractExactVersion(constraint string) string {
	if !strings.HasPrefix(constraint, "==") {
		return ""
	}
	ver := strings.TrimPrefix(constraint, "==")
	// Drop trailing wildcard.
	ver = strings.TrimSuffix(ver, ".*")
	// Drop additional specifiers (e.g. "==1.0.0,<2").
	if comma := strings.Index(ver, ","); comma != -1 {
		ver = ver[:comma]
	}
	return strings.TrimSpace(ver)
}
