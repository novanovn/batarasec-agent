package scanner

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// parseGoSum parses a go.sum file into unique module entries.
func parseGoSum(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	seen := make(map[string]struct{})
	var pkgs []Package

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		modPath := fields[0]
		verField := fields[1]

		// Skip /go.mod-only lines; we want source entries.
		if strings.HasSuffix(verField, "/go.mod") {
			continue
		}

		// Normalise: strip leading "v" and "+incompatible".
		ver := strings.TrimPrefix(verField, "v")
		if idx := strings.Index(ver, "+"); idx != -1 {
			ver = ver[:idx]
		}

		key := modPath + "@" + ver
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		pkgs = append(pkgs, Package{
			Name:      modPath,
			Version:   ver,
			Ecosystem: "go",
			FilePath:  filePath,
		})
	}

	return pkgs, scanner.Err()
}

// parseGoMod extracts direct require declarations from a go.mod file.
// go.sum already contains the full transitive list; go.mod gives us the
// direct deps with their minimum required versions.
func parseGoMod(filePath string) ([]Package, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", filePath, err)
	}
	defer f.Close()

	var pkgs []Package
	inRequire := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "require (" {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Single-line require: require module version
		if strings.HasPrefix(line, "require ") {
			line = strings.TrimPrefix(line, "require ")
			// Process the single-line require entry
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			// Skip indirect deps (they're covered by go.sum).
			if isIndirectRequire(fields) {
				continue
			}
			ver := strings.TrimPrefix(fields[1], "v")
			if idx := strings.Index(ver, "+"); idx != -1 {
				ver = ver[:idx]
			}
			pkgs = append(pkgs, Package{
				Name:      fields[0],
				Version:   ver,
				Ecosystem: "go",
				FilePath:  filePath,
			})
			continue
		}

		if !inRequire {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// Skip indirect deps (they're covered by go.sum).
		if isIndirectRequire(fields) {
			continue
		}

		ver := strings.TrimPrefix(fields[1], "v")
		if idx := strings.Index(ver, "+"); idx != -1 {
			ver = ver[:idx]
		}

		pkgs = append(pkgs, Package{
			Name:      fields[0],
			Version:   ver,
			Ecosystem: "go",
			FilePath:  filePath,
		})
	}

	return pkgs, scanner.Err()
}

func isIndirectRequire(fields []string) bool {
	for i := 2; i < len(fields)-1; i++ {
		if fields[i] == "//" && fields[i+1] == "indirect" {
			return true
		}
	}
	return false
}
