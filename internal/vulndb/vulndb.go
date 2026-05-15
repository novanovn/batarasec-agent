package vulndb

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/batarasec/agent/internal/scanner"
	"github.com/batarasec/agent/pkg/findings"
)

// Entry is one row in the platform-served vulnerability pack.
type Entry struct {
	CVEID            string  `json:"cve_id"`
	PackageName      string  `json:"package_name"`
	AffectedVersions string  `json:"affected_versions"` // semver constraint, e.g. "<4.17.21"
	FixedIn          string  `json:"fixed_in,omitempty"`
	Severity         string  `json:"severity"`
	CVSSScore        float64 `json:"cvss_score,omitempty"`
	Title            string  `json:"title"`
}

// Pack is the JSON file served by GET /agent/v1/vuln-db/pack?eco=<ecosystem>.
type Pack struct {
	Ecosystem string  `json:"ecosystem"`
	UpdatedAt string  `json:"updated_at"`
	Entries   []Entry `json:"entries"`
}

// DB holds all loaded packs, indexed for fast lookup.
type DB struct {
	// index: "ecosystem:lowercase(package)" → []Entry
	index map[string][]Entry
}

// LoadDir reads all *.json and *.json.gz files from dir and builds an index.
func LoadDir(dir string) (*DB, error) {
	db := &DB{index: make(map[string][]Entry)}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read vulndb dir %s: %w", dir, err)
	}

	loaded := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") && !strings.HasSuffix(name, ".json.gz") {
			continue
		}
		path := filepath.Join(dir, name)
		if err := db.loadPack(path); err != nil {
			return nil, fmt.Errorf("load pack %s: %w", name, err)
		}
		loaded++
	}
	if loaded == 0 {
		return nil, fmt.Errorf("no vulnerability packs found in %s", dir)
	}

	return db, nil
}

func (db *DB) loadPack(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("gzip reader: %w", err)
		}
		defer gz.Close()
		r = gz
	}

	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}

	var pack Pack
	if err := json.Unmarshal(data, &pack); err == nil && pack.Ecosystem != "" {
		for _, entry := range pack.Entries {
			key := pack.Ecosystem + ":" + strings.ToLower(entry.PackageName)
			db.index[key] = append(db.index[key], entry)
		}
		return nil
	}

	var entries []Entry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("decode: %w", err)
	}
	ecosystem := ecosystemFromPackPath(path)
	for _, entry := range entries {
		key := ecosystem + ":" + strings.ToLower(entry.PackageName)
		db.index[key] = append(db.index[key], entry)
	}
	return nil
}

// Match returns all CVE findings for the given package.
func ecosystemFromPackPath(path string) string {
	name := strings.TrimSuffix(strings.TrimSuffix(filepath.Base(path), ".gz"), ".json")
	if name == "python" {
		return "python"
	}
	return name
}

func (db *DB) Match(pkg scanner.Package) []findings.Finding {
	key := pkg.Ecosystem + ":" + strings.ToLower(pkg.Name)
	entries := db.index[key]
	if len(entries) == 0 {
		return nil
	}

	var out []findings.Finding
	for _, e := range entries {
		if !isAffected(pkg.Version, e.AffectedVersions, e.FixedIn) {
			continue
		}
		out = append(out, findings.Finding{
			PackageName: pkg.Name,
			Version:     pkg.Version,
			Ecosystem:   pkg.Ecosystem,
			FilePath:    pkg.FilePath,
			CVEID:       e.CVEID,
			Severity:    e.Severity,
			CVSSScore:   e.CVSSScore,
			FixedIn:     e.FixedIn,
			Title:       e.Title,
		})
	}
	return out
}

func isAffected(pkgVersion, constraint, fixedIn string) bool {
	if pkgVersion == "" {
		return false
	}
	v, err := semver.NewVersion(pkgVersion)
	if err != nil {
		return false
	}
	if constraint == "" && fixedIn != "" {
		constraint = "<" + fixedIn
	}
	if constraint == "" {
		return false
	}
	c, err := semver.NewConstraint(constraint)
	if err != nil {
		return false
	}
	return c.Check(v)
}
