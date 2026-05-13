package vulndb

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/batarasec/agent/internal/scanner"
)

func writePack(t *testing.T, dir, name string, pack Pack, gzipFile bool) {
	t.Helper()
	path := filepath.Join(dir, name)
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create pack: %v", err)
	}
	defer f.Close()

	var enc *json.Encoder
	if gzipFile {
		gz := gzip.NewWriter(f)
		defer gz.Close()
		enc = json.NewEncoder(gz)
	} else {
		enc = json.NewEncoder(f)
	}
	if err := enc.Encode(pack); err != nil {
		t.Fatalf("encode pack: %v", err)
	}
}

func TestLoadDirAndMatchJSONAndGzipPacks(t *testing.T) {
	dir := t.TempDir()
	writePack(t, dir, "npm.json", Pack{
		Ecosystem: "npm",
		Entries: []Entry{
			{CVEID: "CVE-2024-0001", PackageName: "lodash", AffectedVersions: "<4.17.21", FixedIn: "4.17.21", Severity: "HIGH", CVSSScore: 8.1, Title: "Prototype pollution"},
			{CVEID: "CVE-2024-0002", PackageName: "lodash", AffectedVersions: ">=5.0.0", Severity: "LOW", Title: "Future issue"},
		},
	}, false)
	writePack(t, dir, "go.json.gz", Pack{
		Ecosystem: "go",
		Entries: []Entry{
			{CVEID: "CVE-2024-0003", PackageName: "github.com/example/lib", AffectedVersions: ">=1.0.0 <1.2.0", FixedIn: "1.2.0", Severity: "CRITICAL", CVSSScore: 9.8, Title: "Go vuln"},
		},
	}, true)

	db, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("LoadDir returned error: %v", err)
	}

	matches := db.Match(scanner.Package{Name: "Lodash", Version: "4.17.20", Ecosystem: "npm", FilePath: "package-lock.json"})
	if len(matches) != 1 {
		t.Fatalf("expected 1 lodash match, got %d: %#v", len(matches), matches)
	}
	if matches[0].CVEID != "CVE-2024-0001" || matches[0].FixedIn != "4.17.21" || matches[0].Severity != "HIGH" {
		t.Fatalf("unexpected lodash match: %#v", matches[0])
	}

	goMatches := db.Match(scanner.Package{Name: "github.com/example/lib", Version: "1.1.9", Ecosystem: "go"})
	if len(goMatches) != 1 || goMatches[0].CVEID != "CVE-2024-0003" {
		t.Fatalf("unexpected go matches: %#v", goMatches)
	}
}

func TestMatchIgnoresUnaffectedInvalidAndUnpinnedVersions(t *testing.T) {
	db := &DB{index: map[string][]Entry{
		"npm:lodash": {
			{CVEID: "CVE-2024-0001", PackageName: "lodash", AffectedVersions: "<4.17.21", Severity: "HIGH"},
			{CVEID: "CVE-2024-0002", PackageName: "lodash", AffectedVersions: "not a constraint", Severity: "HIGH"},
		},
	}}

	for _, pkg := range []scanner.Package{
		{Name: "lodash", Version: "4.17.21", Ecosystem: "npm"},
		{Name: "lodash", Version: "", Ecosystem: "npm"},
		{Name: "lodash", Version: "not-semver", Ecosystem: "npm"},
		{Name: "unknown", Version: "1.0.0", Ecosystem: "npm"},
	} {
		if matches := db.Match(pkg); len(matches) != 0 {
			t.Fatalf("expected no matches for %#v, got %#v", pkg, matches)
		}
	}
}

func TestIsAffectedSemverConstraints(t *testing.T) {
	cases := []struct {
		version    string
		constraint string
		want       bool
	}{
		{"1.2.3", ">=1.0.0 <2.0.0", true},
		{"2.0.0", ">=1.0.0 <2.0.0", false},
		{"4.17.20", "<4.17.21", true},
		{"4.17.21", "<4.17.21", false},
		{"", "<1.0.0", false},
		{"1.0.0", "", false},
	}
	for _, tc := range cases {
		if got := isAffected(tc.version, tc.constraint); got != tc.want {
			t.Fatalf("isAffected(%q, %q) = %v, want %v", tc.version, tc.constraint, got, tc.want)
		}
	}
}
