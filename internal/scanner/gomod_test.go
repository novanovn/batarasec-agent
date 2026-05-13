package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}

func packageByName(pkgs []Package, name string) (Package, bool) {
	for _, pkg := range pkgs {
		if pkg.Name == name {
			return pkg, true
		}
	}
	return Package{}, false
}

func TestParseGoModSingleLineRequire(t *testing.T) {
	path := writeTempFile(t, "go.mod", `module example.com/app

go 1.22

require github.com/gin-gonic/gin v1.9.1
`)

	pkgs, err := parseGoMod(path)
	if err != nil {
		t.Fatalf("parseGoMod returned error: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %#v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "github.com/gin-gonic/gin" || pkgs[0].Version != "1.9.1" || pkgs[0].Ecosystem != "go" {
		t.Fatalf("unexpected package: %#v", pkgs[0])
	}
}

func TestParseGoModBlockRequireSkipsIndirectAndNormalizesVersion(t *testing.T) {
	path := writeTempFile(t, "go.mod", `module example.com/app

go 1.22

require (
	github.com/Masterminds/semver/v3 v3.5.0
	golang.org/x/sys v0.29.0 // indirect
	github.com/example/legacy v1.2.3+incompatible
)
`)

	pkgs, err := parseGoMod(path)
	if err != nil {
		t.Fatalf("parseGoMod returned error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 direct packages, got %d: %#v", len(pkgs), pkgs)
	}
	if _, ok := packageByName(pkgs, "golang.org/x/sys"); ok {
		t.Fatalf("indirect package should be skipped: %#v", pkgs)
	}
	legacy, ok := packageByName(pkgs, "github.com/example/legacy")
	if !ok {
		t.Fatalf("legacy package not found: %#v", pkgs)
	}
	if legacy.Version != "1.2.3" {
		t.Fatalf("expected +incompatible to be stripped, got %q", legacy.Version)
	}
}

func TestParseGoSumDeduplicatesAndSkipsGoModLines(t *testing.T) {
	path := writeTempFile(t, "go.sum", `github.com/pkg/errors v0.9.1 h1:abc
github.com/pkg/errors v0.9.1/go.mod h1:def
github.com/pkg/errors v0.9.1 h1:abc
github.com/example/legacy v1.2.3+incompatible h1:ghi
`)

	pkgs, err := parseGoSum(path)
	if err != nil {
		t.Fatalf("parseGoSum returned error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 unique source packages, got %d: %#v", len(pkgs), pkgs)
	}
	legacy, ok := packageByName(pkgs, "github.com/example/legacy")
	if !ok {
		t.Fatalf("legacy package not found: %#v", pkgs)
	}
	if legacy.Version != "1.2.3" {
		t.Fatalf("expected normalized legacy version 1.2.3, got %q", legacy.Version)
	}
}
