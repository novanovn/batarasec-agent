package scanner

import "testing"

func TestParseNPMV1Dependencies(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "app",
  "lockfileVersion": 1,
  "dependencies": {
    "lodash": { "version": "4.17.20" },
    "empty": { "version": "" }
  }
}`)

	pkgs, err := parseNPM(path)
	if err != nil {
		t.Fatalf("parseNPM returned error: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d: %#v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "lodash" || pkgs[0].Version != "4.17.20" || pkgs[0].Ecosystem != "npm" {
		t.Fatalf("unexpected package: %#v", pkgs[0])
	}
}

func TestParseNPMV2Packages(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "app",
  "lockfileVersion": 2,
  "packages": {
    "": { "version": "1.0.0" },
    "node_modules/express": { "version": "4.18.2" },
    "node_modules/@scope/pkg": { "version": "2.0.0" },
    "packages/web/node_modules/react": { "version": "18.2.0" }
  }
}`)

	pkgs, err := parseNPM(path)
	if err != nil {
		t.Fatalf("parseNPM returned error: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %#v", len(pkgs), pkgs)
	}
	for name, version := range map[string]string{"express": "4.18.2", "@scope/pkg": "2.0.0", "react": "18.2.0"} {
		pkg, ok := packageByName(pkgs, name)
		if !ok {
			t.Fatalf("package %s not found: %#v", name, pkgs)
		}
		if pkg.Version != version || pkg.Ecosystem != "npm" {
			t.Fatalf("unexpected package for %s: %#v", name, pkg)
		}
	}
}

func TestParseNPMV3Packages(t *testing.T) {
	path := writeTempFile(t, "package-lock.json", `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "node_modules/next": { "version": "14.2.0" }
  }
}`)

	pkgs, err := parseNPM(path)
	if err != nil {
		t.Fatalf("parseNPM returned error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Name != "next" || pkgs[0].Version != "14.2.0" {
		t.Fatalf("unexpected packages: %#v", pkgs)
	}
}
