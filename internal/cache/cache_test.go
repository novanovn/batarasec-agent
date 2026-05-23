package cache

import (
	"path/filepath"
	"testing"
)

func TestFindingDeltaFirstScanAndFollowUp(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	delta, err := db.FindingDelta("project-1", []string{"b", "a", "a"})
	if err != nil {
		t.Fatal(err)
	}
	if !delta.FirstScan || len(delta.New) != 2 || len(delta.Resolved) != 0 {
		t.Fatalf("unexpected first delta: %#v", delta)
	}

	if err := db.SetFindingBaseline("project-1", []string{"a", "b"}); err != nil {
		t.Fatal(err)
	}
	delta, err = db.FindingDelta("project-1", []string{"b", "c"})
	if err != nil {
		t.Fatal(err)
	}
	if delta.FirstScan || len(delta.New) != 1 || delta.New[0] != "c" || len(delta.Resolved) != 1 || delta.Resolved[0] != "a" {
		t.Fatalf("unexpected follow-up delta: %#v", delta)
	}
}
