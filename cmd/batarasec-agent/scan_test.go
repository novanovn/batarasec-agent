package main

import "testing"

func TestShouldUpdateVulnerabilityBaseline(t *testing.T) {
	tests := []struct {
		name          string
		fullScan      bool
		manifestCount int
		changedCount  int
		want          bool
	}{
		{name: "explicit full scan", fullScan: true, manifestCount: 3, changedCount: 1, want: true},
		{name: "first scan processes all manifests", manifestCount: 3, changedCount: 3, want: true},
		{name: "partial delta skips baseline", manifestCount: 3, changedCount: 1, want: false},
		{name: "empty snapshot is complete", manifestCount: 0, changedCount: 0, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := shouldUpdateVulnerabilityBaseline(tt.fullScan, tt.manifestCount, tt.changedCount)
			if got != tt.want {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
		})
	}
}
