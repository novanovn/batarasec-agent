package scanner

import (
	"context"
	"errors"
	"testing"
)

func TestParseLynisReport(t *testing.T) {
	report := "warning[]=SSH root login allowed [SSH-7408]\nsuggestion[]=Install debsums utility [PKGS-7370]\n"
	findings := parseLynisReport(report)
	if len(findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(findings))
	}
	if findings[0].RuleID != "LYNIS-SSH-7408" || findings[0].Severity != "medium" {
		t.Fatalf("unexpected warning: %#v", findings[0])
	}
	if findings[1].RuleID != "LYNIS-PKGS-7370" || findings[1].Severity != "low" {
		t.Fatalf("unexpected suggestion: %#v", findings[1])
	}
}

func TestCheckCISToolsPrefersLynis(t *testing.T) {
	runCalled := false
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		runCalled = true
		if name != "lynis" {
			t.Fatalf("expected lynis, got %s", name)
		}
		return []byte("ignored"), nil
	}
	readFile := func(string) ([]byte, error) {
		return []byte("warning[]=Weak permissions [FILE-6310]\n"), nil
	}
	lookPath := func(name string) (string, error) {
		if name == "lynis" || name == "oscap" {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("missing")
	}

	findings := checkCISToolsWithRunner(run, readFile, func(string) error { return nil }, func() string { return "/tmp" }, lookPath)
	if !runCalled || len(findings) != 1 || findings[0].RuleID != "LYNIS-FILE-6310" {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestParseOpenSCAPOutput(t *testing.T) {
	output := "Title\nrule_xccdf_org.ssgproject.content_rule_sshd_disable_root_login fail\nrule_ok pass\n"
	findings := parseOpenSCAPOutput(output)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].RuleID != "OSCAP-rule_xccdf_org.ssgproject.content_rule_sshd_disable_root_login" {
		t.Fatalf("unexpected rule: %#v", findings[0])
	}
}

func TestRunOpenSCAPDoesNotFetchRemoteResources(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "oscap" {
			t.Fatalf("expected oscap, got %s", name)
		}
		for _, arg := range args {
			if arg == "--fetch-remote-resources" {
				t.Fatal("OpenSCAP default scan must not fetch remote resources")
			}
		}
		return []byte("rule_xccdf_org.ssgproject.content_rule_sshd_disable_root_login fail\n"), nil
	}

	findings := runOpenSCAP(run)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
}

func TestCheckCISToolsSkipsWhenUnavailable(t *testing.T) {
	findings := checkCISToolsWithRunner(nil, nil, nil, nil, func(string) (string, error) { return "", errors.New("missing") })
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
