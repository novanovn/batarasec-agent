package scanner

import (
	"context"
	"errors"
	"testing"
)

func TestParseLSMod(t *testing.T) {
	mods := parseLSMod("Module                  Size  Used by\nrootkit_hide           16384  0\nnf_conntrack          196608  1 nf_nat\n")
	if len(mods) != 2 {
		t.Fatalf("expected 2 modules, got %d", len(mods))
	}
	if mods[0].Name != "rootkit_hide" || mods[1].By != "nf_nat" {
		t.Fatalf("unexpected modules: %#v", mods)
	}
}

func TestCheckKernelModulesFlagsSuspiciousUnknownAndUnsigned(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		switch name {
		case "lsmod":
			return []byte("Module Size Used by\nrootkit_hide 16384 0\nnormal_mod 20480 1\nunknown_mod 4096 0\nunowned_mod 8192 0\n"), nil
		case "modinfo":
			switch args[0] {
			case "rootkit_hide":
				return []byte("filename: /lib/modules/6.1/kernel/drivers/rootkit_hide.ko\nlicense: GPL\n"), nil
			case "normal_mod":
				return []byte("filename: /lib/modules/6.1/kernel/drivers/normal_mod.ko\nsigner: Debian Secure Boot CA\n"), nil
			case "unknown_mod":
				return nil, errors.New("missing")
			case "unowned_mod":
				return []byte("filename: /lib/modules/6.1/extra/unowned_mod.ko\nsigner: Vendor CA\n"), nil
			}
		case "dpkg":
			path := args[len(args)-1]
			if path == "/lib/modules/6.1/kernel/drivers/normal_mod.ko" || path == "/lib/modules/6.1/kernel/drivers/rootkit_hide.ko" {
				return []byte("linux-modules: " + path), nil
			}
			return nil, errors.New("not owned")
		}
		return nil, errors.New("unexpected command")
	}
	lookPath := func(name string) (string, error) {
		if name == "lsmod" || name == "modinfo" || name == "dpkg" {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("missing")
	}

	findings := checkKernelModulesWithRunner(run, lookPath)
	rules := map[string]int{}
	for _, f := range findings {
		rules[f.RuleID]++
	}
	if rules["KMOD-001"] != 1 || rules["KMOD-002"] != 1 || rules["KMOD-003"] != 1 || rules["KMOD-004"] != 1 {
		t.Fatalf("unexpected rules: %#v", rules)
	}
}

func TestCheckKernelModulesSkipsWhenLSModMissing(t *testing.T) {
	findings := checkKernelModulesWithRunner(nil, func(string) (string, error) { return "", errors.New("missing") })
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %d", len(findings))
	}
}
