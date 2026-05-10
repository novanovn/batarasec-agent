package scanner

import (
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// Package is a dependency found in a manifest file, before vuln matching.
type Package struct {
	Name      string
	Version   string // exact version if pinned, otherwise best-effort
	Ecosystem string // npm | go | python
	FilePath  string
}

// skipDirs are never walked.
var skipDirs = map[string]struct{}{
	".git": {}, "node_modules": {}, ".cache": {}, "vendor": {},
	"__pycache__": {}, ".tox": {}, ".venv": {}, "venv": {},
	"dist": {}, "build": {}, ".npm": {},
}

// Scanner walks configured paths and parses dependency manifests.
type Scanner struct {
	paths  []string
	logger *zap.Logger
}

func New(paths []string, logger *zap.Logger) *Scanner {
	return &Scanner{paths: paths, logger: logger}
}

// Result holds a parsed manifest's packages and file content hash.
type Result struct {
	FilePath    string
	ContentHash string // sha256 hex of raw file contents
	Packages    []Package
}

// Scan walks all configured paths and returns one Result per manifest found.
func (s *Scanner) Scan() []Result {
	var results []Result

	for _, root := range s.paths {
		if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil // skip unreadable entries silently
			}
			if d.IsDir() {
				if _, skip := skipDirs[d.Name()]; skip {
					return filepath.SkipDir
				}
				return nil
			}

			res, parseErr := s.parseManifest(path, d.Name())
			if parseErr != nil {
				s.logger.Debug("parse error", zap.String("path", path), zap.Error(parseErr))
				return nil
			}
			if res != nil {
				results = append(results, *res)
			}
			return nil
		}); err != nil {
			s.logger.Warn("walk error", zap.String("root", root), zap.Error(err))
		}
	}

	return results
}

func (s *Scanner) parseManifest(path, name string) (*Result, error) {
	var (
		pkgs []Package
		err  error
	)

	switch {
	case name == "package-lock.json":
		pkgs, err = parseNPM(path)
	case name == "go.sum":
		pkgs, err = parseGoSum(path)
	case name == "go.mod":
		pkgs, err = parseGoMod(path)
	case name == "requirements.txt" || strings.HasSuffix(name, "-requirements.txt"):
		pkgs, err = parseRequirements(path)
	case name == "Pipfile.lock":
		pkgs, err = parsePipfileLock(path)
	case name == "poetry.lock":
		pkgs, err = parsePoetryLock(path)
	default:
		return nil, nil
	}

	if err != nil {
		return nil, err
	}

	hash, hashErr := fileHash(path)
	if hashErr != nil {
		return nil, hashErr
	}

	return &Result{
		FilePath:    path,
		ContentHash: hash,
		Packages:    pkgs,
	}, nil
}

func fileHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open for hash: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
