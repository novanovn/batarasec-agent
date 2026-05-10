VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || echo "unknown")

PKG = github.com/batarasec/agent/internal/version
LDFLAGS = \
  -X $(PKG).Version=$(VERSION) \
  -X $(PKG).Commit=$(COMMIT) \
  -X $(PKG).BuildTime=$(BUILD_TIME) \
  -s -w

BINARY = batarasec-agent
MAIN   = ./cmd/batarasec-agent
DIST   = dist

.PHONY: build test lint install clean cross release

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) $(MAIN)

test:
	go test ./...

lint:
	golangci-lint run ./...

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

clean:
	rm -f $(BINARY)
	rm -rf $(DIST)

cross:
	mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-amd64 $(MAIN)
	CGO_ENABLED=0 GOOS=linux  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(DIST)/$(BINARY)-linux-arm64 $(MAIN)
	sha256sum $(DIST)/$(BINARY)-* > $(DIST)/checksums.txt

release:
	goreleaser release --clean
