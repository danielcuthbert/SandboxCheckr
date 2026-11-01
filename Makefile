# SandboxCheckr — pure Go, no cgo, no third-party dependencies.

BIN     := bin/sandboxcheckr
PKG     := ./cmd/sandboxcheckr
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.1.0-dev)
LDFLAGS := -ldflags "-X github.com/danielcuthbert/sandboxcheckr/internal/run.Version=$(VERSION)"

# cgo must be off: it is what lets a single static binary cross-compile, and
# the tool deliberately uses no native APIs.
export CGO_ENABLED := 0

.PHONY: all build test vet cross clean run

all: vet test build

build:
	go build $(LDFLAGS) -o $(BIN) $(PKG)

test:
	go test ./...

vet:
	go vet ./...

# Verify every supported platform compiles from any host.
cross:
	GOOS=linux GOARCH=arm64 go build ./...
	GOOS=linux GOARCH=amd64 go build ./...
	GOOS=darwin GOARCH=arm64 go build ./...
	GOOS=windows GOARCH=amd64 go build ./...
	GOOS=windows GOARCH=arm64 go build ./...

run: build
	./$(BIN)

clean:
	rm -rf bin
