.PHONY: build test lint clean install-tools

# Go parameters
GOCMD=go
GOCACHE?=$(CURDIR)/.cache/go-build
GOPATH?=$(CURDIR)/.cache/gopath
GOMODCACHE?=$(CURDIR)/.cache/gomod
GOLANGCI_LINT_CACHE?=$(CURDIR)/.cache/golangci-lint
GOLANGCI_LINT_VERSION?=v1.64.8
GOLANGCI_LINT_MODULE?=github.com/golangci/golangci-lint/cmd/golangci-lint
export GOCACHE
export GOPATH
export GOMODCACHE
export GOLANGCI_LINT_CACHE
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOINSTALL=$(GOCMD) install
GOMOD=$(GOCMD) mod
TOOLS_BIN=$(GOPATH)/bin
GOLANGCI_LINT_FLAGS?=--timeout=5m
BINARY_CONTROLLER=bin/arca-dns-controller
BINARY_AGENT=bin/arca-dns-agent

# Build flags
LDFLAGS=-ldflags "-s -w"

all: test build

build: build-controller build-agent

build-controller:
	@echo "Building controller..."
	@mkdir -p "$(GOCACHE)" "$(GOMODCACHE)" "$(TOOLS_BIN)"
	@mkdir -p bin
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_CONTROLLER) ./cmd/arca-dns-controller

build-agent:
	@echo "Building agent..."
	@mkdir -p "$(GOCACHE)" "$(GOMODCACHE)" "$(TOOLS_BIN)"
	@mkdir -p bin
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_AGENT) ./cmd/arca-dns-agent

test:
	@echo "Running tests..."
	@mkdir -p "$(GOCACHE)" "$(GOMODCACHE)" "$(TOOLS_BIN)"
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-coverage:
	@echo "Generating coverage report..."
	@mkdir -p "$(GOCACHE)" "$(GOMODCACHE)" "$(TOOLS_BIN)"
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

lint:
	@echo "Running linters..."
	@test -x "$(TOOLS_BIN)/golangci-lint" || { echo "golangci-lint not installed. Run: make install-tools"; exit 1; }
	$(TOOLS_BIN)/golangci-lint run $(GOLANGCI_LINT_FLAGS) ./...

install-tools:
	@echo "Installing development tools..."
	@mkdir -p "$(GOCACHE)" "$(GOMODCACHE)" "$(TOOLS_BIN)"
	$(GOINSTALL) $(GOLANGCI_LINT_MODULE)@$(GOLANGCI_LINT_VERSION)

clean:
	@echo "Cleaning..."
	@rm -rf bin/
	@rm -f coverage.out coverage.html

fmt:
	@echo "Formatting code..."
	$(GOCMD) fmt ./...

vet:
	@echo "Running go vet..."
	$(GOCMD) vet ./...

deps:
	@echo "Downloading dependencies..."
	$(GOMOD) download
	$(GOMOD) tidy

run-controller:
	@echo "Running controller..."
	$(GOBUILD) -o $(BINARY_CONTROLLER) ./cmd/arca-dns-controller
	$(BINARY_CONTROLLER) serve

run-agent:
	@echo "Running agent..."
	$(GOBUILD) -o $(BINARY_AGENT) ./cmd/arca-dns-agent
	$(BINARY_AGENT) daemon

docker-build:
	@echo "Building Docker images..."
	docker build -t arca-dns-controller:latest -f deployments/docker/Dockerfile.controller .
	docker build -t arca-dns-agent:latest -f deployments/docker/Dockerfile.agent .

help:
	@echo "Available targets:"
	@echo "  build            - Build both controller and agent binaries"
	@echo "  build-controller - Build controller binary"
	@echo "  build-agent      - Build agent binary"
	@echo "  test             - Run tests with race detector"
	@echo "  test-coverage    - Generate test coverage report"
	@echo "  lint             - Run golangci-lint"
	@echo "  clean            - Remove build artifacts"
	@echo "  fmt              - Format code"
	@echo "  vet              - Run go vet"
	@echo "  deps             - Download and tidy dependencies"
	@echo "  install-tools    - Install development tools"
	@echo "  run-controller   - Build and run controller"
	@echo "  run-agent        - Build and run agent"
	@echo "  docker-build     - Build Docker images"
