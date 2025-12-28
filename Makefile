.PHONY: build test lint clean install-tools

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_CONTROLLER=bin/arca-dns-controller
BINARY_AGENT=bin/arca-dns-agent

# Build flags
LDFLAGS=-ldflags "-s -w"

all: test build

build: build-controller build-agent

build-controller:
	@echo "Building controller..."
	@mkdir -p bin
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_CONTROLLER) ./cmd/arca-dns-controller

build-agent:
	@echo "Building agent..."
	@mkdir -p bin
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_AGENT) ./cmd/arca-dns-agent

test:
	@echo "Running tests..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...

test-coverage:
	@echo "Generating coverage report..."
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

lint:
	@echo "Running linters..."
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint not installed. Run: make install-tools"; exit 1; }
	golangci-lint run ./...

install-tools:
	@echo "Installing development tools..."
	$(GOGET) github.com/golangci/golangci-lint/cmd/golangci-lint@latest

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
	docker build -t arca-dns-controller:latest -f deployments/Dockerfile.controller .
	docker build -t arca-dns-agent:latest -f deployments/Dockerfile.agent .

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
