# arca-dns

[![Tests](https://github.com/akam1o/arca-dns/actions/workflows/test.yml/badge.svg)](https://github.com/akam1o/arca-dns/actions/workflows/test.yml)
[![Lint](https://github.com/akam1o/arca-dns/actions/workflows/lint.yml/badge.svg)](https://github.com/akam1o/arca-dns/actions/workflows/lint.yml)
[![Build](https://github.com/akam1o/arca-dns/actions/workflows/build.yml/badge.svg)](https://github.com/akam1o/arca-dns/actions/workflows/build.yml)

English | [日本語](README.ja.md)

arca-dns is a high-availability, scalable authoritative DNS system with BGP Anycast + ECMP and a split control/data plane architecture.

## Overview

arca-dns is designed for large-scale DNS deployments with the following features:

- **Split Architecture**: Separate control plane (management/signing) and data plane (distribution/routing)
- **BGP Anycast + ECMP**: Horizontal scaling with equal-cost multi-path routing
- **DNSSEC**: Central signing with automated key management
- **Pluggable Backends**: SQLite (default), PostgreSQL, MySQL, Git, or etcd for zone storage
- **High Performance**: Designed for high-throughput deployments
- **Observability**: DNSTap binary logging and Prometheus metrics

## Architecture

### Control Plane: `arca-dns-controller`
- REST API for zone management (JSON and raw BIND formats)
- Central DNSSEC signing (KSK/ZSK management)
- Pluggable storage backends (SQLite, PostgreSQL, MySQL, Git, etcd)
- Zone versioning and artifact distribution

### Data Plane: `arca-dns-agent`
- Zone synchronization from controller
- DNS server orchestration via plugin interfaces (NSD, Unbound, BIRD)
- BIRD BGP route control with health checking
- DNSTap logging and Prometheus metrics
- Automatic failover and recovery

## Quick Start

This project is operated as a split control/data plane:
- **Control plane (controller)**: Kubernetes / Docker Compose / packages
- **Data plane (agent)**: packages on edge nodes (recommended)

## Deploy

### Control Plane (Controller)

The controller is a standard HTTP API service; TLS is typically terminated by an ingress/reverse proxy.

**Kubernetes (recommended backend: etcd)**:
- Manifests are under `deployments/kubernetes/controller/` (base + overlays).
- Apply:
  - `kubectl apply -k deployments/kubernetes/controller/base` (external/HA etcd)
  - `kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd` (demo-only; includes single-node etcd)
- Replace in manifests:
  - `deployments/kubernetes/controller/base/controller-secret.yaml` (`dnssec-master-key-b64`)
  - `deployments/kubernetes/controller/base/controller.yaml` (API keys, etcd endpoints)
  - (Optional) `deployments/kubernetes/controller/examples/ingress.yaml` (ingress host/class; TLS at ingress)

**Docker Compose (Controller + MySQL example)**:
- Example compose file: `deployments/compose/controller-mysql/docker-compose.yaml`
- Run:
  ```bash
  export ARCA_DNS_API_KEY="$(openssl rand -hex 32)"
  export ARCA_DNS_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_API_KEY" | sha256sum | awk '{print $1}')"
  export ARCA_DNS_AGENT_API_KEY="$(openssl rand -hex 32)"
  export ARCA_DNS_AGENT_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_AGENT_API_KEY" | sha256sum | awk '{print $1}')"
  export ARCA_DNS_DNSSEC_MASTER_KEY_B64="$(openssl rand -base64 32)"
  export ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY="$(openssl rand -base64 32)"

  docker compose -f deployments/compose/controller-mysql/docker-compose.yaml --project-directory . up -d
  ```

**DEB/RPM packages**:
- Packaging assets live under `packaging/` and are built via `.goreleaser.yaml`.
- See `docs/packaging.md` for how to build/install packages and `docs/deployment.md` for operational setup.

### Data Plane (Agent)

The agent is designed to control NSD/Unbound/BIRD on the host and is typically deployed on edge nodes/VMs (not Kubernetes).

**DEB/RPM packages (recommended)**:
1. Install runtime deps: NSD, Unbound, BIRD (bird2 on Debian/Ubuntu).
2. Install `arca-dns` package (agent + controller binaries).
3. Configure `/etc/arca-dns/agent.yaml` (based on `configs/agent.example.yaml`).
4. Start service: `systemctl enable --now arca-dns-agent`

See `docs/deployment.md` and `docs/operations.md` for day-2 operations.

## Development

### Install Development Tools

```bash
make install-tools
```

### Makefile Targets

```bash
make help          # Show available targets
make install-tools # Install development tools (golangci-lint)
make deps          # Download dependencies (go mod download/tidy)
make build         # Build controller + agent binaries
make test          # Run tests (-race + coverage.out)
make test-coverage # Generate coverage.html
make lint          # Run linters
make fmt           # Format code
make vet           # Run go vet
make run-controller CONTROLLER_RUN_CONFIG=/path/to/controller.yaml # Build + run controller
make run-agent AGENT_RUN_CONFIG=/path/to/agent.yaml                # Build + run agent
make docker-build  # Build Docker images
make clean         # Remove build artifacts
```

### Packaging (DEB/RPM)

See `docs/packaging.md`.

### Run Tests

```bash
make test
```

### Run Linter

```bash
make lint
```

### Code Coverage

```bash
make test-coverage
```

## Configuration

See `configs/controller.example.yaml` and `configs/agent.example.yaml`, plus `docs/deployment.md` / `docs/operations.md`.

### Controller Configuration Example

```yaml
api:
  listen: "0.0.0.0:8080"
  # Generate with: openssl rand -base64 32
  artifact_signature_key: "REPLACE_WITH_SHARED_SIGNATURE_KEY"
  # TLS is typically terminated by a reverse proxy / ingress.
  auth:
    enabled: true
    api_keys:
      admin: "sha256:REPLACE_WITH_SHA256_HEX"
      agent: "sha256:REPLACE_WITH_AGENT_SHA256_HEX"
    api_key_roles:
      admin: "admin"
      agent: "agent"

observability:
  # Prometheus /metrics endpoint. /health, /ready, and /status are on the API listener.
  # Bind to 0.0.0.0 only behind network controls or an authenticated proxy.
  listen: "127.0.0.1:9053"

backend:
  type: "sqlite"  # Options: sqlite, postgres, mysql, git, etcd

dnssec:
  enabled: true
  algorithm: 13  # ECDSA-P256
  key_directory: "/var/lib/arca-dns/keys"
```

### Agent Configuration Example

```yaml
controller:
  # Prefer https:// unless this is an intentionally trusted local/private transport.
  # Using http:// with api_key logs a warning.
  url: "http://localhost:8080"
  api_key: "REPLACE_WITH_RAW_AGENT_API_KEY"

sync:
  sync_interval: "30s"
  verify_signatures: true
  # Shared HMAC secret; must match api.artifact_signature_key.
  controller_signature_key: "REPLACE_WITH_SHARED_SIGNATURE_KEY"

nsd:
  enabled: true
  config_path: "/etc/nsd/nsd.conf"
  zone_config_path: "/etc/nsd/arca-dns-zones.conf" # include this from nsd.conf
  zone_directory: "/var/lib/nsd/zones"

unbound:
  enabled: true
  config_path: "/etc/unbound/unbound.conf"
  edns_buffer_size: 1232  # ECMP fragment prevention

bird:
  enabled: true
  socket_path: "/var/run/bird/bird.ctl"
  protocols:
    - name: "anycast_1"
      neighbor_address: "10.0.0.1"
      neighbor_asn: 64512

dnstap:
  enabled: false
  socket_path: "/var/run/dnstap.sock"
  socket_mode: "0660"
  socket_group: "arca-dns" # add the DNS daemon user to this shared group

health:
  check_interval: "10s"
  failure_threshold: 3
  recovery_threshold: 5
  nsd_server: "127.0.0.1:5353"
  unbound_server: "127.0.0.1:53"
```

### Local Build / Run (dev)

Prerequisites:
- Go (see `go.mod`)

Build:
```bash
make build
```

Run controller:
```bash
# Replace API key placeholders and configure a DNSSEC master key first.
./bin/arca-dns-controller serve --config configs/controller.example.yaml
```

Run agent (requires NSD/Unbound/BIRD installed on the host if enabled in config):
```bash
./bin/arca-dns-agent daemon --config configs/agent.example.yaml
```

## API Documentation

API documentation is available in OpenAPI format: [api/openapi.yaml](api/openapi.yaml)
Contributing guide: [docs/contributing.md](docs/contributing.md)

### Zone Management Examples

**Create Zone (JSON)**:
```bash
curl -X POST http://localhost:8080/api/v1/zones \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-api-key" \
  -d '{
    "name": "example.com",
    "soa": {
      "mname": "ns1.example.com",
      "rname": "admin.example.com",
      "refresh": 3600,
      "retry": 1800,
      "expire": 604800,
      "minimum": 86400
    },
    "records": [
      {"name": "@", "type": "NS", "ttl": 3600, "value": "ns1.example.com."},
      {"name": "@", "type": "NS", "ttl": 3600, "value": "ns2.example.com."},
      {"name": "@", "type": "A", "ttl": 300, "value": "203.0.113.1"}
    ]
  }'
```

**Create Zone (Raw BIND)**:
```bash
curl -X POST http://localhost:8080/api/v1/zones/raw \
  -H "Content-Type: text/plain" \
  -H "X-API-Key: your-api-key" \
  --data-binary @example.com.zone
```

**Add 1 record (record CRUD via ETag / If-Match)**:

```bash
BASE="http://localhost:8080/api/v1"
API_KEY="your-api-key" # only if auth is enabled

etag="$(curl -sI "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X POST "${BASE}/zones/example.com./records" \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{"name":"www","type":"A","ttl":300,"value":"203.0.113.2"}'
```

**Apply multiple record changes atomically**:

```bash
etag="$(curl -sI "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"
old_id="$(curl -s "${BASE}/zones/example.com./records" -H "X-API-Key: ${API_KEY}" | jq -r '.records[] | select(.name=="old" and .type=="A") | .id')"

curl -i -X POST "${BASE}/zones/example.com./records/batch" \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d "{
    \"create\": [
      {\"name\":\"api\",\"type\":\"AAAA\",\"ttl\":300,\"value\":\"2001:db8::1\"}
    ],
    \"delete\": [
      {\"id\":\"${old_id}\"}
    ]
  }"
```

**Update or delete a record**:

```bash
record_id="$(curl -s "${BASE}/zones/example.com./records" -H "X-API-Key: ${API_KEY}" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"
etag="$(curl -sI "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X PUT "${BASE}/zones/example.com./records/${record_id}" \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{"name":"www","type":"A","ttl":300,"value":"203.0.113.3"}'

etag="$(curl -sI "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"
record_id="$(curl -s "${BASE}/zones/example.com./records" -H "X-API-Key: ${API_KEY}" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"

curl -i -X DELETE "${BASE}/zones/example.com./records/${record_id}" \
  -H "X-API-Key: ${API_KEY}" \
  -H "If-Match: ${etag}"
```

See `docs/api.md` for record value formats and more examples.

## Project Structure

```
arca-dns/
├── cmd/
│   ├── arca-dns-controller/    # Controller main
│   └── arca-dns-agent/          # Agent main
├── pkg/
│   ├── config/                  # Configuration structures
│   ├── model/                   # Domain models
│   ├── backend/                 # Storage backends
│   ├── dnssec/                  # DNSSEC signing
│   ├── parser/                  # Zone file parsing
│   └── protocol/                # API protocols
├── internal/
│   ├── agent/
│   │   ├── bird/                # BIRD BGP control
│   │   ├── nsd/                 # NSD orchestration
│   │   ├── dnstap/              # DNSTap logging
│   │   └── sync/                # Zone synchronization
│   └── controller/
│       ├── api/                 # API handlers
│       └── service/             # Business logic
├── api/                         # OpenAPI specifications
├── configs/                     # Example configurations
├── deployments/                 # Docker/K8s manifests
└── test/                        # Integration tests
```

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment Guide](docs/deployment.md)
- [API Reference](docs/api.md)
- [Operations Guide](docs/operations.md)
- [DNSSEC Management](docs/dnssec.md)
- [Packaging](docs/packaging.md)

## Contributing

Contributions are welcome! See [docs/contributing.md](docs/contributing.md).

## Contact

For inquiries, open an issue on [GitHub Issues](https://github.com/akam1o/arca-dns/issues). For security reports, use [GitHub Security Advisories](https://github.com/akam1o/arca-dns/security/advisories).

## License

Apache License 2.0

## Roadmap

Roadmap is tracked via GitHub issues/milestones.

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/akam1o/arca-dns/issues).
