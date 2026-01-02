# arca-dns

A high-availability, scalable authoritative DNS system with BGP Anycast + ECMP and split control/data plane architecture.

## Overview

arca-dns is designed for large-scale DNS deployments with the following features:

- **Split Architecture**: Separate control plane (management/signing) and data plane (distribution/routing)
- **BGP Anycast + ECMP**: Horizontal scaling with equal-cost multi-path routing
- **DNSSEC**: Central signing with automated key management
- **Pluggable Backends**: MySQL, Git, or etcd for zone storage
- **High Performance**: Designed for high-throughput deployments
- **Observability**: DNSTap binary logging and Prometheus metrics

## Architecture

### Control Plane: `arca-dns-controller`
- REST API for zone management (JSON and raw BIND formats)
- Central DNSSEC signing (KSK/ZSK management)
- Pluggable storage backends (MySQL, Git, etcd, in-memory)
- Zone versioning and artifact distribution

### Data Plane: `arca-dns-agent`
- Zone synchronization from controller
- NSD and Unbound orchestration
- BIRD BGP route control with health checking
- DNSTap logging and Prometheus metrics
- Automatic failover and recovery

## Quick Start

### Prerequisites

- Go (see `go.mod`)
- NSD (authoritative DNS server)
- Unbound (recursive resolver)
- BIRD (BGP routing daemon)

Note: `arca-dns-controller` itself can be started without NSD/Unbound/BIRD, but a functional data plane node requires them.

### Build

```bash
make build
```

This creates two binaries:
- `bin/arca-dns-controller` - Control plane server
- `bin/arca-dns-agent` - Data plane agent

### Run Controller

```bash
./bin/arca-dns-controller serve --config configs/controller.example.yaml
```

### Run Agent

```bash
./bin/arca-dns-agent daemon --config configs/agent.example.yaml
```

## Development

### Install Development Tools

```bash
make install-tools
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
  # TLS is typically terminated by a reverse proxy / ingress.

backend:
  type: "memory"  # Options: memory, mysql, git, etcd

dnssec:
  enabled: true
  algorithm: 13  # ECDSA-P256
  key_directory: "/var/lib/arca-dns/keys"
```

### Agent Configuration Example

```yaml
controller:
  url: "http://localhost:8080"
  sync_interval: "30s"

nsd:
  config_path: "/etc/nsd/nsd.conf"
  zone_directory: "/var/lib/nsd/zones"

unbound:
  config_path: "/etc/unbound/unbound.conf"
  edns_buffer_size: 1232  # ECMP fragment prevention

bird:
  socket_path: "/var/run/bird/bird.ctl"
  anycast_prefixes:
    - "203.0.113.53/32"

health:
  check_interval: "10s"
  failure_threshold: 3
  recovery_threshold: 5
```

## API Documentation

API documentation is available in OpenAPI format: [api/openapi.yaml](api/openapi.yaml)

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
- API spec: `api/openapi.yaml`

## Contributing

Contributions are welcome — please open an issue/PR and include a clear description and reproduction steps (if applicable).

## License

See [LICENSE](LICENSE) file for details.

## Roadmap

Roadmap is tracked via GitHub issues/milestones.

## Support

For issues and questions, please use the [GitHub issue tracker](https://github.com/akam1o/arca-dns/issues).
