# arca-dns Architecture

English | [日本語](architecture.ja.md)

## Overview

arca-dns is a BGP Anycast DNS system with split control/data plane architecture designed for high availability, security, and operational simplicity.

## System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Control Plane                            │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          arca-dns-controller                          │   │
│  │                                                        │   │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │   │
│  │  │ REST API │  │  DNSSEC   │  │ Backend Storage   │  │   │
│  │  │          │  │  Signing  │  │(SQLite/PG/MySQL/..)│  │   │
│  │  └────┬─────┘  └─────┬────┘  └─────────┬─────────┘  │   │
│  │       │              │                  │             │   │
│  │       └──────────────┴──────────────────┘             │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTPS + ETag
                             │ (Zone Sync)
        ┌────────────────────┴────────────────────┐
        │                                          │
┌───────▼──────────────────┐          ┌───────────▼─────────────┐
│   Data Plane (Site 1)    │          │  Data Plane (Site N)    │
│                           │          │                          │
│  arca-dns-agent           │          │  arca-dns-agent          │
│  ├─ Zone Sync             │          │  ├─ Zone Sync            │
│  ├─ NSD (Authoritative)   │          │  ├─ NSD (Authoritative)  │
│  ├─ Unbound (Recursive)   │          │  ├─ Unbound (Recursive)  │
│  ├─ BIRD (BGP Control)    │          │  ├─ BIRD (BGP Control)   │
│  └─ DNSTap Observability  │          │  └─ DNSTap Observability │
│           │               │          │           │              │
│           ▼               │          │           ▼              │
│    ┌──────────────┐       │          │    ┌──────────────┐     │
│    │ BGP Routers  │       │          │    │ BGP Routers  │     │
│    └──────────────┘       │          │    └──────────────┘     │
└───────────────────────────┘          └──────────────────────────┘
```

## Component Breakdown

### Control Plane: arca-dns-controller

**Purpose**: Centralized zone management, DNSSEC signing, and API server.

**Key Components**:
1. **REST API** (`internal/controller/api/`)
   - Zone CRUD operations (JSON + Raw BIND format)
   - Signed zone artifact distribution
   - DNSSEC key management endpoints
   - Health/metrics endpoints

2. **DNSSEC Signing** (`pkg/dnssec/`)
   - KSK/ZSK key management with encrypted storage
   - Automatic zone signing with NSEC3
   - Background re-signing scheduler
   - DS record export for parent zones

3. **Backend Storage** (`pkg/backend/`)
   - Pluggable storage: SQLite (default), PostgreSQL, MySQL, Git, etcd
   - Capability-based interfaces (ZoneStore, TransactionalStore, RevisionStore, WatchableStore)
   - Transaction support (SQLite, PostgreSQL, MySQL), versioning (Git), watch (etcd)
   - Use SQLite with `:memory:` for disposable local testing

**Data Flow**:
```
User → REST API → Validation → Backend Storage
                       ↓
                 DNSSEC Signing
                       ↓
              Artifact Generation
                       ↓
              Agent Distribution
```

### Data Plane: arca-dns-agent

**Purpose**: Autonomous DNS serving with health-based BGP route control.

**Key Components**:
1. **Zone Sync** (`internal/agent/sync/`)
   - Polls controller for zone updates (ETag conditional fetch)
   - Atomic file writes with backup versions
   - Checksum verification
   - Graceful degradation (serves stale zones if controller unreachable)

2. **Plugin Interfaces** (`internal/agent/plugin/`)
   - `AuthoritativeServer`: Interface for authoritative DNS (NSD, Knot DNS)
   - `Resolver`: Interface for recursive DNS (Unbound)
   - `RouteController`: Interface for BGP route control (BIRD, FRRouting)
   - Noop implementations for disabled components
   - Enables swapping DNS server implementations without changing agent core

3. **NSD Controller** (`internal/agent/nsd/`)
   - Authoritative DNS server orchestration
   - Zone file generation and validation
   - Atomic reload (checkzone before reload)
   - Implements `AuthoritativeServer` plugin interface via adapter

4. **Unbound Controller** (`internal/agent/unbound/`)
   - Recursive DNS resolver orchestration
   - Stub-zone configuration for local NSD
   - EDNS buffer size enforcement (1232 for ECMP safety)
   - Implements `Resolver` plugin interface via adapter

5. **BIRD BGP Control** (`internal/agent/bird/`)
   - Health-driven route announcement/withdrawal
   - State machine with debounce (prevents flapping)
   - Graceful degradation (latency vs hard failure)
   - Implements `RouteController` plugin interface via adapter

6. **DNSTap Observability** (`internal/agent/dnstap/`)
   - Binary query logging via Unix socket
   - Prometheus metrics export
   - Sampled logging (configurable rate)
   - Query aggregation by type/rcode/transport

**Data Flow**:
```
Controller → Zone Sync → File Manager → NSD/Unbound
                                            ↓
                              Health Checker (5 layers)
                                            ↓
                              Health Engine → State Machine
                                            ↓
                              Route Manager → BIRD
                                            ↓
                              BGP Route Announcement
```

## Key Design Decisions

### 1. Control/Data Plane Separation

**Rationale**:
- Controller can be single-instance (simpler ops)
- Agents are autonomous (survive controller outages)
- Scales horizontally (add agents without controller changes)

**Trade-offs**:
- Higher latency for zone updates (poll-based)
- More complex agent logic (autonomy requires smarts)
- ✅ Better reliability and operational simplicity

### 2. Central DNSSEC Signing

**Rationale**:
- Agents don't need access to signing keys (security)
- Uniform signatures across all anycast sites
- Simpler key rotation (one place)

**Trade-offs**:
- Controller must sign before distribution
- Cannot sign per-site (but not needed for anycast)
- ✅ Better security and consistency

### 3. Poll-Based Zone Sync with ETag

**Rationale**:
- No persistent connections (simpler networking)
- HTTP caching semantics (304 Not Modified)
- Agents control sync timing (no push surprises)

**Trade-offs**:
- Updates not instant (30s default interval)
- More HTTP requests (but mostly 304s)
- ✅ Better operational simplicity and bandwidth efficiency

### 4. EDNS Buffer 1232

**Rationale**:
- Prevents UDP fragmentation
- ECMP safe (fragments may take different paths)
- RFC 8899 recommendation

**Implementation**: Enforced in Unbound config, validated in health checks.

### 5. Health-Based BGP Control

**Rationale**:
- Bad DNS is worse than no DNS (fail fast)
- Graceful degradation (latency vs total failure)
- Prevents partial outages from affecting users

**State Machine**:
```
Healthy → [3 failures] → Unhealthy (routes withdrawn)
Unhealthy → [3 successes] → Recovering → [30s + 3 more] → Healthy
Degraded: High latency but functional (routes stay up)
```

## Data Model

### Zone Structure
```go
type Zone struct {
    Name        string          // example.com.
    Version     string          // v01ARZ3NDEKTSV4RRFFQ69G5FAV
    SOA         SOARecord
    Records     []Record        // A, AAAA, MX, TXT, etc.
    DNSSEC      DNSSECConfig    // KSK/ZSK IDs, NSEC3 params
    UpdatedAt   time.Time
}
```

### Version System
- Version (ETag): `v{ULID}` (controller-issued)
- Hash: First 8 chars of SHA256(normalized zone content), exposed as `X-Zone-Hash`
- Used for: ETag, conditional GET, artifact filenames, rollback

### Artifact Structure
```
/var/lib/arca-dns/artifacts/
├── example.com/
│   ├── v01ARZ3NDEKTSV4RRFFQ69G5FAV.zone.signed  # BIND format
│   ├── v01ARZ3NDEKTSV4RRFFQ69G5FAV.json         # Metadata (optional)
│   └── latest -> v01ARZ3NDEKTSV4RRFFQ69G5FAV.zone.signed
```

## Security Model

### Controller Security
1. **API Authentication**: API key-based
2. **Rate Limiting**: Per-client, separate read/write limits
3. **Input Validation**: Size limits, format checks
4. **Audit Logging**: All API requests logged with request ID
5. **DNSSEC Keys**: Encrypted at rest (AES-256-GCM)

### Agent Security
1. **TLS**: Optional mutual TLS to the controller endpoint (typically a reverse proxy / ingress)
2. **Least Privilege**: Read-only API access
3. **File Permissions**: Restrictive permissions on zone files
4. **Key Isolation**: Signing keys never leave controller

### Network Security
1. **Anycast**: Multiple sites, DDoS mitigation
2. **BGP Security**: Route filtering, prefix validation
3. **DNS Security**: DNSSEC, query rate limiting, EDNS buffer limits

## Observability

### Metrics (Prometheus)
**Controller**:
- API request rate/latency
- Zone count, update frequency
- Backend storage operations
- DNSSEC signing operations

**Agent**:
- Zone sync status, staleness
- Health check results (5 layers)
- BGP route status
- DNS query metrics (via DNSTap)

### Logging (Structured)
**Controller**:
- API audit logs
- Zone updates
- DNSSEC operations
- Backend errors

**Agent**:
- Zone sync events
- Health state transitions
- BGP route changes
- DNS queries (sampled)

### Tracing (Optional)
- OpenTelemetry support
- Request ID propagation
- Cross-component correlation

## Operational Workflows

### Zone Update Flow
```
1. User creates/updates zone via API
2. Controller validates and stores zone
3. Controller signs zone with DNSSEC
4. Controller generates signed artifact
5. Agents poll controller (30s interval)
6. Agents fetch if ETag changed
7. Agents verify checksum
8. Agents write zone atomically
9. Agents reload NSD
10. Agents verify health
11. If healthy, BGP routes stay up
```

### Failure Scenarios

**Controller Failure**:
- Agents continue serving (stale zones acceptable)
- Sync marked as stale after 5 minutes
- BGP routes stay up (agents autonomous)

**NSD Crash**:
- Health checks detect failure
- State machine waits for 3 consecutive failures
- BGP routes withdrawn
- Auto-recovery when NSD restarts

**Network Partition**:
- Agents can't reach controller
- Serve stale zones (marked in logs)
- BGP routes stay up (local DNS works)

**DNSSEC Key Rotation**:
- Generate new KSK/ZSK
- Publish DNSKEY records (old + new)
- Wait TTL + propagation time
- Update DS records at parent
- Remove old keys

## Performance Characteristics

### Controller
- **API Latency**: <50ms (p95) for zone CRUD
- **Signing Latency**: ~100ms per zone (ECDSA P-256)
- **Throughput**: 1000+ zones (limited by backend)
- **Backend**: SQLite (1k+ zones), PostgreSQL (10k+ zones), MySQL (10k+ zones), Git (100s zones), etcd (1k+ zones)

### Agent
- **Sync Latency**: 30s default (configurable)
- **Reload Time**: <1s for NSD, <2s for Unbound
- **BGP Convergence**: 30s (debounce) + network propagation
- **Query Capacity**: 50k+ QPS per agent (NSD limit)

### Scaling
- **Horizontal**: Add agents (no controller changes)
- **Geographic**: Deploy agents globally (anycast)
- **Backend**: SQLite by default; PostgreSQL/MySQL for 10k+ zones; Git for <100 zones

## Technology Stack

**Languages**: Go 1.21+

**Dependencies**:
- `miekg/dns`: DNS protocol library
- `gin-gonic/gin`: HTTP framework
- `modernc.org/sqlite`: SQLite backend (pure Go, no CGO)
- `github.com/lib/pq`: PostgreSQL backend
- `go-git/go-git`: Git backend
- `go.etcd.io/etcd/client/v3`: etcd backend
- `go.uber.org/zap`: Structured logging
- `github.com/dnstap/golang-dnstap`: DNSTap protocol

**External Services**:
- NSD (authoritative DNS)
- Unbound (recursive DNS)
- BIRD (BGP daemon)
- Prometheus (metrics)
- SQLite/PostgreSQL/MySQL/etcd/Git (storage)

## Future Enhancements

1. **Push-based sync**: WebSocket or gRPC streaming
2. **Multi-controller**: Active-active with etcd coordination
3. **DNS-over-HTTPS/TLS**: DoH/DoT support
4. **Advanced RBAC**: Per-zone permissions
5. **Geo-steering**: DNS responses based on client location
6. **Query analytics**: Machine learning for anomaly detection
