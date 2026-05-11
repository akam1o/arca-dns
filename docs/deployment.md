# arca-dns Deployment Guide

English | [日本語](deployment.ja.md)

## Overview

arca-dns is deployed as a split control plane and data plane.

- **Controller** (`arca-dns-controller`): REST API, zone management, DNSSEC signing, and signed zone distribution
- **Agent** (`arca-dns-agent`): syncs signed zones and controls NSD/Unbound/BIRD on edge nodes

Recommended production topology:

- run the controller centrally as one VM/process or one Kubernetes Deployment
- run agents on every edge node where DNS and BGP sessions terminate
- terminate controller TLS at an ingress, load balancer, or reverse proxy
- point agents at `https://<controller>/api/v1/*` and let them apply zone files locally

## Deployment Options

| Option | Best for | Notes |
| --- | --- | --- |
| DEB/RPM + systemd | agents, production VMs/bare metal | Best fit when the agent controls host NSD/Unbound/BIRD |
| Controller container | lightweight controller deployment | Images are distroless nonroot; make `/var/lib/arca-dns` writable |
| Docker Compose | local or single-host validation | `deployments/compose/controller-mysql/` runs controller + MySQL |
| Kubernetes | controller cluster deployment | Agents usually still run outside the cluster on edge nodes |

The agent container image contains only `arca-dns-agent` and defaults to sync-only mode: NSD/Unbound/BIRD/DNSTap integrations are disabled, zones are written under `/var/lib/arca-dns/zones`, and the status listener binds to `0.0.0.0:9090`. If you enable host integrations in a container, mount the matching host binaries, sockets, configs, and writable data paths. For production edge nodes, DEB/RPM + systemd is usually the better fit.

## Common Prerequisites

### Controller

- Choose one backend: `sqlite` (default), `postgres`, `mysql`, `git`, or `etcd`
- Use SQLite with `:memory:` only for disposable local validation
- Ensure `storage.artifact_directory` and `storage.key_directory` are writable
- If DNSSEC is enabled, ensure `dnssec.key_directory` is writable and a DNSSEC master key is configured
- If API auth is enabled, configure at least one API key hash

### Agent

- Install NSD, Unbound, and BIRD 2.x on each edge node
  - Debian/Ubuntu: the BIRD package is typically `bird2`
  - EL/RHEL: the BIRD package is typically `bird`
- Ensure `nsd.zone_directory` is writable by the agent
- Include the agent-managed NSD zone file from `nsd.conf`:
  `include: "/etc/nsd/arca-dns-zones.conf"`
- Ensure the agent can run NSD/Unbound/BIRD control and reload commands
- Expose DNS 53/TCP+UDP from the edge node
- Prepare BGP neighbor reachability, local ASN, neighbor ASN, and source IP

### Default Ports

| Component | Port | Purpose |
| --- | --- | --- |
| controller | `8080` | management API, health, readiness, status |
| controller | `9053` | Prometheus metrics, compatibility health/readiness/status aliases |
| agent | `9090` | status, health, readiness, metrics |
| DNS | `53/tcp`, `53/udp` | edge DNS service |

## Secrets and Auth

### API Key

The controller default is `api.auth.enabled: true`. When auth is enabled, `api.auth.api_keys` must contain at least one `sha256:<64 hex>` hash.
The controller observability listener is unauthenticated and binds to `127.0.0.1:9053` by default. Bind it to a remote address only behind network controls or an authenticated proxy.

```bash
ADMIN_API_KEY="$(openssl rand -hex 32)"
ADMIN_API_KEY_HASH="sha256:$(printf '%s' "$ADMIN_API_KEY" | sha256sum | awk '{print $1}')"
AGENT_API_KEY="$(openssl rand -hex 32)"
AGENT_API_KEY_HASH="sha256:$(printf '%s' "$AGENT_API_KEY" | sha256sum | awk '{print $1}')"
SHARED_SIGNATURE_KEY="$(openssl rand -base64 32)"

printf 'raw admin api key: %s\n' "$ADMIN_API_KEY"
printf 'admin hash: %s\n' "$ADMIN_API_KEY_HASH"
printf 'raw agent api key: %s\n' "$AGENT_API_KEY"
printf 'agent hash: %s\n' "$AGENT_API_KEY_HASH"
```

Set the hash on the controller:

```yaml
api:
  # Generate with: openssl rand -base64 32
  artifact_signature_key: "REPLACE_WITH_SHARED_SIGNATURE_KEY"
  auth:
    enabled: true
    api_keys:
      admin: "sha256:REPLACE_WITH_SHA256_HEX"
      agent: "sha256:REPLACE_WITH_AGENT_SHA256_HEX"
    api_key_roles:
      admin: "admin"
      agent: "agent"
```

Set the raw API key on agents:

```yaml
controller:
  url: "https://controller.example.com"
  api_key: "REPLACE_WITH_RAW_AGENT_API_KEY"

sync:
  verify_signatures: true
  # Shared HMAC secret; must match api.artifact_signature_key.
  controller_signature_key: "REPLACE_WITH_SHARED_SIGNATURE_KEY"
```

For env-only controller deployments, API keys can be supplied as:

```bash
export ARCA_DNS_API_AUTH_API_KEYS_ADMIN="$ADMIN_API_KEY_HASH"
export ARCA_DNS_API_AUTH_API_KEYS_AGENT="$AGENT_API_KEY_HASH"
export ARCA_DNS_API_AUTH_API_KEY_ROLES_AGENT="agent"
export ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY="$SHARED_SIGNATURE_KEY"
```

The suffix becomes the lowercased principal name.

### DNSSEC Master Key

When `dnssec.enabled: true`, the controller encrypts DNSSEC private keys at rest with a 32-byte AES-256 master key.

Load priority:

1. `ARCA_DNS_DNSSEC_MASTER_KEY_B64`
2. `dnssec.key_directory/_masterkey`
3. `/etc/arca-dns/master.key`
4. auto-generate, only if `dnssec.master_key_auto_generate: true`

For production, avoid auto-generation and manage the key through an environment secret, Kubernetes Secret, or a root-only file.

```bash
openssl rand -base64 32 | sudo tee /etc/arca-dns/master.key >/dev/null
sudo chmod 600 /etc/arca-dns/master.key
```

When both `storage.key_directory` and `dnssec.key_directory` are set, they must point to the same path, such as `/var/lib/arca-dns/keys`. `storage.key_directory` remains available as a compatibility alias for the DNSSEC key directory.

## Backend Preparation

### SQLite

SQLite is the default backend and creates its schema automatically on first start. It is the simplest option for small single-controller deployments.

For production, use an absolute path under persistent storage instead of a relative DSN:

```yaml
backend:
  type: "sqlite"
  sqlite:
    dsn: "file:/var/lib/arca-dns/arca-dns.db"
```

### MySQL

The MySQL backend does not apply schema migrations during controller startup. Apply the SQL schema before starting the controller.

The schema files live in the repository under `migrations/`. DEB/RPM packages install the same files under `/usr/share/arca-dns/migrations/`.

```bash
mysql -h mysql.example.com -u dns_user -p arca_dns \
  < migrations/mysql/000001_initial_schema.up.sql
# Package install path:
# mysql -h mysql.example.com -u dns_user -p arca_dns \
#   < /usr/share/arca-dns/migrations/mysql/000001_initial_schema.up.sql
```

Example config:

```yaml
backend:
  type: "mysql"
  mysql:
    dsn: "dns_user:dnspassword@tcp(mysql.example.com:3306)/arca_dns?parseTime=true"
```

### PostgreSQL

The PostgreSQL backend also requires schema creation before controller startup.

The schema files live in the repository under `migrations/`. DEB/RPM packages install the same files under `/usr/share/arca-dns/migrations/`.

```bash
psql "postgres://user:pass@postgres.example.com:5432/arca_dns?sslmode=require" \
  -f migrations/postgres/000001_initial_schema.up.sql
# Package install path:
# psql "postgres://user:pass@postgres.example.com:5432/arca_dns?sslmode=require" \
#   -f /usr/share/arca-dns/migrations/postgres/000001_initial_schema.up.sql
```

Example config:

```yaml
backend:
  type: "postgres"
  postgres:
    dsn: "postgres://user:pass@postgres.example.com:5432/arca_dns?sslmode=require"
```

### etcd

etcd is a good fit for Kubernetes controller deployments. Use an external highly available etcd cluster for production rather than the demo single-node overlay.

```yaml
backend:
  type: "etcd"
  etcd:
    endpoints:
      - "https://etcd-1.example.com:2379"
      - "https://etcd-2.example.com:2379"
      - "https://etcd-3.example.com:2379"
    prefix: "/arca-dns"
    dial_timeout: "5s"
    request_timeout: "10s"
```

### Git

The Git backend stores zones in a Git repository. It is useful for auditability, but SQL or etcd backends are usually better for high zone counts or high update rates.

```yaml
backend:
  type: "git"
  git:
    repository_path: "/var/lib/arca-dns/git"
    remote_url: "git@example.com:infra/arca-dns-zones.git"
    branch: "main"
    author: "arca-dns-controller"
    email: "noreply@arca-dns"
    auto_push: false
    auto_pull: false
    pull_interval: "1m"
```

## DEB/RPM + systemd

### 1. Install Packages

```bash
# Debian/Ubuntu
sudo apt-get install bird2 nsd unbound arca-dns

# EL/RHEL family
sudo dnf install bird nsd unbound arca-dns
```

The package installs:

- `/usr/bin/arca-dns-controller`
- `/usr/bin/arca-dns-agent`
- `/etc/arca-dns/controller.yaml`
- `/etc/arca-dns/agent.yaml`
- `/usr/lib/systemd/system/arca-dns-controller.service`
- `/usr/lib/systemd/system/arca-dns-agent.service`
- `/usr/lib/sysusers.d/arca-dns.conf`

`tmpfiles.d` creates:

- `/etc/arca-dns`
- `/var/lib/arca-dns`
- `/var/lib/arca-dns/keys`
- `/var/lib/arca-dns/artifacts`
- `/var/log/arca-dns`

### 2. Configure the Controller

Edit `/etc/arca-dns/controller.yaml`.

Minimum production checks:

- replace the `api.auth.api_keys` placeholder with a real `sha256:<64 hex>` value
- choose `backend.type` and configure the selected backend
- if DNSSEC is enabled, configure `/etc/arca-dns/master.key` or `ARCA_DNS_DNSSEC_MASTER_KEY_B64`
- verify `storage.*` and `dnssec.key_directory` are writable by the service

The packaged controller runs as the `arca-dns` service user. The agent keeps root for NSD/Unbound/BIRD control, but its systemd unit is sandboxed and only the configured DNS, BIRD, state, log, and runtime paths are writable. If you customize those paths, add matching permissions or a systemd drop-in.

### 3. Configure the Agent

Edit `/etc/arca-dns/agent.yaml`.

Set at least:

- `controller.url`: controller URL
- `controller.api_key`: raw API key
- `nsd.enabled`, `nsd.zone_directory`, `nsd.control_path`
- `unbound.enabled`, `unbound.control_path`
- `bird.enabled`, `bird.protocols`, `bird.socket_path`
- `health.nsd_server`, `health.unbound_server`, `health.test_zone`, `health.test_record`

When `health.test_record` is relative, set `health.test_zone` to the served
zone, for example `test_zone: "example.com."` and `test_record: "www"`.
Use a trailing dot on `health.test_record` only when you want to query an
absolute DNS name directly.

If DNSTap is enabled, keep `dnstap.socket_mode` at `0660` and either set
`dnstap.socket_group` to a shared group that contains the DNS daemon user
(`nsd`, `unbound`, or your local equivalent), or rely on the packaged agent's
primary group. The packaged agent runs with primary group `arca-dns`, so adding
the DNS daemon user to `arca-dns` is the default packaged layout.

If the agent generates BIRD config, include the generated file from the main `bird.conf`:

```bird
include "/etc/bird/arca-dns-anycast.conf";
```

Agent BIRD example:

```yaml
bird:
  enabled: true
  socket_path: "/var/run/bird/bird.ctl"
  protocols:
    - name: "anycast_1"
      neighbor_address: "10.0.0.1"
      neighbor_asn: 64512
  anycast_prefixes:
    - "192.0.2.53/32"
    - "2001:db8::53/128"
  config:
    enabled: true
    path: "/etc/bird/arca-dns-anycast.conf"
    router_id: "10.0.0.5"
    local_as: 65001
    source_ip: "10.0.0.5"
```

### 4. Start Services

You do not need to start both services on every host. Usually controller hosts run the controller service and edge nodes run the agent service.

```bash
sudo systemctl enable --now arca-dns-controller
sudo systemctl status arca-dns-controller

sudo systemctl enable --now arca-dns-agent
sudo systemctl status arca-dns-agent
```

Logs:

```bash
journalctl -u arca-dns-controller -f
journalctl -u arca-dns-agent -f
```

## Docker Compose

The Compose example is in `deployments/compose/controller-mysql/docker-compose.yaml`. It is a controller + MySQL validation setup.

Prepare secrets first:

```bash
export ARCA_DNS_API_KEY="$(openssl rand -hex 32)"
export ARCA_DNS_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_API_KEY" | sha256sum | awk '{print $1}')"
export ARCA_DNS_AGENT_API_KEY="$(openssl rand -hex 32)"
export ARCA_DNS_AGENT_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_AGENT_API_KEY" | sha256sum | awk '{print $1}')"
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="$(openssl rand -base64 32)"
export ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY="$(openssl rand -base64 32)"
```

Start:

```bash
docker compose \
  -f deployments/compose/controller-mysql/docker-compose.yaml \
  --project-directory . \
  up -d
```

The Compose example loads `migrations/mysql/000001_initial_schema.up.sql` during MySQL initialization. If a `mysql_data` volume already exists, MySQL will not rerun `/docker-entrypoint-initdb.d`. Recreate the volume when you need a clean schema:

```bash
docker compose \
  -f deployments/compose/controller-mysql/docker-compose.yaml \
  --project-directory . \
  down -v
```

Check the controller:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl -H "X-API-Key: $ARCA_DNS_API_KEY" http://localhost:8080/api/v1/zones
```

Agents normally run on edge node operating systems, where they can control NSD/Unbound/BIRD. Point `controller.url` at the Compose host.

## Kubernetes

The Kubernetes manifests are controller-focused. Agents normally run as systemd services on DNS/BGP edge nodes.

Kustomize entrypoints:

- Base with external/HA etcd: `deployments/kubernetes/controller/base`
- Demo with bundled single-node etcd: `deployments/kubernetes/controller/overlays/demo-etcd`

### 1. Replace the Secret

Replace `api-key-hash`, `agent-api-key-hash`, `dnssec-master-key-b64`, and `artifact-signature-key` in `deployments/kubernetes/controller/base/controller-secret.yaml`.

```bash
openssl rand -base64 32
```

### 2. Replace Controller Config

Edit `deployments/kubernetes/controller/base/controller.yaml`.

- `backend.etcd.endpoints`
- `backend.etcd.prefix`
- `storage.*`
- `dnssec.*`

The Deployment reads `api-key-hash` through `ARCA_DNS_API_AUTH_API_KEYS_ADMIN` and `agent-api-key-hash` through `ARCA_DNS_API_AUTH_API_KEYS_AGENT`, so the Secret values override the placeholder hashes in the ConfigMap. If you use the demo overlay, also replace or override its placeholder values before applying.

### 3. Check the PVC

`deployments/kubernetes/controller/base/controller-pvc.yaml` creates a `10Gi` `ReadWriteOnce` PVC. Adjust storage class and size for your cluster.

The controller Pod mounts `/var/lib/arca-dns` from the PVC and sets `fsGroup: 65532` so the distroless nonroot image can write key and artifact files.

### 4. Deploy

External/HA etcd:

```bash
kubectl apply -k deployments/kubernetes/controller/base
```

Demo single-node etcd:

```bash
kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd
```

### 5. Verify

```bash
kubectl get deploy,po,svc,pvc
kubectl logs deploy/arca-dns-controller
kubectl port-forward svc/arca-dns-controller 8080:8080 9053:9053
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

Ingress example: `deployments/kubernetes/controller/examples/ingress.yaml`. Terminate TLS at the ingress controller or external load balancer.

## Agent Deployment Details

The agent uses these controller APIs:

- `GET /api/v1/zones?fields=summary`
- `GET /api/v1/zones/:name/signed`

When controller API auth is enabled, the agent sends `controller.api_key` in the `X-API-Key` header. Use an API key with the `agent` role; it is limited to zone summary listing and signed artifact reads.

Zone sync does the following:

- fetches the controller zone list
- uses ETags to fetch only changed zones
- verifies checksum headers
- writes atomically under `nsd.zone_directory`
- keeps old files as `*.backup.<timestamp>`
- runs NSD/Unbound reload hooks
- removes local zones that disappeared from the controller

Agent HTTP endpoints:

| Endpoint | Purpose |
| --- | --- |
| `GET /health` | liveness |
| `GET /ready` | first sync has succeeded and sync is not stale |
| `GET /status` | sync state, health, BGP announce state |
| `GET /metrics` | Prometheus metrics |

Controller health/readiness/status endpoints listen on the API address
(`0.0.0.0:8080` in the provided deployment examples). Prometheus metrics
listen on the separate `observability.listen` address. The built-in default is
`127.0.0.1:9053`; the Kubernetes examples use `0.0.0.0:9053` for Service
scraping and should be protected with cluster network controls.

By default the agent status server listens on `127.0.0.1:9090`. Set
`metrics.listen` to a remote address only when the endpoint is protected by
network controls or an authenticated proxy.

## Post-Deployment Checks

Controller:

```bash
curl http://controller:8080/health
curl http://controller:8080/ready
curl http://controller:8080/status
curl http://controller:9053/metrics
```

Agent:

```bash
curl http://localhost:9090/health
curl http://localhost:9090/ready
curl http://localhost:9090/status
curl http://localhost:9090/metrics
```

DNS:

```bash
dig @<agent-ip> example.com SOA +dnssec
dig @<agent-ip> example.com DNSKEY +dnssec
```

BIRD:

```bash
birdc show protocols
birdc show route
```

## Rollout and Backup

- Back up the backend before changing controller storage
- Use DB dumps for SQL backends, repository backups for Git, and snapshots for etcd
- Always back up the DNSSEC key directory and the master key together
- Roll agents gradually and watch `/ready`, `/status`, and BGP announce state
- Use `arca-dns-controller migrate` for supported backend migrations. The current migrate command targets `sqlite` (default), `postgres`, `mysql`, `git`, and `etcd`

## Troubleshooting

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| controller fails on `api.auth.api_keys` | placeholder hash or no API key configured | set a real `sha256:<64 hex>` value |
| controller fails on master key | DNSSEC enabled but no master key | set `ARCA_DNS_DNSSEC_MASTER_KEY_B64` or `/etc/arca-dns/master.key` |
| MySQL/PostgreSQL reports missing tables | SQL schema was not applied | apply `migrations/<backend>/000001_initial_schema.up.sql` before startup |
| container cannot write `/var/lib/arca-dns` | distroless nonroot UID cannot write the volume | make the volume writable by UID/GID `65532`; Kubernetes base already sets `fsGroup: 65532` |
| agent container cannot reload NSD/Unbound/BIRD | image does not include host DNS/BGP control tools | mount the required host binaries/sockets/configs or disable those integrations |
| agent `/ready` returns 503 | first sync has not completed or sync is stale | check controller URL/API key, zone list, and agent logs |
| BGP is not announced | health check failure, BIRD socket permission, or protocol name mismatch | check `curl :9090/status`, `birdc show protocols`, and agent logs |

## Next Steps

- [Operations Guide](operations.md): Day-2 operations
- [API Reference](api.md): API documentation
- [DNSSEC Management](dnssec.md): DNSSEC keys, DS records, rotation
- [Architecture](architecture.md): System design
