# arca-dns Deployment Guide

## Overview

arca-dns consists of:
- **Controller** (`arca-dns-controller`): REST API + DNSSEC signing + artifact distribution
- **Agent** (`arca-dns-agent`): syncs signed zones and controls NSD/Unbound/BIRD on edge nodes

Recommended production topology:
- controller runs centrally (VM/metal or Kubernetes)
- agents run on edge nodes (VM/metal) where BGP adjacencies terminate

## Prerequisites

### Controller
- One backend: `memory` (dev), `mysql`, `git`, or `etcd`
- Storage: writable `storage.artifact_directory` and `storage.key_directory`
- (If `dnssec.enabled: true`) DNSSEC master key configured (see below)

### Agent (edge node)
- NSD, Unbound, BIRD 2.x installed and configured on the node
  - Debian/Ubuntu: package name is typically `bird2`
  - EL/RHEL: package name is typically `bird`
- BGP connectivity to upstream routers
- DNS ports 53/TCP+UDP exposed from the node

### Network
- Controller API: `:8080` by default
- Agent metrics: `:9090` by default

## DEB/RPM setup (recommended for agents)

### 1) Install packages

Install runtime deps and arca-dns:
- Debian/Ubuntu: `bird2`, `nsd`, `unbound`, `arca-dns`
- EL9/RHEL: `bird`, `nsd`, `unbound`, `arca-dns`

### 2) Configure controller

Edit `/etc/arca-dns/controller.yaml` (installed from `configs/controller.example.yaml`).

#### API auth

If `api.auth.enabled: true`, set hashed API keys:

```bash
echo -n 'your-api-key' | sha256sum
```

Then set e.g. `sha256:<hex>` in `api.auth.api_keys`.

#### DNSSEC master key

If `dnssec.enabled: true`, the controller encrypts DNSSEC private keys at rest with a 32-byte AES-256 master key.

Load priority:
1) `ARCA_DNS_DNSSEC_MASTER_KEY_B64` (base64; must decode to 32 bytes)
2) `storage.key_directory/_masterkey` (base64; must decode to 32 bytes)
3) auto-generate (only if `dnssec.master_key_auto_generate: true`)

Example (env var):

```bash
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="$(openssl rand -base64 32)"
```

### 3) Configure agent

Edit `/etc/arca-dns/agent.yaml` (installed from `configs/agent.example.yaml`):
- set `controller.url` to your controller (e.g. `https://controller.example.com:8080`)
- set `controller.api_key` to the *raw* API key (not hashed)
- enable and configure `nsd`, `unbound`, and `bird` sections for your node

### 4) Enable systemd services

```bash
sudo systemctl enable --now arca-dns-controller
sudo systemctl enable --now arca-dns-agent

sudo systemctl status arca-dns-controller
sudo systemctl status arca-dns-agent
```

## Docker Compose

The published images are built from `deployments/docker/Dockerfile.controller` and `deployments/docker/Dockerfile.agent`.
The controller works well in containers; the agent usually runs on the node OS (because it controls NSD/Unbound/BIRD).

### Controller + MySQL

```yaml
# docker-compose.yml (see also `deployments/compose/controller-mysql/docker-compose.yaml`)
services:
  mysql:
    image: mysql:8.0
    environment:
      MYSQL_ROOT_PASSWORD: rootpassword
      MYSQL_DATABASE: arca_dns
      MYSQL_USER: dns_user
      MYSQL_PASSWORD: dnspassword
    volumes:
      - mysql_data:/var/lib/mysql

  controller:
    image: ghcr.io/akam1o/arca-dns-controller:latest
    ports:
      - "8080:8080"
    environment:
      # base64(32 bytes); required if dnssec.enabled: true
      ARCA_DNS_DNSSEC_MASTER_KEY_B64: "REPLACE_WITH_BASE64"
    volumes:
      - ./configs/controller.example.yaml:/etc/arca-dns/controller.yaml:ro
      - controller_data:/var/lib/arca-dns
    depends_on:
      - mysql
    command: ["serve", "--config", "/etc/arca-dns/controller.yaml"]

volumes:
  mysql_data: {}
  controller_data: {}
```

Then run agents on nodes and set `controller.url` to the compose host.

## Kubernetes

### Controller (Deployment + Service)

Deploy the controller as a standard `Deployment` + `Service`:
- `ConfigMap` for `controller.yaml`
- `Secret` for `ARCA_DNS_DNSSEC_MASTER_KEY_B64`
- (Recommended) PVC for `/var/lib/arca-dns` if you use DNSSEC key storage/artifacts
- For Kubernetes, `etcd` is a good default backend (works well with a single controller instance).

Kustomize entrypoints:
- Base (external/HA etcd): `kubectl apply -k deployments/kubernetes/controller/base`
- Demo-only (bundled single-node etcd): `kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd`

Ingress example (TLS terminated at ingress): `deployments/kubernetes/controller/examples/ingress.yaml`

Example (abridged):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: arca-dns-controller
spec:
  replicas: 1
  selector:
    matchLabels:
      app: arca-dns-controller
  template:
    metadata:
      labels:
        app: arca-dns-controller
    spec:
      containers:
        - name: controller
          image: ghcr.io/akam1o/arca-dns-controller:latest
          args: ["serve", "--config", "/etc/arca-dns/controller.yaml"]
          ports:
            - containerPort: 8080
              name: http
          env:
            - name: ARCA_DNS_DNSSEC_MASTER_KEY_B64
              valueFrom:
                secretKeyRef:
                  name: arca-dns-secrets
                  key: dnssec-master-key-b64
          volumeMounts:
            - name: config
              mountPath: /etc/arca-dns/controller.yaml
              subPath: controller.yaml
      volumes:
        - name: config
          configMap:
            name: arca-dns-controller-config
```

### Agent deployment note

The agent is designed to control NSD/Unbound/BIRD on edge nodes.
For Kubernetes-based edge deployments, you typically still run agents on the nodes (outside the cluster),
or you build a custom Pod design/image that provides NSD/Unbound/BIRD in a way the agent can control.

## Container Images

Published registries:
- GHCR: `ghcr.io/akam1o/arca-dns-controller`, `ghcr.io/akam1o/arca-dns-agent`
- Docker Hub: `docker.io/akam1o/arca-dns-controller`, `docker.io/akam1o/arca-dns-agent`

## Next Steps

- [Operations Guide](operations.md): Day-2 operations
- [API Reference](api.md): API documentation
- [Architecture](architecture.md): System design
