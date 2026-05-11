# Deployments

This directory contains deployment-related assets for arca-dns.

Primary targets:

- `deployments/compose/`: Docker Compose examples
- `deployments/kubernetes/`: Kubernetes manifests for the controller
- `deployments/docker/`: Dockerfiles used to build controller and agent images

See the full deployment guide:

- English: `docs/deployment.md`
- Japanese: `docs/deployment.ja.md`

## Important Notes

- The controller serves HTTP by default. Terminate TLS at an ingress, load balancer, or reverse proxy.
- The controller API listens on 8080 by default, including unauthenticated health/readiness/status endpoints; Prometheus metrics listen separately on 9053 and should stay on loopback or behind network controls.
- Controller and agent container images are based on distroless `nonroot`; mounted data directories must be writable by UID/GID `65532`.
- The agent container image defaults to sync-only mode: NSD/Unbound/BIRD/DNSTap integrations are disabled and zones are written under `/var/lib/arca-dns/zones`.
- Enable agent host integrations in containers only when mounting the required host binaries, sockets, configs, and writable data paths. For production edge nodes, DEB/RPM + systemd is usually the better fit.
- MySQL and PostgreSQL backends require schema creation before controller startup. SQLite creates its schema automatically.
- SQL schema files live in the repository under `migrations/`; DEB/RPM packages install them under `/usr/share/arca-dns/migrations/`.

## Docker Compose: Controller + MySQL

Example:

```bash
export ARCA_DNS_API_KEY="$(openssl rand -hex 32)"
export ARCA_DNS_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_API_KEY" | sha256sum | awk '{print $1}')"
export ARCA_DNS_AGENT_API_KEY="$(openssl rand -hex 32)"
export ARCA_DNS_AGENT_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_AGENT_API_KEY" | sha256sum | awk '{print $1}')"
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="$(openssl rand -base64 32)"
export ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY="$(openssl rand -base64 32)"

docker compose \
  -f deployments/compose/controller-mysql/docker-compose.yaml \
  --project-directory . \
  up -d
```

The MySQL service mounts `migrations/mysql/000001_initial_schema.up.sql` into `/docker-entrypoint-initdb.d`, so the schema is applied only when the `mysql_data` volume is first initialized. For a clean local reset:

```bash
docker compose \
  -f deployments/compose/controller-mysql/docker-compose.yaml \
  --project-directory . \
  down -v
```

## Kubernetes Controller

Kustomize entrypoints:

- Base with external/HA etcd: `kubectl apply -k deployments/kubernetes/controller/base`
- Demo-only bundled single-node etcd: `kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd`

Before applying, replace:

- `deployments/kubernetes/controller/base/controller-secret.yaml` (`api-key-hash`, `agent-api-key-hash`, `dnssec-master-key-b64`, `artifact-signature-key`)
- `deployments/kubernetes/controller/base/controller.yaml` (etcd endpoints, backend prefix)
- `deployments/kubernetes/controller/base/controller-pvc.yaml` storage class and size if needed
- `deployments/kubernetes/controller/overlays/demo-etcd/controller.yaml` API key hash if using the demo overlay

Ingress example:

- `deployments/kubernetes/controller/examples/ingress.yaml`
