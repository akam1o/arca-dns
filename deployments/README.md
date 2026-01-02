# Deployments

This directory contains deployment-related assets for arca-dns.

Primary targets:
- `deployments/compose/`: Docker Compose examples (controller-focused)
- `deployments/kubernetes/`: Kubernetes manifests (controller-focused)
- `deployments/docker/`: Dockerfiles used to build images

Notes:
- The agent controls NSD/Unbound/BIRD on the host, so it is typically deployed on nodes/VMs rather than as a Kubernetes workload.
- TLS is typically terminated by an ingress/reverse proxy; the controller serves HTTP by default.
- The Kubernetes example uses `etcd` as the controller backend.

## Kubernetes controller

Kustomize entrypoints:
- Base (external/HA etcd): `kubectl apply -k deployments/kubernetes/controller/base`
- Demo-only (bundled single-node etcd): `kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd`

You will typically replace:
- `deployments/kubernetes/controller/base/controller-secret.yaml` (`dnssec-master-key-b64`)
- `deployments/kubernetes/controller/base/controller.yaml` (API key hashes, etcd endpoints, backend prefix)
- Storage class / size in `deployments/kubernetes/controller/base/controller-pvc.yaml`

Ingress example (TLS terminated at ingress):
- `deployments/kubernetes/controller/examples/ingress.yaml`
