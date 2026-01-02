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
