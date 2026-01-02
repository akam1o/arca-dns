# Packaging (DEB/RPM)

arca-dns supports building DEB and RPM packages for:
- EL9 (RPM)
- Debian (DEB)
- Ubuntu (DEB)

This repo uses **GoReleaser + nfpm** to generate packages for Linux `amd64` and `arm64`.

## Prerequisites

- Go toolchain
- GoReleaser installed locally
  - https://goreleaser.com/install/

## Build packages locally

From the repository root:

```bash
goreleaser release --snapshot --clean
```

Artifacts will be placed under `dist/`, including:
- `*.deb`
- `*.rpm`

## Installed files

- Binaries:
  - `/usr/bin/arca-dns-controller`
  - `/usr/bin/arca-dns-agent`
- Config:
  - `/etc/arca-dns/controller.yaml`
  - `/etc/arca-dns/agent.yaml`
- systemd units:
  - `/usr/lib/systemd/system/arca-dns-controller.service`
  - `/usr/lib/systemd/system/arca-dns-agent.service`
- State/log directories via tmpfiles:
  - `/var/lib/arca-dns/{keys,artifacts}`
  - `/var/log/arca-dns`

## Runtime dependencies

The agent node expects these to be installed on the host:

- Debian/Ubuntu (DEB): `bird2`, `nsd`, `unbound`
- EL9 (RPM): `bird`, `nsd`, `unbound`

## Enable services

```bash
sudo systemctl enable --now arca-dns-controller
sudo systemctl enable --now arca-dns-agent
```
