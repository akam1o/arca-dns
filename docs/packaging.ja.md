# Packaging（DEB/RPM）

[English](packaging.md) | 日本語

arca-dns は以下向けに DEB / RPM パッケージをビルドできます。
- EL9（RPM）
- Debian（DEB）
- Ubuntu（DEB）

このリポジトリは **GoReleaser + nfpm** を用いて、Linux `amd64` / `arm64` 向けのパッケージを生成します。

## 前提条件

- Go ツールチェーン
- ローカルに GoReleaser をインストール
  - https://goreleaser.com/install/

## ローカルでパッケージをビルド

リポジトリのルートから実行します。

```bash
goreleaser release --snapshot --clean
```

成果物は `dist/` 配下に出力されます。
- `*.deb`
- `*.rpm`

## インストールされるファイル

- バイナリ:
  - `/usr/bin/arca-dns-controller`
  - `/usr/bin/arca-dns-agent`
- 設定:
  - `/etc/arca-dns/controller.yaml`
  - `/etc/arca-dns/agent.yaml`
- systemd ユニット:
  - `/usr/lib/systemd/system/arca-dns-controller.service`
  - `/usr/lib/systemd/system/arca-dns-agent.service`
- tmpfiles による state/log ディレクトリ:
  - `/var/lib/arca-dns/{keys,artifacts}`
  - `/var/log/arca-dns`

## 実行時依存（ランタイム）

agent ノードでは、ホスト側に以下がインストールされている想定です。

- Debian/Ubuntu（DEB）: `bird2`, `nsd`, `unbound`
- EL9（RPM）: `bird`, `nsd`, `unbound`

## サービスを有効化

```bash
sudo systemctl enable --now arca-dns-controller
sudo systemctl enable --now arca-dns-agent
```

