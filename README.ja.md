# arca-dns

[![Tests](https://github.com/akam1o/arca-dns/actions/workflows/test.yml/badge.svg)](https://github.com/akam1o/arca-dns/actions/workflows/test.yml)
[![Lint](https://github.com/akam1o/arca-dns/actions/workflows/lint.yml/badge.svg)](https://github.com/akam1o/arca-dns/actions/workflows/lint.yml)
[![Build](https://github.com/akam1o/arca-dns/actions/workflows/build.yml/badge.svg)](https://github.com/akam1o/arca-dns/actions/workflows/build.yml)

[English](README.md) | 日本語

arca-dns は、BGP Anycast + ECMP とコントロール/データプレーン分離アーキテクチャを採用した、高可用・スケーラブルな権威 DNS システムです。

## 概要

arca-dns は、大規模な DNS デプロイメント向けに以下の機能を提供します。

- **分割アーキテクチャ**: コントロールプレーン（管理/署名）とデータプレーン（配布/ルーティング）を分離
- **BGP Anycast + ECMP**: 等コストマルチパス（ECMP）による水平スケーリング
- **DNSSEC**: 中央署名と自動鍵管理
- **差し替え可能なバックエンド**: ゾーン格納に SQLite（既定）/ PostgreSQL / MySQL / Git / etcd を利用可能
- **高性能**: 高スループットな運用を想定
- **可観測性**: DNSTap のバイナリログと Prometheus メトリクス

## アーキテクチャ

### コントロールプレーン: `arca-dns-controller`
- ゾーン管理用 REST API（JSON および生 BIND 形式）
- 中央 DNSSEC 署名（KSK/ZSK 管理）
- 差し替え可能なストレージバックエンド（SQLite / PostgreSQL / MySQL / Git / etcd）
- ゾーンのバージョニングとアーティファクト配布

### データプレーン: `arca-dns-agent`
- コントローラからのゾーン同期
- プラグインインターフェイスによる DNS サーバーオーケストレーション（NSD / Unbound / BIRD）
- ヘルスチェック付き BIRD による BGP ルート制御
- DNSTap ロギングと Prometheus メトリクス
- 自動フェイルオーバーと復旧

## クイックスタート

本プロジェクトは、コントロール/データプレーンを分離して運用します。
- **コントロールプレーン（controller）**: Kubernetes / Docker Compose / パッケージ
- **データプレーン（agent）**: エッジノード向けパッケージ（推奨）

## デプロイ

### コントロールプレーン（Controller）

コントローラは標準的な HTTP API サービスです。TLS は通常、ingress/reverse proxy 側で終端します。

**Kubernetes（推奨バックエンド: etcd）**:
- マニフェストは `deployments/kubernetes/controller/` 配下（base + overlays）にあります。
- 適用:
  - `kubectl apply -k deployments/kubernetes/controller/base`（外部/HA 構成の etcd）
  - `kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd`（デモ用途のみ; 単一ノード etcd を同梱）
- マニフェスト内の置き換え:
  - `deployments/kubernetes/controller/base/controller-secret.yaml`（`dnssec-master-key-b64`）
  - `deployments/kubernetes/controller/base/controller.yaml`（API キー、etcd エンドポイントなど）
  - （任意）`deployments/kubernetes/controller/examples/ingress.yaml`（ingress host/class; TLS は ingress で終端）

**Docker Compose（Controller + MySQL 例）**:
- 例の compose ファイル: `deployments/compose/controller-mysql/docker-compose.yaml`
- 起動:
  - `docker compose -f deployments/compose/controller-mysql/docker-compose.yaml --project-directory . up -d`

**DEB/RPM パッケージ**:
- パッケージング資産は `packaging/` 配下にあり、`.goreleaser.yaml` でビルドします。
- パッケージのビルド/インストールは `docs/packaging.ja.md`、運用セットアップは `docs/deployment.ja.md` を参照してください。

### データプレーン（Agent）

エージェントはホスト上の NSD/Unbound/BIRD を制御する設計で、通常はエッジノード/VM 上にデプロイします（Kubernetes ではありません）。

**DEB/RPM パッケージ（推奨）**:
1. ランタイム依存をインストール: NSD / Unbound / BIRD（Debian/Ubuntu は bird2）。
2. `arca-dns` パッケージ（agent + controller バイナリ同梱）をインストール。
3. `/etc/arca-dns/agent.yaml` を設定（`configs/agent.example.yaml` をベースにする）。
4. サービス起動: `systemctl enable --now arca-dns-agent`

運用（day-2）については `docs/deployment.ja.md` と `docs/operations.ja.md` を参照してください。

## 開発

### 開発ツールのインストール

```bash
make install-tools
```

### Makefile ターゲット

```bash
make help          # 利用可能なターゲットを表示
make install-tools # 開発ツールをインストール（golangci-lint）
make deps          # 依存関係を取得（go mod download/tidy）
make build         # controller + agent バイナリをビルド
make test          # テスト実行（-race + coverage.out）
make test-coverage # coverage.html を生成
make lint          # Lint 実行
make fmt           # フォーマット
make vet           # go vet 実行
make run-controller# ビルドして controller を実行（serve）
make run-agent     # ビルドして agent を実行（daemon）
make docker-build  # Docker イメージをビルド
make clean         # ビルド成果物を削除
```

### パッケージング（DEB/RPM）

`docs/packaging.ja.md` を参照してください。

### テストの実行

```bash
make test
```

### Lint の実行

```bash
make lint
```

### カバレッジ

```bash
make test-coverage
```

## 設定

`configs/controller.example.yaml` と `configs/agent.example.yaml`、および `docs/deployment.ja.md` / `docs/operations.ja.md` を参照してください。

### Controller 設定例

```yaml
api:
  listen: "0.0.0.0:8080"
  # TLS は通常 reverse proxy / ingress で終端します。

backend:
  type: "sqlite"  # 選択肢: sqlite, postgres, mysql, git, etcd, memory

dnssec:
  enabled: true
  algorithm: 13  # ECDSA-P256
  key_directory: "/var/lib/arca-dns/keys"
```

### Agent 設定例

```yaml
controller:
  url: "http://localhost:8080"
  sync_interval: "30s"

nsd:
  config_path: "/etc/nsd/nsd.conf"
  zone_directory: "/var/lib/nsd/zones"

unbound:
  config_path: "/etc/unbound/unbound.conf"
  edns_buffer_size: 1232  # ECMP によるフラグメントを抑制

bird:
  socket_path: "/var/run/bird/bird.ctl"
  anycast_prefixes:
    - "203.0.113.53/32"

health:
  check_interval: "10s"
  failure_threshold: 3
  recovery_threshold: 5
  nsd_server: "127.0.0.1:5353"
  unbound_server: "127.0.0.1:53"
```

### ローカルでのビルド/実行（dev）

前提:
- Go（`go.mod` 参照）

ビルド:
```bash
make build
```

controller の起動:
```bash
./bin/arca-dns-controller serve --config configs/controller.example.yaml
```

agent の起動（設定で有効化する場合、ホストに NSD/Unbound/BIRD のインストールが必要です）:
```bash
./bin/arca-dns-agent daemon --config configs/agent.example.yaml
```

## API ドキュメント

API ドキュメント（OpenAPI）: [api/openapi.yaml](api/openapi.yaml)  
コントリビューションガイド: [docs/contributing.ja.md](docs/contributing.ja.md)

### ゾーン管理の例

**ゾーンの作成（JSON）**:
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

**ゾーンの作成（Raw BIND）**:
```bash
curl -X POST http://localhost:8080/api/v1/zones/raw \
  -H "Content-Type: text/plain" \
  -H "X-API-Key: your-api-key" \
  --data-binary @example.com.zone
```

**レコードを 1 件追加（ETag / If-Match による更新）**:

この API には専用の `/records` エンドポイントはありません。`PUT /api/v1/zones/:name` でゾーンの JSON 全体を更新します。

```bash
BASE="http://localhost:8080/api/v1"
API_KEY="your-api-key" # 認証を有効にしている場合のみ

zone_json="$(curl -s "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}")"
etag="$(curl -sI "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

updated="$(printf '%s' "${zone_json}" | jq '.records += [{"name":"www","type":"A","ttl":300,"value":"203.0.113.2"}]')"

curl -i -X PUT "${BASE}/zones/example.com." \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  --data-binary "${updated}"
```

**複数レコードをまとめて追加**:

```bash
updated="$(printf '%s' "${zone_json}" | jq '.records += [
  {"name":"www","type":"A","ttl":300,"value":"203.0.113.2"},
  {"name":"api","type":"AAAA","ttl":300,"value":"2001:db8::1"},
  {"name":"@","type":"MX","ttl":3600,"value":"10 mail.example.com."}
]')"

curl -i -X PUT "${BASE}/zones/example.com." \
  -H "X-API-Key: ${API_KEY}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  --data-binary "${updated}"
```

レコード値の形式など、より詳しい例は `docs/api.ja.md` を参照してください。

## プロジェクト構成

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

## ドキュメント

- [アーキテクチャ](docs/architecture.ja.md)
- [デプロイガイド](docs/deployment.ja.md)
- [API リファレンス](docs/api.ja.md)
- [運用ガイド](docs/operations.ja.md)
- [DNSSEC 管理](docs/dnssec.ja.md)
- [パッケージング](docs/packaging.ja.md)

## コントリビュート

コントリビューション歓迎です！詳細は [docs/contributing.md](docs/contributing.md) を参照してください。

## 連絡先

問い合わせは [GitHub Issues](https://github.com/akam1o/arca-dns/issues) にて受け付けています。セキュリティ報告は [GitHub Security Advisories](https://github.com/akam1o/arca-dns/security/advisories) を利用してください。

## ライセンス

Apache License 2.0

## ロードマップ

ロードマップは GitHub の issue / milestones で管理しています。

## サポート

質問や不具合報告は、[GitHub issue tracker](https://github.com/akam1o/arca-dns/issues) を利用してください。
