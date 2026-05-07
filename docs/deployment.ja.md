# arca-dns デプロイガイド

[English](deployment.md) | 日本語

## 概要

arca-dns は control plane と data plane を分けてデプロイします。

- **Controller**（`arca-dns-controller`）: REST API、ゾーン管理、DNSSEC 署名、署名済みゾーン配布
- **Agent**（`arca-dns-agent`）: 署名済みゾーンを同期し、エッジノード上の NSD/Unbound/BIRD を制御

推奨する本番トポロジ:

- controller は中枢で 1 台または 1 Pod 稼働させる
- agent は BGP ピアリングが終端する各エッジノードで稼働させる
- controller の TLS は ingress、ロードバランサ、またはリバースプロキシで終端する
- agent は controller の `https://<controller>/api/v1/*` に接続し、DNS ゾーンファイルをローカルに反映する

## デプロイ方式の選び方

| 方式 | 主な用途 | 備考 |
| --- | --- | --- |
| DEB/RPM + systemd | agent、本番 VM/ベアメタル | NSD/Unbound/BIRD をホスト上で制御しやすい |
| Controller コンテナ | controller の軽量運用 | image は distroless nonroot。`/var/lib/arca-dns` の書き込み権限に注意 |
| Docker Compose | ローカル検証、単一ホスト検証 | `deployments/compose/controller-mysql/` は controller + MySQL の例 |
| Kubernetes | controller のクラスタ運用 | agent は通常クラスタ外のエッジノードで動かす |

## 共通の前提条件

### Controller

- backend を 1 つ選ぶ: `sqlite`（既定）、`postgres`, `mysql`, `git`, `etcd`
- `memory` backend はテスト用途のみ。永続化されないため本番では使わない
- `storage.artifact_directory` と `storage.key_directory` が書き込み可能であること
- DNSSEC 有効時は `dnssec.key_directory` が書き込み可能で、DNSSEC マスターキーを設定済みであること
- API 認証を有効にする場合、少なくとも 1 つの API キーハッシュが必要

### Agent

- NSD、Unbound、BIRD 2.x がエッジノードにインストール済みであること
  - Debian/Ubuntu: BIRD パッケージ名は通常 `bird2`
  - EL/RHEL: BIRD パッケージ名は通常 `bird`
- `nsd.zone_directory` が agent から書き込み可能であること
- `nsd.conf` から agent 管理の NSD zone file を include すること:
  `include: "/etc/nsd/arca-dns-zones.conf"`
- NSD/Unbound/BIRD の reload/control コマンドを agent 実行ユーザーが実行できること
- DNS 53/TCP+UDP をエッジノードから公開できること
- BGP セッション用の到達性、local ASN、neighbor ASN、source IP が決まっていること

### 既定ポート

| Component | Port | 内容 |
| --- | --- | --- |
| controller | `8080` | API、health、readiness、metrics |
| agent | `9090` | status、health、readiness、metrics |
| DNS | `53/tcp`, `53/udp` | エッジノードの DNS サービス |

## シークレットと認証

### API キー

controller の既定は `api.auth.enabled: true` です。認証が有効な場合、`api.auth.api_keys` に `sha256:<64 hex>` 形式のハッシュが 1 つ以上必要です。

```bash
API_KEY="$(openssl rand -hex 32)"
API_KEY_HASH="sha256:$(printf '%s' "$API_KEY" | sha256sum | awk '{print $1}')"
SHARED_SIGNATURE_KEY="$(openssl rand -base64 32)"

printf 'raw api key: %s\n' "$API_KEY"
printf 'hash: %s\n' "$API_KEY_HASH"
```

controller にはハッシュを設定します。

```yaml
api:
  # 生成例: openssl rand -base64 32
  artifact_signature_key: "REPLACE_WITH_SHARED_SIGNATURE_KEY"
  auth:
    enabled: true
    api_keys:
      admin: "sha256:REPLACE_WITH_SHA256_HEX"
```

agent には生の API キーを設定します。

```yaml
controller:
  url: "https://controller.example.com"
  api_key: "REPLACE_WITH_RAW_API_KEY"

sync:
  verify_signatures: true
  # api.artifact_signature_key と同じ値にしてください。
  controller_public_key: "REPLACE_WITH_SHARED_SIGNATURE_KEY"
```

環境変数だけで controller の API キーを渡す場合は、次の形式を使えます。suffix は小文字化され、principal 名になります。

```bash
export ARCA_DNS_API_AUTH_API_KEYS_ADMIN="$API_KEY_HASH"
export ARCA_DNS_API_ARTIFACT_SIGNATURE_KEY="$SHARED_SIGNATURE_KEY"
```

### DNSSEC マスターキー

`dnssec.enabled: true` の場合、controller は DNSSEC 秘密鍵を 32 バイトの AES-256 マスターキーで at-rest 暗号化します。

読み込み優先順位:

1. `ARCA_DNS_DNSSEC_MASTER_KEY_B64`
2. `dnssec.key_directory/_masterkey`
3. `/etc/arca-dns/master.key`
4. 自動生成（`dnssec.master_key_auto_generate: true` の場合のみ）

本番では自動生成を避け、環境変数、Kubernetes Secret、または root のみ読めるファイルで管理してください。

```bash
openssl rand -base64 32 | sudo tee /etc/arca-dns/master.key >/dev/null
sudo chmod 600 /etc/arca-dns/master.key
```

`storage.key_directory` と `dnssec.key_directory` の両方を設定する場合は、同じディレクトリ（例: `/var/lib/arca-dns/keys`）を指定してください。`storage.key_directory` は DNSSEC key directory の互換 alias として残しています。

## Backend の準備

### SQLite

SQLite は既定 backend で、初回起動時にスキーマが自動作成されます。小規模環境や単一 controller では最も簡単です。

本番では DSN を相対パスのままにせず、永続ディレクトリ配下に置くことを推奨します。

```yaml
backend:
  type: "sqlite"
  sqlite:
    dsn: "file:/var/lib/arca-dns/arca-dns.db"
```

### MySQL

MySQL backend は controller 起動時にスキーマを自動投入しません。controller を起動する前に SQL を適用してください。

schema ファイルは現状リポジトリの `migrations/` 配下にあります。DEB/RPM パッケージからデプロイする場合は、同じ release の source tree を使うか、これらの SQL ファイルをデプロイ artifact に含めてください。

```bash
mysql -h mysql.example.com -u dns_user -p arca_dns \
  < migrations/mysql/000001_initial_schema.up.sql
```

設定例:

```yaml
backend:
  type: "mysql"
  mysql:
    dsn: "dns_user:dnspassword@tcp(mysql.example.com:3306)/arca_dns?parseTime=true"
```

### PostgreSQL

PostgreSQL backend も controller 起動前に SQL の適用が必要です。

schema ファイルは現状リポジトリの `migrations/` 配下にあります。DEB/RPM パッケージからデプロイする場合は、同じ release の source tree を使うか、これらの SQL ファイルをデプロイ artifact に含めてください。

```bash
psql "postgres://user:pass@postgres.example.com:5432/arca_dns?sslmode=require" \
  -f migrations/postgres/000001_initial_schema.up.sql
```

設定例:

```yaml
backend:
  type: "postgres"
  postgres:
    dsn: "postgres://user:pass@postgres.example.com:5432/arca_dns?sslmode=require"
```

### etcd

Kubernetes では etcd backend が扱いやすい選択肢です。production では単一ノード etcd ではなく、外部の冗長化された etcd を使ってください。

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

Git backend はゾーンを Git repository に保存します。監査性は高い一方、ゾーン数や更新頻度が大きい環境では SQL/etcd backend を優先してください。

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

### 1. パッケージをインストール

```bash
# Debian/Ubuntu
sudo apt-get install bird2 nsd unbound arca-dns

# EL/RHEL 系
sudo dnf install bird nsd unbound arca-dns
```

パッケージは次のファイルを配置します。

- `/usr/bin/arca-dns-controller`
- `/usr/bin/arca-dns-agent`
- `/etc/arca-dns/controller.yaml`
- `/etc/arca-dns/agent.yaml`
- `/usr/lib/systemd/system/arca-dns-controller.service`
- `/usr/lib/systemd/system/arca-dns-agent.service`
- `/usr/lib/sysusers.d/arca-dns.conf`

`tmpfiles.d` により次のディレクトリも作成されます。

- `/etc/arca-dns`
- `/var/lib/arca-dns`
- `/var/lib/arca-dns/keys`
- `/var/lib/arca-dns/artifacts`
- `/var/log/arca-dns`

### 2. controller を設定

`/etc/arca-dns/controller.yaml` を編集します。

最低限、次を確認してください。

- `api.auth.api_keys` の placeholder を実際の `sha256:<64 hex>` に置き換える
- `backend.type` と backend 固有設定を決める
- DNSSEC 有効時は `/etc/arca-dns/master.key` または `ARCA_DNS_DNSSEC_MASTER_KEY_B64` を設定する
- `storage.*` と `dnssec.key_directory` が service から書き込み可能であることを確認する

パッケージ版 controller は `arca-dns` service user で起動します。agent は NSD/Unbound/BIRD の制御のため root を維持しますが、systemd unit で sandboxing され、設定済みの DNS、BIRD、state、log、runtime path のみを書き込み可能にしています。path を変更する場合は、権限または systemd drop-in も合わせて調整してください。

### 3. agent を設定

`/etc/arca-dns/agent.yaml` を編集します。

最低限、次を設定します。

- `controller.url`: controller の URL
- `controller.api_key`: 生の API キー
- `nsd.enabled`, `nsd.zone_directory`, `nsd.control_path`
- `unbound.enabled`, `unbound.control_path`
- `bird.enabled`, `bird.protocols`, `bird.socket_path`
- `health.nsd_server`, `health.unbound_server`, `health.test_record`

BIRD config を agent から生成する場合は、メインの `bird.conf` に生成ファイルを include してください。

```bird
include "/etc/bird/arca-dns-anycast.conf";
```

agent 側の設定例:

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

### 4. systemd service を起動

controller と agent を同じノードで必ず両方起動する必要はありません。通常、controller ノードでは controller service、エッジノードでは agent service を起動します。

```bash
sudo systemctl enable --now arca-dns-controller
sudo systemctl status arca-dns-controller

sudo systemctl enable --now arca-dns-agent
sudo systemctl status arca-dns-agent
```

ログ確認:

```bash
journalctl -u arca-dns-controller -f
journalctl -u arca-dns-agent -f
```

## Docker Compose

Compose 例は `deployments/compose/controller-mysql/docker-compose.yaml` にあります。これは controller + MySQL の検証用構成です。

事前に API キーと DNSSEC マスターキーを環境変数へ設定します。

```bash
export ARCA_DNS_API_KEY="$(openssl rand -hex 32)"
export ARCA_DNS_API_KEY_HASH="sha256:$(printf '%s' "$ARCA_DNS_API_KEY" | sha256sum | awk '{print $1}')"
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="$(openssl rand -base64 32)"
```

起動:

```bash
docker compose \
  -f deployments/compose/controller-mysql/docker-compose.yaml \
  --project-directory . \
  up -d
```

Compose 例は MySQL 初期化時に `migrations/mysql/000001_initial_schema.up.sql` を読み込みます。既存の `mysql_data` volume がある場合、MySQL の `/docker-entrypoint-initdb.d` は再実行されません。スキーマを入れ直す検証では volume を作り直してください。

```bash
docker compose \
  -f deployments/compose/controller-mysql/docker-compose.yaml \
  --project-directory . \
  down -v
```

controller 確認:

```bash
curl http://localhost:8080/health
curl http://localhost:8080/ready
curl -H "X-API-Key: $ARCA_DNS_API_KEY" http://localhost:8080/api/v1/zones
```

agent は通常、NSD/Unbound/BIRD を制御するエッジノードの OS 上で動かし、`controller.url` を Compose ホストに向けます。

## Kubernetes

Kubernetes マニフェストは controller 用です。agent は通常、BGP と DNS が動作するエッジノード上で systemd service として稼働させます。

Kustomize entrypoint:

- Base（外部/HA etcd）: `deployments/kubernetes/controller/base`
- Demo（単一ノード etcd 同梱）: `deployments/kubernetes/controller/overlays/demo-etcd`

### 1. Secret を置き換える

`deployments/kubernetes/controller/base/controller-secret.yaml` の `dnssec-master-key-b64` を置き換えます。

```bash
openssl rand -base64 32
```

### 2. controller 設定を置き換える

`deployments/kubernetes/controller/base/controller.yaml` を編集します。

- `api.auth.api_keys.admin`
- `backend.etcd.endpoints`
- `backend.etcd.prefix`
- `storage.*`
- `dnssec.*`

demo overlay を使う場合は、`deployments/kubernetes/controller/overlays/demo-etcd/controller.yaml` 側も同様に API キーハッシュを置き換えます。

### 3. PVC を確認する

`deployments/kubernetes/controller/base/controller-pvc.yaml` は `10Gi` の `ReadWriteOnce` PVC を作成します。storage class や容量はクラスタに合わせて変更してください。

controller Pod は `/var/lib/arca-dns` を PVC に mount し、Pod security context で `fsGroup: 65532` を設定しています。これは distroless nonroot image が key/artifact directory に書き込めるようにするためです。

### 4. デプロイする

外部/HA etcd:

```bash
kubectl apply -k deployments/kubernetes/controller/base
```

デモ用単一ノード etcd:

```bash
kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd
```

### 5. 確認する

```bash
kubectl get deploy,po,svc,pvc
kubectl logs deploy/arca-dns-controller
kubectl port-forward svc/arca-dns-controller 8080:8080
curl http://localhost:8080/health
curl http://localhost:8080/ready
```

Ingress 例は `deployments/kubernetes/controller/examples/ingress.yaml` にあります。TLS は ingress controller または外部 LB で終端してください。

## Agent のデプロイ詳細

agent は controller から次の API を利用します。

- `GET /api/v1/zones`
- `GET /api/v1/zones/:name/signed`

controller の API 認証が有効な場合、agent は `X-API-Key` header に `controller.api_key` を付与します。

zone 同期では次を行います。

- controller の zone 一覧を取得
- ETag を使って変更済み zone のみ取得
- checksum header を検証
- `nsd.zone_directory` に atomic write
- 既存ファイルを `*.backup.<timestamp>` として保持
- NSD/Unbound reload hook を実行
- controller から削除された zone をローカルから削除

agent の HTTP endpoint:

| Endpoint | 内容 |
| --- | --- |
| `GET /health` | liveness |
| `GET /ready` | 初回同期済み、かつ sync が stale でないこと |
| `GET /status` | 同期状態、health、BGP announce 状態 |
| `GET /metrics` | Prometheus metrics |

agent の status server はデフォルトで `127.0.0.1:9090` を listen します。
`metrics.listen` をリモートアドレスに変更する場合は、network control
または認証付き proxy の背後に置いてください。

## デプロイ後の確認

controller:

```bash
curl http://controller:8080/health
curl http://controller:8080/ready
curl http://controller:8080/status
curl http://controller:8080/metrics
```

agent:

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

## ロールアウトとバックアップ

- controller backend を変更する前に、backend native のバックアップを取得する
- SQL backend は DB dump、Git backend は repository backup、etcd は snapshot を使う
- DNSSEC key directory と master key は必ず一緒にバックアップする
- agent は複数台を少しずつ更新し、`/ready`, `/status`, BGP announce 状態を確認する
- controller の backend を移行する場合は `arca-dns-controller migrate` を使える。現時点の migrate command は `sqlite`（既定）、`postgres`, `mysql`, `git`, `etcd` を対象にしている

## よくある問題

| 症状 | 主な原因 | 対応 |
| --- | --- | --- |
| controller が `api.auth.api_keys` で起動しない | placeholder のまま、または API キー未設定 | `sha256:<64 hex>` を設定する |
| controller が master key エラーで起動しない | DNSSEC 有効だが master key がない | `ARCA_DNS_DNSSEC_MASTER_KEY_B64` または `/etc/arca-dns/master.key` を設定する |
| MySQL/PostgreSQL で table not found | SQL スキーマ未適用 | `migrations/<backend>/000001_initial_schema.up.sql` を適用してから起動する |
| container が `/var/lib/arca-dns` に書けない | distroless nonroot image の UID と volume 権限が合っていない | volume を UID/GID `65532` で書けるようにする。Kubernetes base は `fsGroup: 65532` を設定済み |
| agent `/ready` が 503 | 初回同期未完了、または sync stale | controller URL/API key、zone 一覧、agent ログを確認する |
| BGP が announce されない | health check 失敗、BIRD socket 権限、protocol 名不一致 | `curl :9090/status`, `birdc show protocols`, agent ログを確認する |

## 次のステップ

- [運用ガイド](operations.ja.md): Day-2 運用
- [API リファレンス](api.ja.md): API ドキュメント
- [DNSSEC 管理](dnssec.ja.md): DNSSEC 鍵、DS、ローテーション
- [アーキテクチャ](architecture.ja.md): システム設計
