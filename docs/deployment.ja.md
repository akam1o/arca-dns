# arca-dns デプロイガイド

[English](deployment.md) | 日本語

## 概要

arca-dns は以下で構成されます。
- **Controller**（`arca-dns-controller`）: REST API + DNSSEC 署名 + アーティファクト配布
- **Agent**（`arca-dns-agent`）: 署名済みゾーンを同期し、エッジノード上の NSD/Unbound/BIRD を制御

推奨する本番トポロジ:
- controller は中枢で稼働（VM/ベアメタル、または Kubernetes）
- agents は BGP ピアリングが終端するエッジノード（VM/ベアメタル）で稼働

## 前提条件

### Controller
- いずれかの backend: `sqlite`（既定、ゼロコンフィグ）, `postgres`, `mysql`, `git`, `etcd`（`memory` はテスト用に利用可能だが非推奨）
- ストレージ: 書き込み可能な `storage.artifact_directory` と `storage.key_directory`（DNSSEC 有効時は `dnssec.key_directory` も設定）
- （`dnssec.enabled: true` の場合）DNSSEC マスターキー設定（後述）

### Agent（エッジノード）
- ノード上に NSD / Unbound / BIRD 2.x をインストールし、設定できること
  - Debian/Ubuntu: パッケージ名は通常 `bird2`
  - EL/RHEL: パッケージ名は通常 `bird`
- 上流ルータへの BGP 接続性
- ノードから 53/TCP+UDP を公開

### Network
- Controller API: 既定で `:8080`
- Agent メトリクス: 既定で `:9090`

## DEB/RPM セットアップ（agent は推奨）

### 1) パッケージをインストール

ランタイム依存と arca-dns をインストールします。
- Debian/Ubuntu: `bird2`, `nsd`, `unbound`, `arca-dns`
- EL9/RHEL: `bird`, `nsd`, `unbound`, `arca-dns`

### 2) controller を設定

`/etc/arca-dns/controller.yaml` を編集します（`configs/controller.example.yaml` からインストールされます）。

#### API 認証

controller のデフォルトは `api.auth.enabled: true` です。認証が有効な場合、
少なくとも 1 つの有効な API キーハッシュが設定されていないと起動時にエラーになります。
controller を公開する前に API キーのハッシュ値を設定してください。

```bash
echo -n 'your-api-key' | sha256sum
```

次に `api.auth.api_keys` に `sha256:<hex>` の形式で設定してください。env だけで
設定する場合は `ARCA_DNS_API_AUTH_API_KEYS_ADMIN=sha256:<hex>` を使えます。
suffix は小文字化され、API key の principal 名になります。

意図的に無認証のローカル開発環境として起動する場合だけ、明示的に
`api.auth.enabled: false` を設定してください。

#### DNSSEC マスターキー

`dnssec.enabled: true` の場合、controller は 32 バイトの AES-256 マスターキーで DNSSEC 秘密鍵を at-rest 暗号化します。

読み込み優先順位:
1) `ARCA_DNS_DNSSEC_MASTER_KEY_B64`（base64; 32 バイトにデコードできること）
2) `dnssec.key_directory/_masterkey`（base64; 32 バイトにデコードできること）
3) `/etc/arca-dns/master.key`（base64; 32 バイトにデコードできること）
4) 自動生成（`dnssec.master_key_auto_generate: true` の場合のみ）

Tip: 多くの環境では `storage.key_directory` と `dnssec.key_directory` を同じディレクトリ（例: `/var/lib/arca-dns/keys`）にします。

例（環境変数）:

```bash
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="$(openssl rand -base64 32)"
```

### 3) agent を設定

`/etc/arca-dns/agent.yaml` を編集します（`configs/agent.example.yaml` からインストールされます）。
- `controller.url` を controller の URL に設定（例: `https://controller.example.com:8080`）
- `controller.api_key` は *生の* API キー（ハッシュではない）を設定
- ノードに合わせて `nsd` / `unbound` / `bird` を有効化し設定

### 4) systemd サービスを有効化

```bash
sudo systemctl enable --now arca-dns-controller
sudo systemctl enable --now arca-dns-agent

sudo systemctl status arca-dns-controller
sudo systemctl status arca-dns-agent
```

## Docker Compose

配布されるイメージは `deployments/docker/Dockerfile.controller` と `deployments/docker/Dockerfile.agent` からビルドされます。
controller はコンテナ運用と相性が良い一方、agent は（NSD/Unbound/BIRD を制御する都合上）通常ノード OS 上で動かします。

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

その後 agent を各ノードで起動し、`controller.url` を compose ホストに向けてください。

## Kubernetes

### Controller（Deployment + Service）

controller は通常の `Deployment` + `Service` としてデプロイします。
- `controller.yaml` 用 `ConfigMap`
- `ARCA_DNS_DNSSEC_MASTER_KEY_B64` 用 `Secret`
- （推奨）DNSSEC の鍵保管/アーティファクト用に `/var/lib/arca-dns` の PVC
- Kubernetes では `etcd` が backend として扱いやすい既定値です（単一 controller インスタンスでも動作が良い）。

Kustomize のエントリポイント:
- Base（外部/HA etcd）: `kubectl apply -k deployments/kubernetes/controller/base`
- デモ用途のみ（単一ノード etcd 同梱）: `kubectl apply -k deployments/kubernetes/controller/overlays/demo-etcd`

Ingress 例（TLS は ingress で終端）: `deployments/kubernetes/controller/examples/ingress.yaml`

例（抜粋）:

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

### Agent デプロイに関する注意

agent はエッジノード上の NSD/Unbound/BIRD を制御する設計です。
Kubernetes ベースのエッジデプロイでは、一般には agent はノード上（クラスタ外）で稼働させるか、
agent が制御できる形で NSD/Unbound/BIRD を同梱した独自 Pod/イメージ設計が必要です。

## コンテナイメージ

公開レジストリ:
- GHCR: `ghcr.io/akam1o/arca-dns-controller`, `ghcr.io/akam1o/arca-dns-agent`
- Docker Hub: `docker.io/akam1o/arca-dns-controller`, `docker.io/akam1o/arca-dns-agent`

## 次のステップ

- [運用ガイド](operations.ja.md): Day-2 運用
- [API リファレンス](api.ja.md): API ドキュメント
- [アーキテクチャ](architecture.ja.md): システム設計
