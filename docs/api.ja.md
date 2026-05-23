# API リファレンス（Controller）

[English](api.md) | 日本語

Controller API の source of truth は `api/openapi.yaml`（OpenAPI 3.0）です。本ドキュメントは、一般的なワークフローと HTTP の要点に焦点を当てた、人が読みやすいガイドです。

## Base URL

- API base: `http://<controller-host>:8080/api/v1`。認証不要の health/readiness/status endpoint は `http://<controller-host>:8080`
- Observability base: `http://<controller-host>:9053`。Prometheus metrics と過去互換の health/readiness/status alias を提供します。

## 認証

controller 設定で API 認証を有効にしている場合、*保護された* エンドポイントには API キーのヘッダを付与してください。

```http
X-API-Key: <api-key>
```

API キーには `api.auth.api_key_roles` で明示的な role を割り当てる必要があります。`admin` key は管理 API にアクセスでき、`agent` key は zone summary 一覧と signed artifact 読み取りに制限されます。`api.auth.allow_implicit_admin_roles` は role を省略していた既存 config の移行時だけに使う互換設定です。

Health/readiness/status endpoint（`/health`, `/ready`, `/status`）と observability metrics（`/metrics`）は認証不要です。Health/readiness/status は API listener、metrics は observability listener で提供されます。

## データモデル（Zone）

`Zone` の JSON フィールド（`pkg/model/zone.go` 参照）:

- `name`（string）: ゾーン FQDN（通常は末尾にドットを付ける。例: `example.com.`）
- `version`（string）: 一意なバージョン識別子（`v{ULID}` 形式）。`ETag` としても使用
- `soa`（object）: SOA（`mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum`）
- `records`（array）: RR。各レコードは `name`, `type`, `ttl`, `value`（backend/type により `id` / `priority` が付くことがあります）
- `dnssec`（object, optional）: DNSSEC 設定と署名の有効期限（有効時）
- `created_at`, `updated_at`（RFC3339 timestamps）

対応 RR type: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `PTR`, `SRV`, `CAA`

## エラー応答形式

多くの API エラーは JSON で返されます。

```json
{
  "code": "INVALID_INPUT",
  "message": "Zone validation failed",
  "details": { "zone": "example.com." }
}
```

`code` は `pkg/model/errors.go` に定義されています（例: `NOT_FOUND`, `ALREADY_EXISTS`, `INVALID_INPUT`, `CONFLICT`, `UNAUTHORIZED`, `RATE_LIMIT_EXCEEDED`）。

## 同時更新制御（ETag / If-Match）

- `POST /zones`, `GET /zones/:name`, `PUT /zones/:name` の成功レスポンスには zone resource `ETag`（`ETag: "<zone.version>"`）が含まれます。
- `PUT /zones/:name` と `DELETE /zones/:name` は、zone resource ETag を `If-Match` に指定する必要があります。並行更新があると `409 Conflict` を返します。
- `GET /zones/:name` は zone resource ETag による `If-None-Match` をサポートし、変更が無い場合は `304 Not Modified` を返します。

署名済みアーティファクトについて:
- `GET /zones/:name/signed` と `GET /zones/:name/signed/metadata` は、zone resource ETag ではなく signed artifact `ETag` を返します。
- signed artifact `ETag` は署名済みゾーンファイル本文の SHA256（hex）全体を HTTP ETag として引用符付きで返したものです。
- 署名済みアーティファクトの条件付きリクエストでは、この signed artifact ETag を `If-None-Match` に指定してください。
- `X-Zone-Hash` は同じ SHA256 値を引用符なしで返します。
- `X-Zone-Hash8` は `X-Zone-Hash` の先頭 8 文字（短縮）
- 条件付きリクエストヘッダでは、引用符付き/なしのどちらの ETag 値も受理します。

## エンドポイント

### Health / Status / Metrics（認証不要）

- API listener（`:8080`）: `GET /health`, `GET /ready`, `GET /status`
- Observability listener（`:9053`）: `GET /metrics`
- Observability listener には過去互換の `/health`, `/ready`, `/status`, `/api/v1/*` alias も残しています。

### Zones（JSON モード）

- `GET /zones?limit=<n>&offset=<n>`: ゾーン一覧（ページング）。`fields=summary` を付けると `name` と `version` のみを返します。
- `POST /zones`: ゾーン作成
- `GET /zones/:name`: ゾーン取得
- `PUT /zones/:name`: ゾーン更新（`If-Match` 必須）
- `DELETE /zones/:name`: ゾーン削除（`If-Match` 必須）

Notes:
- `PUT` では JSON ボディ内の `name` がパスパラメータ `:name` と一致している必要があります。
- DNSSEC が有効な controller では、作成/更新の backend 書き込み前に同期的に署名します。署名に失敗した場合、リクエストは `500 Failed to sign zone` で失敗し、zone は保存されません。

#### レコード操作（records をどう更新するか）

レコード変更は record 専用エンドポイントで行います。`PUT /zones/:name` は SOA メタデータを更新し、既存レコードは保持します。

エンドポイント:

- `GET /zones/:name/records`: ゾーンのレコード一覧
- `POST /zones/:name/records`: レコード作成
- `POST /zones/:name/records/batch`: 複数の作成/更新/削除を原子的に適用
- `PUT /zones/:name/records/:id`: レコード置換
- `DELETE /zones/:name/records/:id`: レコード削除

レコードを変更するリクエストでは、現在のゾーン `ETag` を `If-Match` に指定する必要があります。これはゾーン更新と同じ楽観ロックです。
batch endpoint は削除、更新、作成の順で適用し、最終的なレコード集合が検証を通ってから 1 回だけ保存します。

レコードフィールド:

- `name`（string）: ゾーン origin からの相対名（例: `"@"`, `"www"`, `"mail.sub"`）。現在は「非空」のみをチェックしますが、DNS らしい値にしてください。
- `type`（string）: 対応 type のいずれか（後述）
- `ttl`（number）: `> 0` かつ `<= 2147483647`
- `value`（string）: `type` に依存（検証あり。後述）
- `id`（string, optional）: backend が保持する場合は backend 依存です。backend が ID を返さない場合、API は record CRUD 用にレコード内容から決定的な ID を返します。

#### レコード value の形式（検証ルール）

controller は `record.type` に応じて `record.value` を検証します（`pkg/model/validation.go` 参照）。

- `A`: IPv4（例: `"192.0.2.1"`）
- `AAAA`: IPv6（例: `"2001:db8::1"`）
- `CNAME`, `NS`, `PTR`: ドメイン名（例: `"target.example.com."`）
- `MX`: `"priority domain"`（例: `"10 mail.example.com."`）
- `SRV`: `"priority weight port target"`（例: `"10 5 443 svc.example.com."`）
- `TXT`: 空文字列を含む 0〜65279 bytes の任意文字列（例: `"v=spf1 -all"`）
- `CAA`: `"flags tag value"`（例: `"0 issue letsencrypt.org"`）

末尾ドットのないドメインターゲットは、既に zone origin で終わっている場合を除き、zone origin からの相対名として解釈されます。外部ターゲットを指定する場合は、`value` で末尾ドット付き FQDN を使ってください。

### Zones（Raw BIND モード）

- `POST /zones/raw`: BIND ゾーンファイルをアップロードしてゾーン作成

対応 Content-Type:
- `text/plain`: リクエストボディがゾーンファイル。ファイルに `$ORIGIN` が無い場合は `origin=<zone>` を query に指定します。
- `multipart/form-data`: `zonefile` フィールドとしてファイルをアップロード。origin はフォームフィールド `origin` で指定するか、`<filename>.zone` から推定される場合があります。

非対応/拒否される機能（`400`）:
- `$GENERATE` directive
- `$INCLUDE` directive（セキュリティ上の理由で既定無効）
- 未知の RR type（Raw アップロードにおける DNSSEC RR type も含む）

### Zone Artifacts（agent 向け）

- `GET /zones/:name/signed`: 署名済みゾーンファイル（BIND 形式）をダウンロード
  - レスポンスヘッダに `ETag`, `X-Zone-Serial`, `X-Zone-Hash`, 任意の `X-Zone-Signature`, 任意の `X-Zone-Signature-Key-ID`, `Content-Disposition` を含みます。
  - 署名サービスが利用できない場合、controller は未署名の生成ゾーンへフォールバックします。

### DNSSEC

- `GET /zones/:name/ds`（alias: `GET /zones/:name/dnssec/ds`）: DS レコード（plain text; 1 行 1 レコード）
  - 署名サービスが利用できない場合は `503`
  - レスポンスヘッダに `X-Zone-Name`, `X-Zone-Version` を含みます。

## 例（curl）

共通変数:

```bash
BASE="http://localhost:8080/api/v1"
API_KEY="your-api-key" # 認証を有効にしている場合のみ
AUTH=(-H "X-API-Key: ${API_KEY}")
```

ゾーン作成（JSON）:

```bash
curl -i -X POST "${BASE}/zones" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"example.com.",
    "soa":{"mname":"ns1.example.com.","rname":"admin.example.com.","refresh":3600,"retry":1800,"expire":604800,"minimum":86400},
    "records":[
      {"name":"@","type":"NS","ttl":3600,"value":"ns1.example.com."},
      {"name":"@","type":"A","ttl":300,"value":"192.0.2.1"}
    ]
  }'
```

ゾーン一覧:

```bash
curl -s "${BASE}/zones?limit=100&offset=0" "${AUTH[@]}"
```

楽観ロック付きの SOA メタデータ更新:

```bash
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X PUT "${BASE}/zones/example.com." \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{
    "name":"example.com.",
    "soa":{"mname":"ns1.example.com.","rname":"admin.example.com.","serial":0,"refresh":3600,"retry":1800,"expire":604800,"minimum":86400}
  }'
```

レコード一覧:

```bash
curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}"
```

レコード 1 件追加（例: `www A`）:

```bash
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X POST "${BASE}/zones/example.com./records" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{"name":"www","type":"A","ttl":300,"value":"192.0.2.2"}'
```

複数レコード変更を原子的に適用:

```bash
records_json="$(curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}")"
root_id="$(printf '%s' "${records_json}" | jq -r '.records[] | select(.name=="@" and .type=="A") | .id')"
old_id="$(printf '%s' "${records_json}" | jq -r '.records[] | select(.name=="old" and .type=="A") | .id')"
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X POST "${BASE}/zones/example.com./records/batch" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d "{
    \"create\": [
      {\"name\":\"api\",\"type\":\"AAAA\",\"ttl\":300,\"value\":\"2001:db8::1\"}
    ],
    \"update\": [
      {\"id\":\"${root_id}\",\"name\":\"@\",\"type\":\"A\",\"ttl\":300,\"value\":\"192.0.2.9\"}
    ],
    \"delete\": [
      {\"id\":\"${old_id}\"}
    ]
  }"
```

レコード更新:

```bash
record_id="$(curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X PUT "${BASE}/zones/example.com./records/${record_id}" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{"name":"www","type":"A","ttl":300,"value":"192.0.2.3"}'
```

レコード削除:

```bash
record_id="$(curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X DELETE "${BASE}/zones/example.com./records/${record_id}" \
  "${AUTH[@]}" \
  -H "If-Match: ${etag}"
```

条件付きリクエストで署名済みゾーンを取得:

```bash
etag="$(curl -sI "${BASE}/zones/example.com./signed" "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"
curl -i "${BASE}/zones/example.com./signed" "${AUTH[@]}" -H "If-None-Match: ${etag}"
```
