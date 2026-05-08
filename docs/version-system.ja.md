# ゾーンバージョンシステム

[English](version-system.md) | 日本語

## 概要

arca-dns は、controller が発行するゾーンバージョンで論理的なゾーン書き込みを識別します。ゾーンバージョンは `Zone.Version` に保存され、ゾーン JSON API の楽観的同時更新制御に使われます。

ゾーンバージョンは、以下とは別物です。

- DNS SOA serial: DNS プロトコル上のメタデータ
- コンテンツハッシュ: 整合性検証やキャッシュ検証のためのチェックサム
- 署名済みアーティファクトの ETag: 署名済みゾーンファイル本文のハッシュ

この分離により、controller は書き込みごとに新しい識別子を発行しつつ、agent はローカルに配置する署名済みファイルのバイト列を検証できます。

---

## バージョン識別子の形式

### スキーム

```text
v{ULID}
```

ここで:

- `v` は固定プレフィックスです。
- `ULID` は controller が発行する 26 文字の monotonic ULID です。

例:

```text
v01ARZ3NDEKTSV4RRFFQ69G5FAV
v01ARZ3NDEKTSV4RRFFQ69G5FB0
v01ARZ3NDEKTSV4RRFFQ69G5FB1
```

主な性質:

- 作成時刻順にソートできます。
- controller の書き込みごとに一意です。
- ゾーン内容から決定論的には計算されません。
- 同じゾーンデータを再 import / copy しても、destination backend への書き込み時に新しいバージョンが作られます。

---

## バージョン生成

controller は `model.NewZoneVersion()` でバージョンを生成します。

```go
func NewZoneVersion() (string, error) {
	id, err := util.NewULID(time.Now())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v%s", id), nil
}
```

controller handler は、create、update、raw import、record mutation が成功して永続化される前に新しいバージョンを割り当てます。backend も、信頼済みの controller 生成バージョンが渡されずに create / update された場合は新しいバージョンを生成します。

SOA serial の扱いはゾーンバージョンとは独立しています。serial は通常の DNS 書き込み処理で変わることがありますが、バージョン識別子には埋め込まれません。

---

## API での利用

### ゾーンリソースの ETag

ゾーン JSON エンドポイントでは `Zone.Version` が HTTP ETag として返されます。

```http
HTTP/1.1 200 OK
ETag: "v01ARZ3NDEKTSV4RRFFQ69G5FAV"
Content-Type: application/json
```

クライアントは、楽観ロックのためにその値を送ります。

```http
PUT /api/v1/zones/example.com.
If-Match: "v01ARZ3NDEKTSV4RRFFQ69G5FAV"
Content-Type: application/json
```

保存済みゾーンのバージョンが一致しない場合、controller は `409 Conflict` を返します。クライアントはゾーンを再取得してから再試行します。

### 署名済みアーティファクトの ETag

署名済みゾーンエンドポイントでは、別の ETag を使います。この ETag は署名済みゾーンファイル本文の SHA256 です。

```http
HTTP/1.1 200 OK
ETag: "717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724"
X-Zone-Hash: 717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724
X-Zone-Hash8: 717fd058
X-Zone-Serial: 2024122801
Content-Type: text/plain; charset=utf-8
```

`GET /api/v1/zones/:name/signed/metadata` は、論理ゾーンバージョンとアーティファクトハッシュの両方を返します。

```json
{
  "zone": "example.com.",
  "version": "v01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "serial": 2024122801,
  "hash": "717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724",
  "hash8": "717fd058",
  "dnssec_enabled": true
}
```

agent は、条件付き取得に署名済みアーティファクトの ETag を保存して送信します。これは、ローカルに配置済みのファイルそのものを検証するためです。

---

## アーティファクトキャッシュ

controller のアーティファクトキャッシュが有効な場合、署名済みゾーンファイルは安全なゾーンディレクトリ配下に、論理ゾーンバージョンを含むファイル名で保存されます。

```text
/var/lib/arca-dns/artifacts/example.com/v01ARZ3NDEKTSV4RRFFQ69G5FAV.zone.signed
```

ファイル名は、そのキャッシュがどの論理ゾーン書き込みから生成されたかを表します。アーティファクトレスポンスの ETag は引き続きファイル内容の SHA256 です。

---

## 同時更新制御

### 更新成功

```text
Client                    Controller
  | GET /zones/example.com.   |
  |-------------------------->|
  | 200 OK                    |
  | ETag: "v01...FAV"         |
  |<--------------------------|
  | PUT /zones/example.com.   |
  | If-Match: "v01...FAV"     |
  |-------------------------->|
  | 200 OK                    |
  | ETag: "v01...FB0"         |
  |<--------------------------|
```

### 競合

```text
Client                    Controller
  | PUT /zones/example.com.   |
  | If-Match: "v01...FAV"     |
  |-------------------------->|
  | 409 Conflict              |
  |<--------------------------|
  | GET /zones/example.com.   |
  |-------------------------->|
  | current ETag で再試行     |
```

変更系リクエストでは常に `If-Match` を使ってください。使わない場合、古いデータを読んだクライアントが他クライアントの変更を上書きできます。

---

## バージョン履歴とロールバック

### backend の対応状況

| Backend    | Versioning | Mechanism |
|------------|------------|-----------|
| SQLite     | Optional   | `zone_versions` table |
| PostgreSQL | Optional   | `zone_versions` table |
| MySQL      | Optional   | `zone_versions` table |
| Git        | Yes        | Git commits and version trailers |
| etcd       | Yes        | etcd revisions |

### バージョン一覧

```http
GET /api/v1/zones/example.com./versions
```

レスポンス例:

```json
{
  "versions": [
    {
      "version": "v01ARZ3NDEKTSV4RRFFQ69G5FB1",
      "serial": 2024122803,
      "timestamp": "2024-12-28T12:00:00Z",
      "hash": "1a2b3c4d"
    },
    {
      "version": "v01ARZ3NDEKTSV4RRFFQ69G5FB0",
      "serial": 2024122802,
      "timestamp": "2024-12-28T11:00:00Z",
      "hash": "7f2b8d1c"
    },
    {
      "version": "v01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "serial": 2024122801,
      "timestamp": "2024-12-28T10:00:00Z",
      "hash": "a3f5c2e9"
    }
  ]
}
```

revision metadata の `hash` はコンテンツメタデータです。controller が発行するバージョン識別子の一部ではありません。

### ロールバック

ロールバックは、古いゾーンデータを通常の書き込みとして適用します。

```http
GET /api/v1/zones/example.com./versions/v01ARZ3NDEKTSV4RRFFQ69G5FAV
GET /api/v1/zones/example.com.

PUT /api/v1/zones/example.com.
If-Match: "v01ARZ3NDEKTSV4RRFFQ69G5FB1"
Content-Type: application/json
```

ロールバック書き込みでは、controller が新しいバージョンを発行します。古いバージョン文字列は再利用されません。

---

## Agent 同期

agent はゾーン一覧でゾーン名と論理バージョンを確認し、その後に署名済みアーティファクトを条件付き取得します。

```text
Agent                         Controller
  | GET /zones/example.com./signed      |
  | If-None-Match: "<artifact-sha256>"   |
  |------------------------------------>|
  | 304 Not Modified                    |
  |<------------------------------------|
  | download / reload なし              |
```

アーティファクトが変わった場合:

```text
Agent                         Controller
  | GET /zones/example.com./signed      |
  | If-None-Match: "<old-artifact-hash>" |
  |------------------------------------>|
  | 200 OK                              |
  | ETag: "<new-artifact-hash>"          |
  | X-Zone-Hash: "<new-artifact-hash>"   |
  | signed zone file                    |
  |<------------------------------------|
  | checksum 検証、atomic write、reload  |
```

---

## ベストプラクティス

- `Zone.Version` は opaque string として扱う。
- ゾーン変更では `If-Match` を使う。
- バージョン文字列から SOA serial や content hash を推測しない。
- 署名済みゾーンファイルの検証には signed artifact ETag と `X-Zone-Hash` を使う。
- backend が対応している場合はバージョン履歴を保持する。
- migration では、destination への書き込み時に新しいバージョンが発行される前提で扱う。

---

## トラブルシューティング

**更新のたびに ETag 競合が発生する**

複数クライアントが同じゾーンを更新しています。ゾーンを再取得し、変更を merge して、現在の ETag で再試行してください。

**agent が古いアーティファクトのまま**

controller 到達性、署名済みアーティファクトの ETag 処理、checksum 検証エラー、ローカル reload 失敗を確認してください。

**再 import したゾーンのバージョンが変わった**

想定された挙動です。バージョンは controller が発行する write ID であり、決定論的な content ID ではありません。

---

## 参考

- ULID: Universally Unique Lexicographically Sortable Identifier
- RFC 1982: Serial Number Arithmetic
- RFC 7232: HTTP Conditional Requests
- FIPS 180-4: SHA-256
