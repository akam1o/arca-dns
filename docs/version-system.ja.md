# ゾーンバージョンシステム

[English](version-system.md) | 日本語

## 概要

arca-dns のゾーンバージョンシステムは、以下を一貫した不変の識別子で結びつけます。

1. **API ETag**: HTTP リクエストの楽観的同時更新制御に使用
2. **アーティファクトファイル名**: agent がデプロイ済みゾーンを追跡するために使用
3. **agent 適用状態**: ロールバックや監査のために使用

本ドキュメントは、バージョンスキーム、生成方法、システム内での利用方法を説明します。

---

## バージョン識別子の形式

### スキーム

```
v{ULID}
```

ここで:
- **ULID**: controller が発行する ULID（時系列ソート可能、26 文字）

また、arca-dns はコンテンツハッシュも別途公開します。
- **hash**: 正規化されたゾーン内容の SHA256 の先頭 8 文字（`X-Zone-Hash` およびメタデータ API で返されます）

### 例

```
v01ARZ3NDEKTSV4RRFFQ69G5FAV
v01ARZ3NDEKTSV4RRFFQ69G5FB0
v01ARZ3NDEKTSV4RRFFQ69G5FB1
```

### 構成要素

#### Serial Number

serial は `YYYYMMDDnn`（10 桁）形式です。

- **YYYY**: 年（4 桁）
- **MM**: 月（01-12）
- **DD**: 日（01-31）
- **nn**: カウンタ（00-99）

**自動インクリメントの挙動**:
- 既存 serial の日付が今日と一致する場合、`nn` をインクリメント
- 今日の方が新しい場合、`{newdate}01` にリセット
- 1 日あたりゾーンごとに最大 100 更新
- RFC 1982 に従い、serial は 4294967295（2^32 - 1）で wrap

#### Hash

hash は次のように計算されます。

```
hash = SHA256(canonical_zone_content)[:8]
```

`canonical_zone_content` は以下を正規化して組み立てます。
1. ゾーン名（小文字化）
2. SOA（正規化）
3. すべてのレコードを次でソート:
   - レコード名（辞書順）
   - レコード type（辞書順）
   - レコード value（辞書順）
4. DNSSEC 設定（有効時）

**重要**: hash は DNSSEC 署名前に計算します。これにより、未署名/署名済みの状態に依存しない一貫した hash になります。

---

## バージョン生成

### Controller の処理

ゾーンを作成/更新するとき:

1. **serial を計算**
   ```go
   currentSerial := zone.SOA.Serial
   today := time.Now().Format("20060102")

   if strings.HasPrefix(fmt.Sprintf("%010d", currentSerial), today) {
       // Same day, increment counter
       newSerial = currentSerial + 1
   } else {
       // New day, reset counter
       newSerial = parseDate(today) * 100 + 1
   }
   ```

2. **ゾーンを正規化**
   ```go
   canonical := canonicalizeZone(zone)
   ```

3. **hash を計算**
   ```go
   h := sha256.Sum256([]byte(canonical))
   hash := hex.EncodeToString(h[:])[:8]
   ```

4. **version を作成**
   ```go
   version := fmt.Sprintf("v%d-%s", newSerial, hash)
   ```

5. **version を保存**
   ```go
   zone.Version = version
   versionMap[version] = {
       Zone:               zone,
       Serial:             newSerial,
       Timestamp:          now,
       Hash:               hash,
       SignedArtifactPath: "/path/to/artifact",
   }
   ```

### 例（コード）

```go
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GenerateVersion generates a version identifier for a zone.
func GenerateVersion(zone *Zone) (string, error) {
	// 1. Compute new serial
	serial := computeSerial(zone.SOA.Serial)

	// 2. Canonicalize zone
	canonical := canonicalizeZone(zone)

	// 3. Compute hash
	h := sha256.Sum256([]byte(canonical))
	hash := hex.EncodeToString(h[:])[:8]

	// 4. Create version
	version := fmt.Sprintf("v%d-%s", serial, hash)

	return version, nil
}

func computeSerial(currentSerial uint32) uint32 {
	now := time.Now()
	today, _ := strconv.Atoi(now.Format("20060102"))

	currentDate := currentSerial / 100
	currentCounter := currentSerial % 100

	if currentDate == uint32(today) && currentCounter < 99 {
		return currentSerial + 1
	}

	return uint32(today)*100 + 1
}

func canonicalizeZone(zone *Zone) string {
	var buf strings.Builder

	// Zone name (lowercase)
	buf.WriteString(strings.ToLower(zone.Name))
	buf.WriteString("\n")

	// SOA
	buf.WriteString(fmt.Sprintf("SOA %s %s %d %d %d %d %d\n",
		zone.SOA.MName, zone.SOA.RName,
		zone.SOA.Serial, zone.SOA.Refresh, zone.SOA.Retry,
		zone.SOA.Expire, zone.SOA.Minimum))

	// Records (sorted)
	records := make([]Record, len(zone.Records))
	copy(records, zone.Records)
	sort.Slice(records, func(i, j int) bool {
		if records[i].Name != records[j].Name {
			return records[i].Name < records[j].Name
		}
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		return records[i].Value < records[j].Value
	})

	for _, r := range records {
		buf.WriteString(fmt.Sprintf("%s %s %d %s\n",
			r.Name, r.Type, r.TTL, r.Value))
	}

	return buf.String()
}
```

---

## バージョンの利用

### API ETag

version は HTTP レスポンスの ETag として返されます。

**Response:**
```http
HTTP/1.1 200 OK
ETag: "v2024122801-a3f5c2e9"
Content-Type: application/json
```

**Conditional Request:**
```http
GET /api/v1/zones/example.com.
If-None-Match: "v2024122801-a3f5c2e9"
```

**Conditional Update:**
```http
PUT /api/v1/zones/example.com.
If-Match: "v2024122801-a3f5c2e9"
Content-Type: application/json
```

### アーティファクトファイル名

署名済みゾーンファイルは、ファイル名に version を含めて保存されます。

```
/var/lib/arca-dns/artifacts/example.com/v2024122801-a3f5c2e9.zone.signed
```

メタデータも隣接して保存されます。

```json
{
  "version": "v2024122801-a3f5c2e9",
  "serial": 2024122801,
  "hash": "a3f5c2e9",
  "timestamp": "2024-12-28T10:30:00Z",
  "checksum": "sha256:1a2b3c4d...",
  "signature": "base64_encoded_hmac..."
}
```

### Agent State

agent はローカル状態として適用済み version を保持します。

```json
{
  "zones": {
    "example.com.": {
      "current_version": "v2024122801-a3f5c2e9",
      "applied_at": "2024-12-28T10:31:00Z",
      "previous_versions": [
        "v2024122723-7f2b8d1c",
        "v2024122701-4e9c1a6f"
      ],
      "nsd_reloaded": true,
      "unbound_reloaded": true
    }
  }
}
```

---

## 同時更新制御

### ETag による楽観ロック

**Read Zone:**
```
Client                    Controller
  |                           |
  | GET /zones/example.com.   |
  |-------------------------->|
  |                           |
  | 200 OK                    |
  | ETag: "v...01-a3f5c2e9"   |
  |<--------------------------|
```

**Update Zone（成功）:**
```
Client                    Controller
  |                           |
  | PUT /zones/example.com.   |
  | If-Match: "v...01-a3f5"   |
  |-------------------------->|
  |                           | (version matches)
  | 200 OK                    | (update succeeds)
  | ETag: "v...02-7f2b8d1c"   |
  |<--------------------------|
```

**Update Zone（競合）:**
```
Client                    Controller
  |                           |
  | PUT /zones/example.com.   |
  | If-Match: "v...01-a3f5"   |
  |-------------------------->|
  |                           | (version mismatch!)
  | 409 Conflict              |
  | ETag: "v...02-7f2b8d1c"   | (current version)
  |<--------------------------|
  |                           |
  | GET /zones/example.com.   | (re-read)
  |-------------------------->|
  | (update with new ETag)    |
```

### ロストアップデートの防止

If-Match を使わないと、並行更新で上書きが起こり得ます。

```
Time   Client A               Controller              Client B
----   --------               ----------              --------
T1     GET zone (v1)
T2                                                    GET zone (v1)
T3     PUT zone -> v2
T4                                                    PUT zone -> v3
                                                      (overwrites A's change!)
```

If-Match を使えば競合を検出できます。

```
Time   Client A               Controller              Client B
----   --------               ----------              --------
T1     GET zone (v1)
T2                                                    GET zone (v1)
T3     PUT zone                                      PUT zone
       If-Match: v1                                  If-Match: v1
       -> succeeds (v2)
T4                                                    -> 409 Conflict!
                                                      (must re-read v2)
```

---

## バージョン履歴とロールバック

### backend の対応状況

| Backend    | Versioning | Mechanism |
|------------|-----------|----------|
| SQLite     | ⚠️ Optional | `zone_versions` テーブル |
| PostgreSQL | ⚠️ Optional | `zone_versions` テーブル |
| MySQL      | ⚠️ Optional | `zone_versions` テーブル |
| Git        | ✅ Yes    | Git commit（ネイティブ） |
| etcd       | ✅ Yes    | revision ベース履歴 |
| Memory     | ❌ No     | 現在の 1 バージョンのみ（非推奨） |

### ロールバック手順

**List Versions:**
```bash
GET /api/v1/zones/example.com./versions
```

Response:
```json
{
  "versions": [
    {
      "version": "v2024122803-1a2b3c4d",
      "serial": 2024122803,
      "timestamp": "2024-12-28T12:00:00Z",
      "hash": "1a2b3c4d"
    },
    {
      "version": "v2024122802-7f2b8d1c",
      "serial": 2024122802,
      "timestamp": "2024-12-28T11:00:00Z",
      "hash": "7f2b8d1c"
    },
    {
      "version": "v2024122801-a3f5c2e9",
      "serial": 2024122801,
      "timestamp": "2024-12-28T10:00:00Z",
      "hash": "a3f5c2e9"
    }
  ]
}
```

**Rollback to Previous Version:**
```bash
# Get the old version
GET /api/v1/zones/example.com./versions/v2024122801-a3f5c2e9

# Apply it as a new update (creates v2024122804)
PUT /api/v1/zones/example.com.
If-Match: "v2024122803-1a2b3c4d"
Content-Type: application/json

{
  "soa": { ... },  # from v2024122801
  "records": [ ... ]
}
```

**Note**: ロールバックは「serial を巻き戻す」のではなく、serial をインクリメントした新バージョンを作成します（DNS のベストプラクティス）。

---

## Agent 同期

### 条件付き取得（If-None-Match）

```
Agent                         Controller
  |                               |
  | GET /zones/example.com./signed
  | If-None-Match: "v...01-a3f5"  |
  |------------------------------>|
  |                               | (version unchanged)
  | 304 Not Modified              |
  |<------------------------------|
  |                               |
  | (no download, no reload)      |
```

帯域削減: ゾーンあたり同期間隔ごとに ~10KB

### 更新検知フロー

```
Agent                         Controller
  |                               |
  | GET /zones/example.com./signed
  | If-None-Match: "v...01-a3f5"  |
  |------------------------------>|
  |                               | (version changed!)
  | 200 OK                        |
  | ETag: "v...02-7f2b"           |
  | X-Zone-Hash: "7f2b8d1c..."    |
  | [zone file content]           |
  |<------------------------------|
  |                               |
  | 1. Verify checksum            |
  | 2. Write to temp file         |
  | 3. Validate with nsd-checkzone|
  | 4. Atomic rename              |
  | 5. Backup old version         |
  | 6. Reload NSD/Unbound         |
  | 7. Update local state         |
```

---

## 整合性検証

### チェックサム検証

agent はダウンロードしたゾーンの SHA256 を検証します。

```go
func verifyChecksum(data []byte, expectedHash string) error {
	h := sha256.Sum256(data)
	actualHash := hex.EncodeToString(h[:])

	if !strings.HasPrefix(actualHash, expectedHash) {
		return fmt.Errorf("checksum mismatch: expected %s, got %s",
			expectedHash, actualHash[:8])
	}

	return nil
}
```

### 署名検証（任意）

有効化している場合、controller は HMAC でアーティファクト署名を行います。

```go
func signArtifact(data []byte, secret string) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func verifySignature(data []byte, signature string, secret string) error {
	expected := signArtifact(data, secret)
	if signature != expected {
		return errors.New("signature verification failed")
	}
	return nil
}
```

---

## 監視とアラート

### メトリクス

**Controller:**
- `arca_zone_version_created_total{zone}` - 生成されたバージョン総数
- `arca_zone_version_rollback_total{zone}` - ロールバック回数
- `arca_zone_version_conflict_total{zone}` - ETag 競合数

**Agent:**
- `arca_zone_version_current{zone,version}` - ゾーンごとの現在バージョン（gauge）
- `arca_zone_version_synced_total{zone}` - 同期成功回数
- `arca_zone_version_age_seconds{zone}` - 現在バージョンの経過時間

### アラート例

**Version Drift:**
```yaml
alert: ZoneVersionDrift
expr: |
  count(arca_zone_version_current{zone="example.com."}) by (version) > 1
for: 10m
annotations:
  summary: "Multiple agents running different versions of {{ $labels.zone }}"
```

**Stale Version:**
```yaml
alert: ZoneVersionStale
expr: |
  arca_zone_version_age_seconds > 3600
for: 5m
annotations:
  summary: "Zone {{ $labels.zone }} hasn't been updated in over 1 hour"
```

---

## ベストプラクティス

### Do:

✅ 更新には常に If-Match を使う  
✅ ロールバックのために agent 状態に version を保持する  
✅ agent 間の version drift を監視する  
✅（backend が許すなら）履歴を保持する  
✅ agent 側でチェックサム検証を行う  
✅ If-None-Match による条件付き取得で帯域を節約する

### Don't:

❌ If-Match なしで更新しない（ロストアップデートのリスク）  
❌ serial を手動でいじらない（controller に任せる）  
❌ 古い serial を再利用しない（RFC 1982 的に問題）  
❌ チェックサム検証を省略しない（破損検知できない）  
❌ 履歴を全削除しない（ロールバック不能）

---

## トラブルシューティング

### 症状と対処

**問題**: 更新のたびに ETag 競合が発生する  
- **原因**: 複数クライアントが同一ゾーンを同時更新  
- **対処**: 指数バックオフ付きリトライを実装する

**問題**: agent が古い version のまま  
- **原因**: 同期失敗、controller 到達不能  
- **対処**: agent ログと controller 到達性を確認する

**問題**: version hash が予期せず変わる  
- **原因**: レコード順序が変わっている（非 canonical）  
- **対処**: hash 計算前に正規化を徹底する

**問題**: serial が不自然に進む  
- **原因**: クロックスキュー、日付変更  
- **対処**: システム時刻、NTP 同期を確認する

---

## 参考

- RFC 1982: Serial Number Arithmetic
- RFC 7719: DNS Terminology
- HTTP ETag: RFC 7232
- SHA-256: FIPS 180-4

