# DNSSEC 鍵管理ガイド

[English](dnssec.md) | 日本語

このドキュメントは、arca-dns の DNSSEC 鍵を管理する方法（鍵生成、ローテーション、バックアップ/復旧）を説明します。

## 目次

- [概要](#概要)
- [マスターキー管理](#マスターキー管理)
- [ゾーン鍵の生成](#ゾーン鍵の生成)
- [DS レコードのエクスポート](#ds-レコードのエクスポート)
- [鍵ローテーション](#鍵ローテーション)
- [バックアップと復旧](#バックアップと復旧)
- [セキュリティ考慮事項](#セキュリティ考慮事項)
- [トラブルシューティング](#トラブルシューティング)

## 概要

arca-dns は controller による中央署名方式で DNSSEC を実装しています。

- **KSK（Key Signing Key）**: DNSKEY RRset を署名
- **ZSK（Zone Signing Key）**: ゾーン内のその他 RRset を署名
- **アルゴリズム**: 既定は ECDSA-P256-SHA256（algorithm 13）。RSA-SHA256（algorithm 8）もサポート
- **マスターキー**: at-rest の秘密鍵暗号化に使う AES-256 キー

すべての秘密鍵は AES-256-GCM で暗号化され、AAD（Authenticated Additional Data）によりメタデータ改ざんを検出します。

## マスターキー管理

### 本番環境

本番では、環境変数でマスターキーを渡すことを推奨します。

```bash
# Generate a random 32-byte master key
python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
# Output: e.g., Q0TV7fRu9QMZKg810KOiokVTJrJDSVPqgaOBxHKNX5U=

# Set environment variable
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="Q0TV7fRu9QMZKg810KOiokVTJrJDSVPqgaOBxHKNX5U="
```

マスターキーは安全に保管してください。
- **Kubernetes**: Secret に保存し Pod spec から参照
- **Systemd**: 権限を絞った `EnvironmentFile=` を利用
- **Docker**: `-e` や Docker secrets で渡す
- **Vault/KMS**: 将来的な拡張（M7+）

### 開発環境

開発用途では、初回起動時に controller がマスターキーを自動生成できます。

```yaml
# config.yaml
dnssec:
  enabled: true
  key_directory: ./keys
```

マスターキーは `./keys/_masterkey` に 0600 権限で保存されます。

**⚠️ 注意**: 自動生成は本番では推奨しません。

### マスターキーの優先順位

controller は次の優先順位でマスターキーを読み込みます。

1. **環境変数**: `ARCA_DNS_DNSSEC_MASTER_KEY_B64`
2. **ファイル**: `{key_directory}/_masterkey`
3. **自動生成**: `AllowAutoGenerate` が true の場合のみ（dev mode）

## ゾーン鍵の生成

### 自動生成

API でゾーンを作成/更新すると、controller は署名前に KSK/ZSK が存在することを保証し、必要に応じて生成します。

### 手動生成

ゾーンの鍵を事前生成する例です。

```go
package main

import (
	"fmt"
	"os"
	"github.com/akam1o/arca-dns/pkg/dnssec"
)

func main() {
	// Load master key
	masterKeyB64, _ := os.ReadFile("/var/lib/arca-dns/keys/_masterkey")
	masterKey, _ := dnssec.ParseMasterKeyB64(string(masterKeyB64))

	// Create key manager
	km, _ := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: "/var/lib/arca-dns/keys",
		MasterKey:    masterKey,
		Algorithm:    13, // ECDSA-P256
	})

	// Generate keys for zone
	ksk, zsk, err := km.EnsureZoneKeys("example.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated KSK: key tag %d\n", ksk.ID.KeyTag)
	fmt.Printf("Generated ZSK: key tag %d\n", zsk.ID.KeyTag)
}
```

### 鍵の保存形式

鍵はゾーンごとのディレクトリに保存されます。

```
{key_directory}/
└── example.com/
    ├── active.json                        # Current active key tags
    ├── Kexample.com.+013+12345.key        # KSK public key (BIND format)
    ├── Kexample.com.+013+12345.private.enc # KSK private key (encrypted)
    ├── Kexample.com.+013+54321.key        # ZSK public key (BIND format)
    └── Kexample.com.+013+54321.private.enc # ZSK private key (encrypted)
```

**ファイル権限**:
- 公開鍵（`.key`）: 0644
- 秘密鍵（`.private.enc`）: 0600
- ディレクトリ: 0700
- マスターキー: 0600

## DS レコードのエクスポート

KSK 生成後、DNSSEC のチェーンを確立するため、親ゾーンに DS レコードを登録する必要があります。

### DS レコードの出力

```bash
# Export in BIND format (default)
arca-dns-controller dnssec export-ds example.com

# Export in JSON format
arca-dns-controller dnssec export-ds example.com --format json

# Use SHA-384 digest (default is SHA-256)
arca-dns-controller dnssec export-ds example.com --digest 4

# Use custom config file
arca-dns-controller dnssec export-ds example.com --config /etc/arca-dns/controller.yaml
```

### 出力例

**BIND format**:
```
example.com. 3600 IN DS 12345 13 2 A1B2C3D4E5F6...
```

**JSON format**:
```json
{
  "name": "example.com.",
  "ttl": 3600,
  "class": "IN",
  "type": "DS",
  "key_tag": 12345,
  "algorithm": 13,
  "digest_type": 2,
  "digest": "A1B2C3D4E5F6..."
}
```

### 親ゾーンへ登録

1. 上記の方法で DS レコードを出力する
2. レジストラまたは親ゾーン運用者へ DS を提出する
3. 親ゾーンが DS を公開するのを待つ
4. DNSSEC チェーンを検証する: `dig +dnssec example.com SOA`

## 鍵ローテーション

DNSSEC 鍵のローテーションは、セキュリティ上のベストプラクティスとして定期的に実施するべきです。

### KSK ローテーション（手動手順）

⚠️ **重要**: KSK ローテーションは親ゾーンとの調整が必要です。

**タイムライン**: 各ステップ間は「親ゾーン TTL の 2 倍」程度を確保してください。

1. **新しい KSK を生成**（Day 0）
   ```bash
   # The controller will generate a new KSK when you explicitly trigger rotation
   # For now, use the API to update the zone, which triggers re-signing
   curl -X PUT https://controller/api/v1/zones/example.com \
     -H "Content-Type: application/json" \
     -d @zone.json
   ```

2. **新しい DS レコードを出力**
   ```bash
   arca-dns-controller dnssec export-ds example.com > new-ds.txt
   ```

3. **親ゾーンへ新 DS を提出**（Day 0）
   - レジストラへ提出
   - 旧 DS も維持（旧/新 DS が共存する期間を設ける）

4. **親ゾーンの伝播を待つ**（Day 0 + parent TTL）
   - `dig +dnssec example.com DS` で検証

5. **active セットから旧 KSK を外す**（Day 0 + 2× parent TTL）
   - `active.json` を更新して新 KSK の key tag を採用
   - controller が新 KSK で再署名

6. **親ゾーンから旧 DS を削除**（Day 0 + 3× parent TTL）
   - レジストラへ削除依頼

### ZSK ローテーション（簡略）

ZSK ローテーションは親ゾーン調整が不要です。

**タイムライン**: 各ステップ間は「ゾーン最大 TTL の 2 倍」程度を確保してください。

1. **新しい ZSK を生成**
   - KSK と同様

2. **旧/新 ZSK の両方で署名**（Day 0）
   - pre-publication として両方で署名

3. **新 ZSK のみに切り替え**（Day 0 + 2× max TTL）
   - `active.json` を更新して新 ZSK の key tag を採用
   - 旧 ZSK の署名は自然に失効

4. **旧 ZSK を削除**（Day 0 + 3× max TTL）
   - 旧 ZSK ファイルを削除

**Note**: 自動鍵ローテーションは M8 以降の拡張で実装予定です。

## バックアップと復旧

### バックアップ手順

**バックアップ対象（重要）**:
1. マスターキー: `{key_directory}/_masterkey`
2. 全ゾーンの鍵ファイル: `{key_directory}/*/*.key` と `{key_directory}/*/*.private.enc`
3. active 鍵の追跡: `{key_directory}/*/active.json`

**バックアップスクリプト例**:
```bash
#!/bin/bash
KEY_DIR="/var/lib/arca-dns/keys"
BACKUP_DIR="/backup/arca-dns-keys-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"
cp -r "$KEY_DIR" "$BACKUP_DIR/"
chmod 700 "$BACKUP_DIR"

# Encrypt backup (recommended)
tar czf - "$BACKUP_DIR" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -out "$BACKUP_DIR.tar.gz.enc"

# Securely delete unencrypted backup
rm -rf "$BACKUP_DIR"
```

**バックアップ頻度**:
- マスターキー: 生成直後に確実に保存し、その後は月次
- ゾーン鍵: 鍵生成/ローテーションごと
- フルバックアップ: 日次

### 復旧手順

**シナリオ 1: 鍵ファイルを失ったがバックアップがある**

1. controller を停止
2. バックアップから鍵ファイルを復元
3. ファイル権限を確認（秘密鍵 0600、ディレクトリ 0700）
4. controller を起動
5. DNSSEC 署名を検証: `dig +dnssec example.com SOA`

**シナリオ 2: マスターキーを失ったがバックアップがある**

1. controller を停止
2. `_masterkey` を 0600 で復元
3. 環境変数方式なら env を設定
4. controller を起動

**シナリオ 3: 鍵の完全喪失**

マスターキーとすべてのバックアップを失うと:

1. 新しいマスターキーを生成
2. 全ゾーンの KSK/ZSK を新規生成
3. 全ゾーンの DS レコードを新規出力
4. 親ゾーンへ新 DS を提出
5. **⚠️ 親ゾーンが新 DS を公開するまで DNSSEC は破綻します**

## セキュリティ考慮事項

### 暗号化

- 秘密鍵は **AES-256-GCM** で暗号化
- AAD により zone/algorithm/key_tag/role の改ざんを検出
- nonce 長を検証し、panic を誘発する入力を排除
- すべての書き込みは原子的（tmp + rename）で破損を防止

### 鍵保管

- マスターキー: 秘密情報。バージョン管理にコミットしない
- 秘密鍵: at-rest 暗号化 + 厳格な権限
- 公開鍵: 共有可能（DNS 応答に含まれる）

### アクセス制御

- 鍵ディレクトリへのアクセスを制限（chmod 700）
- マスターキーは controller プロセス以外に読ませない
- dev/staging/prod で別マスターキーを使う

### 監視

以下を監視してください。
- マスターキー読み込み失敗
- 鍵の復号失敗
- 鍵ファイル欠損
- 権限エラー

## トラブルシューティング

### "Master key not found"

**原因**: 環境変数/ファイルにマスターキーが無く、自動生成も無効。

**対処**:
```bash
# Option 1: Set environment variable
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="<your-key-here>"

# Option 2: Create master key file
python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())" \
  > /var/lib/arca-dns/keys/_masterkey
chmod 600 /var/lib/arca-dns/keys/_masterkey
```

### "Decryption failed"

**原因**: マスターキー違い、または鍵ファイル破損。

**対処**:
1. マスターキーが正しいか確認
2. ファイル整合性を確認
3. 破損しているならバックアップから復元

### "Invalid nonce length"

**原因**: 暗号化済み鍵ファイルの破損。

**対処**:
1. バックアップから復元
2. バックアップが無ければ鍵を再生成し、親ゾーンの DS を更新

### Permission Errors

**原因**: ファイル権限が不正。

**対処**:
```bash
# Fix permissions
chmod 700 /var/lib/arca-dns/keys
chmod 700 /var/lib/arca-dns/keys/*
chmod 644 /var/lib/arca-dns/keys/*/*.key
chmod 600 /var/lib/arca-dns/keys/*/*.private.enc
chmod 600 /var/lib/arca-dns/keys/_masterkey
```

### DNSSEC Validation Failures

**症状**: `dig +dnssec` が SERVFAIL や BOGUS になる。

**調査手順**:
1. 親ゾーンに DS が公開されているか: `dig example.com DS`
2. DNSKEY を確認: `dig example.com DNSKEY +dnssec`
3. RRSIG を確認: `dig example.com SOA +dnssec`
4. チェーン検証: `delv example.com SOA`

## 追加リソース

- [RFC 4033](https://tools.ietf.org/html/rfc4033) - DNS Security Introduction
- [RFC 4034](https://tools.ietf.org/html/rfc4034) - Resource Records for DNSSEC
- [RFC 4035](https://tools.ietf.org/html/rfc4035) - Protocol Modifications for DNSSEC
- [RFC 5155](https://tools.ietf.org/html/rfc5155) - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
- [RFC 6781](https://tools.ietf.org/html/rfc6781) - DNSSEC Operational Practices

---

**Version**: M4.1  
**Last Updated**: 2025-12-28

