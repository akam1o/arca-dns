# arca-dns アーキテクチャ

[English](architecture.md) | 日本語

## 概要

arca-dns は、BGP Anycast とコントロール/データプレーン分離アーキテクチャを採用した DNS システムです。高可用性・セキュリティ・運用容易性を重視して設計されています。

## システム構成

```
┌─────────────────────────────────────────────────────────────┐
│                     Control Plane                            │
│                                                               │
│  ┌──────────────────────────────────────────────────────┐   │
│  │          arca-dns-controller                          │   │
│  │                                                        │   │
│  │  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │   │
│  │  │ REST API │  │  DNSSEC   │  │ Backend Storage   │  │   │
│  │  │          │  │  Signing  │  │ (Git/MySQL/etcd)  │  │   │
│  │  └────┬─────┘  └─────┬────┘  └─────────┬─────────┘  │   │
│  │       │              │                  │             │   │
│  │       └──────────────┴──────────────────┘             │   │
│  └──────────────────────────────────────────────────────┘   │
└────────────────────────────┬─────────────────────────────────┘
                             │ HTTPS + ETag
                             │ (Zone Sync)
        ┌────────────────────┴────────────────────┐
        │                                          │
┌───────▼──────────────────┐          ┌───────────▼─────────────┐
│   Data Plane (Site 1)    │          │  Data Plane (Site N)    │
│                           │          │                          │
│  arca-dns-agent           │          │  arca-dns-agent          │
│  ├─ Zone Sync             │          │  ├─ Zone Sync            │
│  ├─ NSD (Authoritative)   │          │  ├─ NSD (Authoritative)  │
│  ├─ Unbound (Recursive)   │          │  ├─ Unbound (Recursive)  │
│  ├─ BIRD (BGP Control)    │          │  ├─ BIRD (BGP Control)   │
│  └─ DNSTap Observability  │          │  └─ DNSTap Observability │
│           │               │          │           │              │
│           ▼               │          │           ▼              │
│    ┌──────────────┐       │          │    ┌──────────────┐     │
│    │ BGP Routers  │       │          │    │ BGP Routers  │     │
│    └──────────────┘       │          │    └──────────────┘     │
└───────────────────────────┘          └──────────────────────────┘
```

## コンポーネント内訳

### Control Plane: arca-dns-controller

**目的**: ゾーン管理の集中化、DNSSEC 署名、API サーバ。

**主要コンポーネント**:
1. **REST API**（`internal/controller/api/`）
   - ゾーン CRUD（JSON + Raw BIND）
   - 署名済みゾーンアーティファクト配布
   - DNSSEC 鍵管理エンドポイント
   - health/metrics エンドポイント

2. **DNSSEC 署名**（`pkg/dnssec/`）
   - 暗号化ストレージを伴う KSK/ZSK 管理
   - NSEC3 による自動署名
   - バックグラウンド再署名スケジューラ
   - 親ゾーン向け DS レコードのエクスポート

3. **Backend Storage**（`pkg/backend/`）
   - 差し替え可能なストレージ: Memory / MySQL / Git / etcd
   - capability ベースのインターフェイス
   - トランザクション（MySQL）、バージョニング（Git）、watch（etcd）

**データフロー**:
```
User → REST API → Validation → Backend Storage
                       ↓
                 DNSSEC Signing
                       ↓
              Artifact Generation
                       ↓
              Agent Distribution
```

### Data Plane: arca-dns-agent

**目的**: 自律的に DNS を提供し、ヘルス状態に基づいて BGP 経路を制御する。

**主要コンポーネント**:
1. **Zone Sync**（`internal/agent/sync/`）
   - controller からのゾーン同期（ETag / conditional GET）
   - チェックサム検証と整合性チェック
   - 原子的なファイル更新（tmp + rename）
   - バージョン履歴とロールバック支援

2. **NSD オーケストレーション**（`internal/agent/nsd/`）
   - 権威 DNS（NSD）の制御
   - ゾーンファイル配置と `nsd-control` による reload
   - `nsd-checkzone` を用いた事前検証
   - ヘルスチェックとプロセス監視

3. **Unbound オーケストレーション**（`internal/agent/unbound/`）
   - recursive resolver（Unbound）の制御
   - ローカル NSD 向け stub-zone 設定
   - EDNS バッファサイズの強制（ECMP 安全のため 1232）
   - ヘルスチェックと reload 管理

4. **BIRD BGP 制御**（`internal/agent/bird/`）
   - ヘルスに応じた経路 announce/withdraw
   - debounce を備えた状態機械（フラップ抑止）
   - 段階的劣化（レイテンシ悪化 vs ハード障害）
   - プロトコル単位の経路管理

5. **DNSTap 可観測性**（`internal/agent/dnstap/`）
   - Unix socket 経由のバイナリクエリログ
   - Prometheus メトリクスの export
   - サンプリングログ（レート設定可能）
   - type/rcode/transport 別の集計

**データフロー**:
```
Controller → Zone Sync → File Manager → NSD/Unbound
                                            ↓
                              Health Checker (5 layers)
                                            ↓
                              Health Engine → State Machine
                                            ↓
                              Route Manager → BIRD
                                            ↓
                              BGP Route Announcement
```

## 主要な設計判断

### 1. Control/Data Plane の分離

**狙い**:
- controller は単一インスタンスでも成立（運用がシンプル）
- agent は自律（controller 障害でも動作継続）
- 水平スケール（agent を足すだけで拡張）

**トレードオフ**:
- ゾーン更新は即時反映ではない（ポーリング）
- agent 側がやや複雑（自律性のため）
- ✅ 結果として信頼性と運用容易性が高い

### 2. DNSSEC 署名の集中化

**狙い**:
- agent が署名鍵へアクセスしない（セキュリティ）
- 全 Anycast site で一貫した署名
- 鍵ローテーションが一箇所で完結

**トレードオフ**:
- 配布前に controller が署名する必要
- site ごとの署名はできない（Anycast では通常不要）
- ✅ セキュリティと一貫性が高い

### 3. ETag によるポーリング同期

**狙い**:
- 常時接続を不要にする（ネットワークが簡単）
- HTTP キャッシュセマンティクス（304 Not Modified）
- agent が同期タイミングを制御（push の予期せぬ更新がない）

**トレードオフ**:
- 即時反映ではない（既定 30s）
- HTTP リクエスト数が増える（大半は 304）
- ✅ シンプルで帯域効率が良い

### 4. EDNS バッファ 1232

**狙い**:
- UDP フラグメントを抑止
- ECMP 安全（フラグメントが別経路に分散しうる）
- RFC 8899 推奨

**実装**: Unbound 設定で強制し、ヘルスチェックでも検証します。

### 5. ヘルスに基づく BGP 制御

**狙い**:
- 「壊れた DNS」は「DNS が無い」より悪い（速やかに withdraw）
- 段階的劣化（レイテンシ悪化 vs 全断）
- 部分障害が利用者影響に波及するのを防ぐ

**状態機械**:
```
Healthy → [3 failures] → Unhealthy (routes withdrawn)
Unhealthy → [3 successes] → Recovering → [30s + 3 more] → Healthy
Degraded: High latency but functional (routes stay up)
```

## データモデル

### Zone 構造
```go
type Zone struct {
    Name        string          // example.com.
    Version     string          // v01ARZ3NDEKTSV4RRFFQ69G5FAV
    SOA         SOARecord
    Records     []Record        // A, AAAA, MX, TXT, etc.
    DNSSEC      DNSSECConfig    // KSK/ZSK IDs, NSEC3 params
    UpdatedAt   time.Time
}
```

### バージョンシステム
- Version（ETag）: `v{ULID}`（controller 発行）
- Hash: SHA256（正規化ゾーン内容）の先頭 8 文字。`X-Zone-Hash` として公開
- 用途: ETag、conditional GET、アーティファクトファイル名、ロールバック

### アーティファクト構成
```
/var/lib/arca-dns/artifacts/
├── example.com/
│   ├── v01ARZ3NDEKTSV4RRFFQ69G5FAV.zone.signed  # BIND format
│   ├── v01ARZ3NDEKTSV4RRFFQ69G5FAV.json         # Metadata (optional)
│   └── latest -> v01ARZ3NDEKTSV4RRFFQ69G5FAV.zone.signed
```

## セキュリティモデル

### Controller のセキュリティ
1. **API 認証**: API キー
2. **レート制限**: クライアント単位（read/write 別）
3. **入力バリデーション**: サイズ制限、形式チェック
4. **監査ログ**: すべての API リクエストに request ID を付けて記録
5. **DNSSEC 鍵**: at-rest 暗号化（AES-256-GCM）

### Agent のセキュリティ
1. **TLS**: controller への mTLS（任意。通常は reverse proxy / ingress 側で終端）
2. **最小権限**: 読み取り中心の API アクセス
3. **ファイル権限**: ゾーンファイルに対する厳格な権限
4. **鍵の分離**: 署名鍵は controller から出ない

### ネットワークセキュリティ
1. **Anycast**: 複数 site による耐障害・DDoS 緩和
2. **BGP セキュリティ**: フィルタリング、prefix 検証
3. **DNS セキュリティ**: DNSSEC、クエリレート制限、EDNS 制限

## 可観測性

### メトリクス（Prometheus）
**Controller**:
- API レート/レイテンシ
- ゾーン数、更新頻度
- backend 操作
- DNSSEC 署名操作

**Agent**:
- ゾーン同期状態、staleness
- ヘルスチェック結果（5 レイヤ）
- BGP ルート状態
- DNS クエリメトリクス（DNSTap）

### ログ（構造化）
**Controller**:
- API 監査ログ
- ゾーン更新
- DNSSEC 操作
- backend エラー

**Agent**:
- ゾーン同期イベント
- ヘルス状態遷移
- BGP ルート変更
- DNS クエリ（サンプリング）

### トレーシング（任意）
- OpenTelemetry
- request ID 伝播
- コンポーネント間相関

## 運用ワークフロー

### ゾーン更新フロー
```
1. ユーザが API でゾーン作成/更新
2. controller が検証して保存
3. controller が DNSSEC 署名
4. controller が署名済みアーティファクトを生成
5. agent がポーリング（既定 30s）
6. ETag 変更時のみ取得
7. agent がチェックサムを検証
8. agent が原子的にゾーンを書き込み
9. agent が NSD を reload
10. agent がヘルス検証
11. healthy なら BGP 経路は維持
```

### 障害シナリオ

**Controller 障害**:
- agent は提供を継続（stale でも許容）
- 5 分超で sync を stale として扱う
- BGP 経路は維持（agent は自律）

**NSD クラッシュ**:
- ヘルスチェックが検知
- 連続 3 回失敗で状態遷移
- BGP 経路を withdraw
- NSD 復旧時に自動回復

**ネットワーク分断**:
- agent が controller に到達できない
- stale ゾーンを提供（ログに記録）
- BGP 経路は維持（ローカル DNS は動作）

**DNSSEC 鍵ローテーション**:
- 新しい KSK/ZSK を生成
- DNSKEY（旧+新）を公開
- TTL + 伝播を待つ
- 親ゾーンの DS を更新
- 旧鍵を削除

## 性能特性

### Controller
- **API レイテンシ**: ゾーン CRUD で p95 < 50ms
- **署名レイテンシ**: ゾーンあたり ~100ms（ECDSA P-256）
- **スループット**: 1000+ ゾーン（backend 依存）
- **backend**: Git（100s）、MySQL（10k+）、etcd（1k+）

### Agent
- **同期レイテンシ**: 既定 30s（設定可能）
- **reload**: NSD < 1s、Unbound < 2s
- **BGP 収束**: debounce 30s + ネットワーク伝播
- **処理能力**: agent あたり 50k+ QPS（NSD 依存）

### スケーリング
- **水平**: agent を追加（controller 変更不要）
- **地理分散**: agent をグローバルに配置（anycast）
- **backend**: MySQL は 10k+、Git は <100 目安

## 技術スタック

**Languages**: Go 1.21+

**Dependencies**:
- `miekg/dns`: DNS プロトコルライブラリ
- `gin-gonic/gin`: HTTP framework
- `go-git/go-git`: Git backend
- `go.etcd.io/etcd/client/v3`: etcd backend
- `go.uber.org/zap`: 構造化ロギング
- `github.com/dnstap/golang-dnstap`: DNSTap プロトコル

**External Services**:
- NSD（権威 DNS）
- Unbound（recursive DNS）
- BIRD（BGP daemon）
- Prometheus（metrics）
- MySQL / etcd / Git（storage）

## 今後の拡張

1. **Push 型同期**: WebSocket / gRPC streaming
2. **Multi-controller**: etcd 協調による active-active
3. **DNS-over-HTTPS/TLS**: DoH/DoT
4. **高度な RBAC**: ゾーン単位の権限
5. **Geo-steering**: クライアント地域に応じた応答
6. **クエリアナリティクス**: 異常検知など

