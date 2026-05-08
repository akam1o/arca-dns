# arca-dns 運用ガイド

[English](operations.md) | 日本語

## Day-2 運用

このガイドは、本番環境で arca-dns を運用するための一般的な作業をまとめます。

## 監視

### ヘルスチェック

**Controller**:
```bash
# Liveness check
curl http://controller:9053/health

# Readiness check (includes backend connectivity)
curl http://controller:9053/ready

# Full status with metrics
curl http://controller:9053/status
```

**Agent**:
```bash
# Liveness check
curl http://localhost:9090/health

# Readiness check (requires successful sync)
curl http://localhost:9090/ready

# Full status with zone states
curl http://localhost:9090/status
```

agent の status server はデフォルトで `127.0.0.1:9090` に bind します。
`/status` には zone 同期状態と BGP 状態が含まれるため、`metrics.listen`
をリモート公開する場合は firewall、tunnel、または認証済みの control plane
の背後に置いてください。

### Prometheus メトリクス

**Controller metrics**（`http://controller:9053/metrics`）:
- `api_requests_total`: method/path/status 別の API リクエスト数
- `api_request_duration_seconds`: API レイテンシのヒストグラム
- `zones_total`: 現在のゾーン数
- `dnssec_signing_duration_seconds`: DNSSEC 署名のレイテンシ
- `backend_operations_total`: backend 操作数（type/status 別）

**Agent metrics**（`http://localhost:9090/metrics`）:
- `dns_queries_total`: type/rcode 別のクエリ数
- `dns_query_duration_seconds`: クエリレイテンシのヒストグラム
- `dns_udp_queries_total`, `dns_tcp_queries_total`: transport 別
- `dns_queries_per_second`: 現在の QPS gauge
- `arca_dns_agent_sync_has_success`: これまでに同期成功したことがあるか（1/0）
- `arca_dns_agent_sync_stale`: 同期が stale かどうか（1/0）
- `arca_dns_agent_sync_last_success_timestamp_seconds`: 最終同期成功時刻（unix; 無ければ 0）
- `arca_dns_agent_health_status`: 全体ヘルス（1/0）
- `arca_dns_agent_health_check_status{type=...}`: チェック種別ごとのヘルス（1/0）
- `arca_dns_agent_bgp_enabled`: BGP 制御が有効か（1/0）
- `arca_dns_agent_bgp_routes_announced`: 現在 announce 中か（1/0）
- `arca_dns_agent_bgp_last_change_timestamp_seconds`: 最終ルート状態変更時刻（unix; 無ければ省略）

### ログ監視

**よく見るログパターン**:
```bash
# Controller: Zone updates
journalctl -u arca-dns-controller | grep "zone_updated"

# Controller: DNSSEC signing
journalctl -u arca-dns-controller | grep "dnssec_signed"

# Agent: Zone sync failures
journalctl -u arca-dns-agent | grep "sync_failed"

# Agent: BGP route changes
journalctl -u arca-dns-agent | grep "route_"

# Agent: Health failures
journalctl -u arca-dns-agent | grep "health_check_failed"
```

## ゾーン管理

### ゾーンを追加する

```bash
# Via API (JSON format)
curl -X POST http://controller:8080/api/v1/zones \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "example.com.",
    "soa": {
      "mname": "ns1.example.com.",
      "rname": "admin.example.com.",
      "refresh": 3600,
      "retry": 600,
      "expire": 604800,
      "minimum": 300
    },
    "records": [
      {"name": "@", "type": "NS", "ttl": 3600, "value": "ns1.example.com."},
      {"name": "@", "type": "A", "ttl": 300, "value": "192.0.2.1"},
      {"name": "www", "type": "A", "ttl": 300, "value": "192.0.2.1"}
    ]
  }'

# Via API (Raw BIND format)
curl -X POST http://controller:8080/api/v1/zones/raw \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: text/plain" \
  --data-binary @example.com.zone
```

### ゾーンを更新する

```bash
# SOA メタデータを更新する。このエンドポイントでは既存 records は保持されます。
etag="$(curl -sI http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -X PUT http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -H "If-Match: ${etag}" \
  -d '{
    "name": "example.com.",
    "soa": {
      "mname": "ns1.example.com.",
      "rname": "admin.example.com.",
      "refresh": 3600,
      "retry": 600,
      "expire": 604800,
      "minimum": 300
    }
  }'

# 特定の record は record CRUD エンドポイントで更新する。
record_id="$(curl -s http://controller:8080/api/v1/zones/example.com./records \
  -H "X-API-Key: your-api-key" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"
etag="$(curl -sI http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -X PUT "http://controller:8080/api/v1/zones/example.com./records/${record_id}" \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -H "If-Match: ${etag}" \
  -d '{"name": "www", "type": "A", "ttl": 300, "value": "192.0.2.100"}'
```

### ゾーンを削除する

```bash
etag="$(curl -sI http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -X DELETE http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" \
  -H "If-Match: ${etag}"
```

### ゾーン状態を確認する

```bash
# List all zones
curl http://controller:8080/api/v1/zones \
  -H "X-API-Key: your-api-key"

# Get specific zone
curl http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key"

# Get signed zone (what agents fetch)
curl http://controller:8080/api/v1/zones/example.com./signed \
  -H "X-API-Key: your-api-key"
```

## DNSSEC 運用

### ゾーンの鍵を生成する

```bash
# Keys are auto-generated on first zone creation if DNSSEC enabled
# Manual generation:
arca-dns-controller dnssec generate-keys --zone example.com.
```

### DS レコードをエクスポートする

```bash
# BIND format (for parent zone file)
arca-dns-controller dnssec export-ds --zone example.com. --format bind

# JSON format (for API submission)
arca-dns-controller dnssec export-ds --zone example.com. --format json

# Output:
# example.com. IN DS 12345 13 2 ABC123...
```

### 鍵ローテーション

現在のリリースでは自動鍵ローテーションは未実装です。DNSSEC scheduler は署名期限前の再署名を行いますが、新しい KSK/ZSK は生成しません。

**手動ローテーション**:
```bash
# 先に maintenance window に入り、DNSSEC scheduler と zone/record 書き込みを止める。
# generate-keys --rotate は新しい KSK/ZSK を即 active にする。
arca-dns-controller dnssec generate-keys --zone example.com. --rotate

# 新しい DS を出力する
arca-dns-controller dnssec export-ds --zone example.com.

# 親ゾーンに新 DS を提出し、伝播までは旧 DS も維持する。
# その後 docs/dnssec.ja.md の手順に従って再署名を発生させる。
# 新 DS が見えて再署名が成功してから scheduler と書き込みを再開する。

# 旧署名の期限切れ後、inactive な鍵ファイルを削除する
arca-dns-controller dnssec remove-old-keys --zone example.com.
```

### DNSSEC を検証する

```bash
# Check DNSKEY records
dig +dnssec DNSKEY example.com. @agent-ip

# Verify DS at parent
dig +dnssec DS example.com. @parent-ns

# Full chain validation
delv example.com. @agent-ip

# Validation with unbound-host
unbound-host -C /etc/unbound/unbound.conf -v example.com
```

## バックアップと復旧

### Controller のバックアップ

**SQLite Backend**（既定）:
```bash
# Backup database file
cp /var/lib/arca-dns/arca-dns.db arca_dns_backup_$(date +%Y%m%d).db

# Backup DNSSEC keys (encrypted)
tar -czf keys_backup_$(date +%Y%m%d).tar.gz \
  /var/lib/arca-dns/keys/ \
  /etc/arca-dns/master.key
```

**PostgreSQL Backend**:
```bash
# Backup database
pg_dump -U dns_user arca_dns > arca_dns_backup_$(date +%Y%m%d).sql

# Backup DNSSEC keys (encrypted)
tar -czf keys_backup_$(date +%Y%m%d).tar.gz \
  /var/lib/arca-dns/keys/ \
  /etc/arca-dns/master.key
```

**MySQL Backend**:
```bash
# Backup database
mysqldump -u dns_user -p arca_dns > arca_dns_backup_$(date +%Y%m%d).sql

# Backup DNSSEC keys (encrypted)
tar -czf keys_backup_$(date +%Y%m%d).tar.gz \
  /var/lib/arca-dns/keys/ \
  /etc/arca-dns/master.key
```

**Git Backend**:
```bash
# Clone repository (full backup)
git clone /var/lib/arca-dns/repo arca_dns_backup_$(date +%Y%m%d)

# Backup keys separately
tar -czf keys_backup_$(date +%Y%m%d).tar.gz \
  /var/lib/arca-dns/keys/ \
  /etc/arca-dns/master.key
```

**etcd Backend**:
```bash
# Snapshot etcd
etcdctl snapshot save arca_dns_backup_$(date +%Y%m%d).db

# Backup keys
tar -czf keys_backup_$(date +%Y%m%d).tar.gz \
  /var/lib/arca-dns/keys/ \
  /etc/arca-dns/master.key
```

### Controller の復旧

**SQLite Backend**（既定）:
```bash
# Restore database file
cp arca_dns_backup_20241228.db /var/lib/arca-dns/arca-dns.db

# Restore keys
tar -xzf keys_backup_20241228.tar.gz -C /
sudo chown -R arca-dns:arca-dns /var/lib/arca-dns/keys
sudo chmod 700 /var/lib/arca-dns/keys

# Restart controller
sudo systemctl restart arca-dns-controller
```

**PostgreSQL Backend**:
```bash
# Restore database
psql -U dns_user arca_dns < arca_dns_backup_20241228.sql

# Restore keys
tar -xzf keys_backup_20241228.tar.gz -C /
sudo chown -R arca-dns:arca-dns /var/lib/arca-dns/keys
sudo chmod 700 /var/lib/arca-dns/keys

# Restart controller
sudo systemctl restart arca-dns-controller
```

**MySQL Backend**:
```bash
# Restore database
mysql -u dns_user -p arca_dns < arca_dns_backup_20241228.sql

# Restore keys
tar -xzf keys_backup_20241228.tar.gz -C /
sudo chown -R arca-dns:arca-dns /var/lib/arca-dns/keys
sudo chmod 700 /var/lib/arca-dns/keys

# Restart controller
sudo systemctl restart arca-dns-controller
```

### Agent の復旧

**自動**: agent は stateless で、再起動時に controller から再同期します。

**手動でゾーンを復元**:
```bash
# If controller is down, restore from backup
cp /backup/zones/*.zone.signed /var/lib/nsd/zones/
nsd-control reload
```

## トラブルシューティング

### Controller の問題

**症状**: API が応答しない
```bash
# Check service status
systemctl status arca-dns-controller

# Check logs
journalctl -u arca-dns-controller -n 100

# Check port binding
netstat -tlnp | grep -E '8080|9053'

# Test backend connectivity
# SQLite:
ls -la /var/lib/arca-dns/arca-dns.db

# PostgreSQL:
psql -U dns_user -h localhost -c "SELECT 1"

# MySQL:
mysql -u dns_user -p -h localhost -e "SELECT 1"

# Git:
ls -la /var/lib/arca-dns/repo/.git
```

**症状**: DNSSEC 署名に失敗する
```bash
# Check keys exist
ls -la /var/lib/arca-dns/keys/

# Check master key
echo $ARCA_DNS_DNSSEC_MASTER_KEY_B64

# Check key permissions
stat /var/lib/arca-dns/keys/

# Check logs for specific error
journalctl -u arca-dns-controller | grep "dnssec_error"
```

### Agent の問題

**症状**: ゾーン同期が失敗する
```bash
# Check controller connectivity
curl -I http://controller:9053/health

# Check API key
curl -H "X-API-Key: your-key" https://controller:8080/api/v1/zones

# Check sync status
curl http://localhost:9090/status | jq '.zones'

# Force sync
systemctl restart arca-dns-agent
```

**症状**: BGP ルートが announce されない
```bash
# Check health status
curl http://localhost:9090/status | jq '.health'

# Check BIRD status
birdc show protocols
birdc show route

# Check NSD status
nsd-control status

# Check Unbound status
unbound-control status

# View agent logs
journalctl -u arca-dns-agent | grep -E '(health|bgp|route)'
```

**症状**: DNS レイテンシが高い
```bash
# Check DNSTap metrics
curl http://localhost:9090/metrics | grep dns_query_duration

# Test NSD directly
dig @127.0.0.1 -p 5353 example.com +dnssec

# Test Unbound directly
dig @127.0.0.1 example.com

# Check system load
top
iostat -x 1 10

# Check DNS query rate
tcpdump -i any -c 1000 'port 53' | wc -l
```

### 代表的なエラーパターン

| Error | Cause | Solution |
|-------|-------|----------|
| `backend connection failed` | DB/Git/etcd に到達不能 | backend サービス/認証情報を確認 |
| `zone sync stale` | controller 到達不能が 5 分超 | ネットワーク、controller 状態を確認 |
| `dnssec verification failed` | 署名が無効 | 再署名、鍵を確認 |
| `health check failed: nsd` | NSD がクラッシュ/応答なし | NSD 再起動、設定確認 |
| `route not announced` | ヘルスチェック不合格 | DNS 側を修正し回復を待つ |
| `master key not found` | `ARCA_DNS_DNSSEC_MASTER_KEY_B64` が無く `_masterkey` も無い | env 設定または自動生成を有効化 |

## 性能チューニング

### Controller 最適化

**MySQL backend**:
```sql
# Add indexes for common queries
CREATE INDEX idx_zone_name ON zones(name);
CREATE INDEX idx_updated_at ON zones(updated_at);

# Tune connection pool
SET GLOBAL max_connections = 200;
```

**API rate limits**:
```yaml
# Adjust in controller.yaml
api:
  rate_limit:
    read_rps: 200   # Increase for high-traffic
    write_rps: 20
    burst: 50
```

### Agent 最適化

**ゾーン同期間隔**:
```yaml
# Reduce sync interval for faster updates (uses more bandwidth)
sync:
  sync_interval: 10s  # Default: 30s
```

**ヘルスチェック頻度**:
```yaml
# Adjust based on failover requirements
health:
  check_interval: 5s  # Default: 10s
```

**DNSTap サンプリング**:
```yaml
# Reduce log volume
dnstap:
  sample_rate: 10000  # Log 1/10000 queries (default: 1/1000)
```

### NSD チューニング

```bash
# /etc/nsd/nsd.conf
server:
    server-count: 8          # Match CPU cores
    tcp-count: 250           # Concurrent TCP connections
    tcp-query-count: 50      # Queries per TCP connection
    tcp-timeout: 30          # TCP connection timeout
    ipv4-edns-size: 1232     # ECMP-safe
    ipv6-edns-size: 1232
```

### Unbound チューニング

```bash
# /etc/unbound/unbound.conf
server:
    num-threads: 8           # Match CPU cores
    msg-cache-size: 256m     # Message cache
    rrset-cache-size: 512m   # RRset cache
    outgoing-range: 8192     # Concurrent queries
    num-queries-per-thread: 4096
    jostle-timeout: 200      # Drop slow queries
```

## セキュリティメンテナンス

### API キーのローテーション

```bash
# admin key をローテーション
NEW_ADMIN_KEY=$(openssl rand -hex 32)
NEW_ADMIN_HASH=$(printf '%s' "$NEW_ADMIN_KEY" | sha256sum | cut -d' ' -f1)

# controller config を更新
# 既存の admin key と agent key を残したまま、新しい admin key を追加します。
# admin key を agent に配布しないでください。
api:
  auth:
    api_keys:
      old_admin: "sha256:OLD_ADMIN_HASH"
      new_admin: "sha256:$NEW_ADMIN_HASH"
      agent: "sha256:CURRENT_AGENT_HASH"
    api_key_roles:
      old_admin: "admin"
      new_admin: "admin"
      agent: "agent"

# controller を reload
systemctl reload arca-dns-controller

# 新しい admin key を確認
curl -H "X-API-Key: $NEW_ADMIN_KEY" https://controller:8080/api/v1/zones

# 移行後に old_admin を config から削除
```

```bash
# agent key は別にローテーション
NEW_AGENT_KEY=$(openssl rand -hex 32)
NEW_AGENT_HASH=$(printf '%s' "$NEW_AGENT_KEY" | sha256sum | cut -d' ' -f1)

# controller config を更新
# admin key を残し、agent key は両方 agent role にします。
api:
  auth:
    api_keys:
      admin: "sha256:CURRENT_ADMIN_HASH"
      old_agent: "sha256:OLD_AGENT_HASH"
      new_agent: "sha256:$NEW_AGENT_HASH"
    api_key_roles:
      admin: "admin"
      old_agent: "agent"
      new_agent: "agent"

# controller を reload してから、agent に NEW_AGENT_KEY を設定
systemctl reload arca-dns-controller

# 新しい agent key を同期用 view で確認
curl -H "X-API-Key: $NEW_AGENT_KEY" \
  "https://controller:8080/api/v1/zones?fields=summary"

# 全 agent の更新後に old_agent を config から削除
```

### マスターキーのローテーション

```bash
# Generate new master key
openssl rand -hex 32 > /etc/arca-dns/master.key.new

# Re-encrypt all DNSSEC keys with new master key
arca-dns-controller dnssec reencrypt-keys \
  --old-key-file /etc/arca-dns/master.key \
  --new-key-file /etc/arca-dns/master.key.new

# Replace old key
mv /etc/arca-dns/master.key /etc/arca-dns/master.key.old
mv /etc/arca-dns/master.key.new /etc/arca-dns/master.key

# Restart controller
systemctl restart arca-dns-controller
```

### 証明書更新

```bash
# Let's Encrypt example (reverse proxy / ingress termination)
certbot renew

# Reload reverse proxy / ingress (example)
systemctl reload nginx
```

## スケーリング

### agent を追加する

```bash
# Deploy new agent to additional site
# Follow deployment guide for agent setup

# Agent auto-discovers and syncs zones
# BGP routes announced automatically when healthy

# agent key で controller の同期用 view を読めることを確認
curl -H "X-API-Key: $ARCA_DNS_AGENT_API_KEY" \
  "https://controller:8080/api/v1/zones?fields=summary"
```

### controller のスケール（Active-Passive）

```bash
# Setup secondary controller with same config
# Point to same backend (MySQL/etcd)

# Use load balancer with health checks
# Or DNS failover

# Only one controller should run scheduler
# Set scheduler_enabled: false on standby
```

## 監視アラート

### 推奨 Prometheus アラート

```yaml
groups:
- name: arca-dns
  rules:
  # Controller alerts
  - alert: ControllerDown
    expr: up{job="arca-dns-controller"} == 0
    for: 1m

  - alert: HighAPILatency
    expr: histogram_quantile(0.95, api_request_duration_seconds) > 1
    for: 5m

  # Agent alerts
  - alert: ZoneSyncFailed
    expr: arca_dns_agent_sync_has_success == 0
    for: 5m

  - alert: HealthCheckFailing
    expr: arca_dns_agent_health_status == 0
    for: 2m
```
