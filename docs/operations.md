# arca-dns Operations Guide

English | [日本語](operations.ja.md)

## Day-2 Operations

This guide covers common operational tasks for maintaining arca-dns in production.

## Monitoring

### Health Checks

**Controller**:
```bash
# Liveness check
curl http://controller:8080/health

# Readiness check (includes backend connectivity)
curl http://controller:8080/ready

# Full status with metrics
curl http://controller:8080/status
```

**Agent**:
```bash
# Liveness check
curl http://agent:9090/health

# Readiness check (requires successful sync)
curl http://agent:9090/ready

# Full status with zone states
curl http://agent:9090/status
```

### Prometheus Metrics

**Controller metrics** (`http://controller:8080/metrics`):
- `api_requests_total`: API request count by method, path, status
- `api_request_duration_seconds`: API latency histogram
- `zones_total`: Current number of zones
- `dnssec_signing_duration_seconds`: DNSSEC signing latency
- `backend_operations_total`: Backend operation count by type, status

**Agent metrics** (`http://agent:9090/metrics`):
- `dns_queries_total`: DNS query count by type, rcode
- `dns_query_duration_seconds`: Query latency histogram
- `dns_udp_queries_total`, `dns_tcp_queries_total`: Transport breakdown
- `dns_queries_per_second`: Current QPS gauge
- `arca_dns_agent_sync_has_success`: Whether the agent has ever synced successfully (1/0)
- `arca_dns_agent_sync_stale`: Whether sync is currently stale (1/0)
- `arca_dns_agent_sync_last_success_timestamp_seconds`: Last successful sync time (unix timestamp; 0 if none)
- `arca_dns_agent_health_status`: Overall health status (1/0)
- `arca_dns_agent_health_check_status{type=...}`: Per-check health status (1/0)
- `arca_dns_agent_bgp_enabled`: Whether BGP control is enabled (1/0)
- `arca_dns_agent_bgp_routes_announced`: Whether routes are currently announced (1/0)
- `arca_dns_agent_bgp_last_change_timestamp_seconds`: Last successful route state change (unix timestamp; omitted if never)

### Log Monitoring

**Key log patterns**:
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

## Zone Management

### Adding a New Zone

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

### Updating a Zone

```bash
# Update SOA metadata. Existing records are preserved by this endpoint.
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

# Update a specific record through the record CRUD endpoint.
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

### Deleting a Zone

```bash
etag="$(curl -sI http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -X DELETE http://controller:8080/api/v1/zones/example.com. \
  -H "X-API-Key: your-api-key" \
  -H "If-Match: ${etag}"
```

### Viewing Zone Status

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

## DNSSEC Operations

### Generating Keys for a Zone

```bash
# Keys are auto-generated on first zone creation if DNSSEC enabled
# Manual generation:
arca-dns-controller dnssec generate-keys --zone example.com.
```

### Exporting DS Records

```bash
# BIND format (for parent zone file)
arca-dns-controller dnssec export-ds --zone example.com. --format bind

# JSON format (for API submission)
arca-dns-controller dnssec export-ds --zone example.com. --format json

# Output:
# example.com. IN DS 12345 13 2 ABC123...
```

### Key Rotation

Automated key rotation is not implemented in the current release. The DNSSEC scheduler re-signs zones before signatures expire, but it does not create new KSK/ZSK material.

**Manual rotation**:
```bash
# Enter a maintenance window first: pause DNSSEC scheduling and zone/record writes.
# generate-keys --rotate activates the new KSK/ZSK immediately.
arca-dns-controller dnssec generate-keys --zone example.com. --rotate

# Export new DS records
arca-dns-controller dnssec export-ds --zone example.com.

# Submit the new DS at the parent zone and keep the old DS until propagation.
# Then trigger re-signing as described in docs/dnssec.md.
# Resume scheduling and writes only after the new DS is visible and re-signing succeeds.

# After old signatures expire, remove inactive key files
arca-dns-controller dnssec remove-old-keys --zone example.com.
```

### Verifying DNSSEC

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

## Backup and Recovery

### Controller Backup

**SQLite Backend** (default):
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

### Controller Recovery

**SQLite Backend** (default):
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

### Agent Recovery

**Automatic**: Agents are stateless and re-sync from controller on restart.

**Manual zone restoration**:
```bash
# If controller is down, restore from backup
cp /backup/zones/*.zone.signed /var/lib/nsd/zones/
nsd-control reload
```

## Troubleshooting

### Controller Issues

**Issue**: API not responding
```bash
# Check service status
systemctl status arca-dns-controller

# Check logs
journalctl -u arca-dns-controller -n 100

# Check port binding
netstat -tlnp | grep 8080

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

**Issue**: DNSSEC signing failures
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

### Agent Issues

**Issue**: Zone sync failing
```bash
# Check controller connectivity
curl -I https://controller:8080/health

# Check API key
curl -H "X-API-Key: your-key" https://controller:8080/api/v1/zones

# Check sync status
curl http://localhost:9090/status | jq '.zones'

# Force sync
systemctl restart arca-dns-agent
```

**Issue**: BGP routes not announced
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

**Issue**: High DNS latency
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

### Common Error Patterns

| Error | Cause | Solution |
|-------|-------|----------|
| `backend connection failed` | DB/Git/etcd unreachable | Check backend service, credentials |
| `zone sync stale` | Controller unreachable >5min | Check network, controller status |
| `dnssec verification failed` | Invalid signature | Re-sign zone, check keys |
| `health check failed: nsd` | NSD crashed/not responding | Restart NSD, check config |
| `route not announced` | Health checks failing | Fix DNS issues, wait for recovery |
| `master key not found` | Missing ARCA_DNS_DNSSEC_MASTER_KEY_B64 (and no `_masterkey` file) | Set env var or enable auto-generate |

## Performance Tuning

### Controller Optimization

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

### Agent Optimization

**Zone sync interval**:
```yaml
# Reduce sync interval for faster updates (uses more bandwidth)
sync:
  sync_interval: 10s  # Default: 30s
```

**Health check frequency**:
```yaml
# Adjust based on failover requirements
health:
  check_interval: 5s  # Default: 10s
```

**DNSTap sampling**:
```yaml
# Reduce log volume
dnstap:
  sample_rate: 10000  # Log 1/10000 queries (default: 1/1000)
```

### NSD Tuning

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

### Unbound Tuning

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

## Security Maintenance

### API Key Rotation

```bash
# Generate new key
NEW_KEY=$(openssl rand -hex 32)
NEW_HASH=$(echo -n "$NEW_KEY" | sha256sum | cut -d' ' -f1)

# Update controller config
# Add new key while keeping old
api:
  auth:
    api_keys:
      old_admin: "sha256:OLD_HASH"
      new_admin: "sha256:$NEW_HASH"

# Reload controller
systemctl reload arca-dns-controller

# Update agents with new key
# Test new key works
curl -H "X-API-Key: $NEW_KEY" https://controller:8080/api/v1/zones

# Remove old key from config after migration
```

### Master Key Rotation

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

### Certificate Renewal

```bash
# Let's Encrypt example (reverse proxy / ingress termination)
certbot renew

# Reload reverse proxy / ingress (example)
systemctl reload nginx
```

## Scaling

### Adding More Agents

```bash
# Deploy new agent to additional site
# Follow deployment guide for agent setup

# Agent auto-discovers and syncs zones
# BGP routes announced automatically when healthy

# Verify from controller
curl -H "X-API-Key: $API_KEY" \
  https://controller:8080/api/v1/agents
```

### Scaling Controller (Active-Passive)

```bash
# Setup secondary controller with same config
# Point to same backend (MySQL/etcd)

# Use load balancer with health checks
# Or DNS failover

# Only one controller should run scheduler
# Set scheduler_enabled: false on standby
```

## Monitoring Alerts

### Recommended Prometheus Alerts

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

  - alert: BGPRouteDown
    expr: arca_dns_agent_bgp_enabled == 1 and arca_dns_agent_bgp_routes_announced == 0
    for: 1m

  - alert: HighDNSLatency
    expr: histogram_quantile(0.95, dns_query_duration_seconds) > 0.1
    for: 5m
```

## Next Steps

- [Architecture](architecture.md): System design details
- [Deployment](deployment.md): Deployment procedures
- [API Reference](api.md): API documentation
