# Zone Version System

## Overview

The arca-dns zone version system provides a consistent, immutable identifier that ties together:

1. **API ETag**: Used for optimistic concurrency control in HTTP requests
2. **Artifact Filename**: Used by agents to track deployed zones
3. **Agent Applied State**: Used for rollback and audit purposes

This document describes the version scheme, how versions are generated, and how they're used throughout the system.

---

## Version Identifier Format

### Scheme

```
v{ULID}
```

Where:
- **ULID**: controller-issued ULID (time-sortable, 26 chars)

Additionally, arca-dns exposes a separate content hash:
- **hash**: First 8 characters of SHA256 hash of canonical zone content (returned as `X-Zone-Hash` and in metadata APIs)

### Examples

```
v01ARZ3NDEKTSV4RRFFQ69G5FAV
v01ARZ3NDEKTSV4RRFFQ69G5FB0
v01ARZ3NDEKTSV4RRFFQ69G5FB1
```

### Components

#### Serial Number

The serial is a 10-digit number following the format `YYYYMMDDnn`:

- **YYYY**: 4-digit year
- **MM**: 2-digit month (01-12)
- **DD**: 2-digit day (01-31)
- **nn**: 2-digit counter (00-99)

**Auto-increment behavior:**
- If the current date matches the date in the existing serial, increment `nn`
- If the current date is newer, reset to `{newdate}01`
- Maximum 100 updates per day per zone
- Serial wraps at 4294967295 (2^32 - 1) per RFC 1982

#### Hash

The hash is computed as follows:

```
hash = SHA256(canonical_zone_content)[:8]
```

Where `canonical_zone_content` is:
1. Zone name (lowercase)
2. SOA record (normalized)
3. All records sorted by:
   - Record name (alphabetically)
   - Record type (alphabetically)
   - Record value (alphabetically)
4. DNSSEC configuration (if enabled)

**Important**: The hash is computed BEFORE DNSSEC signing, ensuring consistent hashes across unsigned and signed versions.

---

## Version Generation

### Controller Process

When a zone is created or updated:

1. **Compute Serial**
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

2. **Canonicalize Zone**
   ```go
   canonical := canonicalizeZone(zone)
   ```

3. **Compute Hash**
   ```go
   h := sha256.Sum256([]byte(canonical))
   hash := hex.EncodeToString(h[:])[:8]
   ```

4. **Create Version**
   ```go
   version := fmt.Sprintf("v%d-%s", newSerial, hash)
   ```

5. **Store Version**
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

### Example Code

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

## Version Usage

### API ETag

The version is returned as an ETag header in HTTP responses:

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

### Artifact Filename

Signed zone files are stored with the version in the filename:

```
/var/lib/arca-dns/artifacts/example.com/v2024122801-a3f5c2e9.zone.signed
```

Metadata is stored alongside:

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

Agents track applied versions in local state:

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

## Concurrency Control

### Optimistic Locking with ETag

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

**Update Zone (Success):**
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

**Update Zone (Conflict):**
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

### Preventing Lost Updates

Without If-Match, updates may overwrite concurrent changes:

```
Time   Client A               Controller              Client B
----   --------               ----------              --------
T1     GET zone (v1)
T2                                                    GET zone (v1)
T3     PUT zone -> v2
T4                                                    PUT zone -> v3
                                                      (overwrites A's change!)
```

With If-Match, conflicts are detected:

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

## Version History and Rollback

### Backend Support

| Backend | Versioning | Mechanism |
|---------|-----------|-----------|
| Memory  | ❌ No     | Single current version only |
| MySQL   | ⚠️ Optional | Separate `zone_versions` table |
| Git     | ✅ Yes    | Git commits (native versioning) |
| etcd    | ✅ Yes    | Revision-based history |

### Rollback Process

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

**Note**: Rollback creates a NEW version with incremented serial, not a reversion to the old serial. This follows DNS best practices.

---

## Agent Synchronization

### Conditional Fetch Flow

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

Bandwidth saved: ~10KB per zone per sync interval

### Update Detection Flow

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

## Integrity Verification

### Checksum Verification

The agent verifies the SHA256 checksum of downloaded zones:

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

### Signature Verification (Optional)

When enabled, the controller signs artifacts with HMAC:

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

## Monitoring and Alerting

### Metrics

**Controller:**
- `arca_zone_version_created_total{zone}` - Total versions created
- `arca_zone_version_rollback_total{zone}` - Total rollbacks performed
- `arca_zone_version_conflict_total{zone}` - Total ETag conflicts

**Agent:**
- `arca_zone_version_current{zone,version}` - Current version per zone (gauge)
- `arca_zone_version_synced_total{zone}` - Total successful syncs
- `arca_zone_version_age_seconds{zone}` - Age of current version

### Alerts

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

## Best Practices

### Do:

✅ Always use If-Match for updates
✅ Store version in agent state for rollback
✅ Monitor version drift across agents
✅ Keep version history (backend permitting)
✅ Verify checksums on agent
✅ Use conditional fetch (If-None-Match) to save bandwidth

### Don't:

❌ Update zones without If-Match (risk of lost updates)
❌ Manually modify serial numbers (let controller auto-increment)
❌ Reuse old serial numbers (breaks RFC 1982)
❌ Skip checksum verification (risk of corruption)
❌ Delete all version history (keep rollback capability)

---

## Troubleshooting

### Symptoms and Solutions

**Problem**: ETag conflicts on every update
- **Cause**: Multiple clients updating same zone
- **Solution**: Implement retry with exponential backoff

**Problem**: Agent stuck on old version
- **Cause**: Sync failures, controller unreachable
- **Solution**: Check agent logs, controller connectivity

**Problem**: Version hash changes unexpectedly
- **Cause**: Record order changed (non-canonical)
- **Solution**: Ensure canonicalization before hashing

**Problem**: Serial number jumps forward unexpectedly
- **Cause**: Clock skew, date changed
- **Solution**: Verify system time, check NTP sync

---

## References

- RFC 1982: Serial Number Arithmetic
- RFC 7719: DNS Terminology
- HTTP ETag specification: RFC 7232
- SHA-256: FIPS 180-4
