# Zone Version System

English | [日本語](version-system.ja.md)

## Overview

arca-dns uses controller-issued zone versions to identify logical zone writes.
A zone version is stored in `Zone.Version` and is used by the zone JSON API for
optimistic concurrency control.

Zone versions are intentionally separate from:

- DNS SOA serials, which are DNS protocol metadata.
- Content hashes, which are checksums for integrity and cache validation.
- Signed artifact ETags, which are hashes of the signed zone file body.

This separation lets the controller issue a fresh write identifier while agents
can still validate the exact signed bytes they downloaded.

---

## Version Identifier Format

### Scheme

```text
v{ULID}
```

Where:

- `v` is a literal prefix.
- `ULID` is a 26-character monotonic ULID issued by the controller.

Examples:

```text
v01ARZ3NDEKTSV4RRFFQ69G5FAV
v01ARZ3NDEKTSV4RRFFQ69G5FB0
v01ARZ3NDEKTSV4RRFFQ69G5FB1
```

Important properties:

- Versions are sortable by creation time.
- Versions are unique for controller writes.
- Versions are not deterministic from zone content.
- Re-importing or re-copying the same zone data creates a new version when the
  destination backend writes the zone.

---

## Version Generation

The controller generates versions with `model.NewZoneVersion()`:

```go
func NewZoneVersion() (string, error) {
	id, err := util.NewULID(time.Now())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v%s", id), nil
}
```

Controller handlers assign a new version before persisting successful create,
update, raw import, and record mutation requests. Backends also generate a new
version when a caller creates or updates a zone without providing a trusted
precomputed controller version.

SOA serial handling is independent from the zone version. The serial may change
as part of normal DNS write processing, but it is not embedded in the version
identifier.

---

## API Usage

### Zone Resource ETags

The zone JSON endpoints use `Zone.Version` as the HTTP ETag.

```http
HTTP/1.1 200 OK
ETag: "v01ARZ3NDEKTSV4RRFFQ69G5FAV"
Content-Type: application/json
```

Clients should send that value back for optimistic locking:

```http
PUT /api/v1/zones/example.com.
If-Match: "v01ARZ3NDEKTSV4RRFFQ69G5FAV"
Content-Type: application/json
```

If the stored zone version no longer matches, the controller returns
`409 Conflict` and the client must re-read the zone before retrying.

### Signed Artifact ETags

The signed zone endpoints use a different ETag: the SHA256 hash of the signed
zone file body.

```http
HTTP/1.1 200 OK
ETag: "717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724"
X-Zone-Hash: 717fd0585d1c8d14254131e3d8ee338739570e5b078cda7e726ffd4e466f0724
X-Zone-Hash8: 717fd058
X-Zone-Serial: 2024122801
Content-Type: text/plain; charset=utf-8
```

`GET /api/v1/zones/:name/signed/metadata` returns both the logical zone version
and the artifact hash:

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

Agents store and send the signed artifact ETag for conditional fetches because
it validates the exact file that is deployed locally.

---

## Artifact Cache

When controller artifact caching is enabled, signed zone files are stored under a
safe zone directory and named with the logical zone version:

```text
/var/lib/arca-dns/artifacts/example.com/v01ARZ3NDEKTSV4RRFFQ69G5FAV.zone.signed
```

The filename identifies which logical zone write produced the cached artifact.
The artifact response ETag still remains the SHA256 hash of the file content.

---

## Concurrency Control

### Successful Update

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

### Conflict

```text
Client                    Controller
  | PUT /zones/example.com.   |
  | If-Match: "v01...FAV"     |
  |-------------------------->|
  | 409 Conflict              |
  |<--------------------------|
  | GET /zones/example.com.   |
  |-------------------------->|
  | retry with current ETag   |
```

Always use `If-Match` for mutating requests. Without it, a client can overwrite
another client's changes after reading stale data.

---

## Version History and Rollback

### Backend Support

| Backend    | Versioning | Mechanism |
|------------|------------|-----------|
| SQLite     | Optional   | `zone_versions` table |
| PostgreSQL | Optional   | `zone_versions` table |
| MySQL      | Optional   | `zone_versions` table |
| Git        | Yes        | Git commits and version trailers |
| etcd       | Yes        | etcd revisions |
| Memory     | No         | Current in-memory value only |

### Listing Versions

```http
GET /api/v1/zones/example.com./versions
```

Example response:

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

`hash` in revision metadata is content metadata. It is not part of the
controller-issued version identifier.

### Rollback

Rollback is implemented as a normal write of older zone data:

```http
GET /api/v1/zones/example.com./versions/v01ARZ3NDEKTSV4RRFFQ69G5FAV
GET /api/v1/zones/example.com.

PUT /api/v1/zones/example.com.
If-Match: "v01ARZ3NDEKTSV4RRFFQ69G5FB1"
Content-Type: application/json
```

The rollback write creates a new controller-issued version. It does not reuse
the old version string.

---

## Agent Synchronization

Agents list zones to discover zone names and logical versions, then fetch signed
artifacts conditionally.

```text
Agent                         Controller
  | GET /zones/example.com./signed      |
  | If-None-Match: "<artifact-sha256>"   |
  |------------------------------------>|
  | 304 Not Modified                    |
  |<------------------------------------|
  | no download, no reload              |
```

When an artifact changes:

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
  | verify checksum, write atomically, reload |
```

---

## Best Practices

- Treat `Zone.Version` as an opaque string.
- Use `If-Match` for zone mutations.
- Do not infer SOA serials or content hashes from version strings.
- Use signed artifact ETags and `X-Zone-Hash` to validate downloaded zone files.
- Keep version history where the backend supports it.
- During migration, expect destination writes to issue new versions.

---

## Troubleshooting

**ETag conflicts on every update**

Multiple clients are updating the same zone. Re-read the zone, merge changes,
and retry with the current ETag.

**Agent is stuck on an old artifact**

Check controller connectivity, signed artifact ETag handling, checksum
verification errors, and local reload failures.

**A re-imported zone has a different version**

This is expected. Versions are controller-issued write IDs, not deterministic
content IDs.

---

## References

- ULID: Universally Unique Lexicographically Sortable Identifier
- RFC 1982: Serial Number Arithmetic
- RFC 7232: HTTP Conditional Requests
- FIPS 180-4: SHA-256
