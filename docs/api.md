# API Reference (Controller)

English | [日本語](api.ja.md)

The source of truth for the Controller API is `api/openapi.yaml` (OpenAPI 3.0). This document is a practical, human-friendly guide with common workflows and HTTP details.

## Base URL

- API base: `http://<controller-host>:8080/api/v1`
- Health/metrics base (also exposed under `/api/v1/*` as aliases): `http://<controller-host>:8080`

## Authentication

If API auth is enabled in the controller config, include an API key header on *protected* endpoints:

```http
X-API-Key: <api-key>
```

Health endpoints (`/health`, `/ready`, `/status`, `/metrics`) do not require auth.

## Data Model (Zone)

`Zone` JSON fields (see `pkg/model/zone.go`):

- `name` (string): zone FQDN (typically ends with a trailing dot, e.g. `example.com.`).
- `version` (string): unique version identifier (format `v{ULID}`), also used as `ETag`.
- `soa` (object): SOA fields (`mname`, `rname`, `serial`, `refresh`, `retry`, `expire`, `minimum`).
- `records` (array): resource records; each record has `name`, `type`, `ttl`, `value` (`id`/`priority` may appear depending on backend/type).
- `dnssec` (object, optional): DNSSEC configuration and signature expiration (when enabled).
- `created_at`, `updated_at` (RFC3339 timestamps).

Supported record types include: `A`, `AAAA`, `CNAME`, `MX`, `NS`, `TXT`, `PTR`, `SRV`, `CAA`.

## Error Response Format

Most API errors are returned as JSON:

```json
{
  "code": "INVALID_INPUT",
  "message": "Zone validation failed",
  "details": { "zone": "example.com." }
}
```

Error `code` values are defined in `pkg/model/errors.go` (e.g. `NOT_FOUND`, `ALREADY_EXISTS`, `INVALID_INPUT`, `CONFLICT`, `UNAUTHORIZED`, `RATE_LIMIT_EXCEEDED`).

## Concurrency Control (ETag / If-Match)

- Successful `POST /zones`, `GET /zones/:name`, and `PUT /zones/:name` return an `ETag` header (`ETag: <zone.version>`).
- `PUT /zones/:name` requires `If-Match: <etag>`; if the zone was updated concurrently, the API returns `409 Conflict`.
- `GET /zones/:name/signed` supports `If-None-Match: <etag>` and returns `304 Not Modified` (with `ETag` + metadata headers) when unchanged.
  - Note: `ETag` values are returned as quoted strings (e.g. `ETag: "<zone.version>"`). Clients should send the value back in `If-Match`/`If-None-Match` (quoted or unquoted are accepted).

For signed artifacts:
- `X-Zone-Hash` is the full SHA256 (hex) of the returned zone file body.
- `X-Zone-Hash8` is the first 8 characters of `X-Zone-Hash` (short form).

## Endpoints

### Health / Status / Metrics (no auth)

- `GET /health` (and `GET /api/v1/health`): liveness (`{"status":"ok"}`)
- `GET /ready` (and `GET /api/v1/ready`): readiness (`{"status":"ready"}` or `503 {"status":"not_ready","error":"..."}`)
- `GET /status` (and `GET /api/v1/status`): build info (`status`, `version`, `commit`, `date`)
- `GET /metrics` (and `GET /api/v1/metrics`): Prometheus metrics (may return `501` if metrics are disabled)

### Zones (JSON mode)

- `GET /zones?limit=<n>&offset=<n>`: list zones (paginated)
- `POST /zones`: create a zone
- `GET /zones/:name`: get a zone
- `PUT /zones/:name`: update a zone (requires `If-Match`)
- `DELETE /zones/:name`: delete a zone

Notes:
- `PUT` requires the JSON body `name` to match the `:name` path parameter.
- After create/update, the controller will attempt DNSSEC signing asynchronously (the request still succeeds even if signing fails; it is logged).

#### Record Operations (How to “hit” records)

Record changes are managed through record-specific endpoints. `PUT /zones/:name` updates SOA metadata and preserves existing records.

Endpoints:

- `GET /zones/:name/records`: list records for a zone
- `POST /zones/:name/records`: create a record
- `PUT /zones/:name/records/:id`: replace a record
- `DELETE /zones/:name/records/:id`: delete a record

Mutating record requests require `If-Match` with the current zone `ETag`; this uses the same optimistic locking model as zone updates.

Record fields:

- `name` (string): record name, relative to the zone origin (examples: `"@"`, `"www"`, `"mail.sub"`). The API currently checks only “non-empty”; keep it DNS-like.
- `type` (string): one of the supported types (see below).
- `ttl` (number): must be `> 0` and `<= 2147483647`.
- `value` (string): format depends on `type` (validated; see below).
- `id` (string, optional): backend-specific when stored; if a backend does not provide one, the API returns a deterministic ID derived from the record content for record CRUD.

#### Record Value Formats (Validation Rules)

The controller validates `record.value` based on `record.type` (see `pkg/model/validation.go`):

- `A`: IPv4 (example: `"192.0.2.1"`)
- `AAAA`: IPv6 (example: `"2001:db8::1"`)
- `CNAME`, `NS`, `PTR`: domain name (example: `"target.example.com."`)
- `MX`: `"priority domain"` (example: `"10 mail.example.com."`)
- `SRV`: `"priority weight port target"` (example: `"10 5 443 svc.example.com."`)
- `TXT`: any non-empty string up to 65535 chars (example: `"v=spf1 -all"`)
- `CAA`: `"flags tag value"` (example: `"0 issue letsencrypt.org"`)

Domain names accept a trailing dot or not (both are currently treated as valid); for clarity, prefer FQDNs with a trailing dot in `value`.

### Zones (Raw BIND mode)

- `POST /zones/raw`: create a zone by uploading a BIND zone file.

Supported content types:
- `text/plain`: request body is the zone file; supply `origin=<zone>` query parameter unless the file includes `$ORIGIN`.
- `multipart/form-data`: upload file field name `zonefile`; origin may be provided by form field `origin` or inferred from `<filename>.zone` when present.

Unsupported/rejected features (API returns `400`):
- `$GENERATE` directive
- `$INCLUDE` directive (disabled by default for security)
- unknown RR types (including DNSSEC record types in raw uploads)

### Zone Artifacts (for agents)

- `GET /zones/:name/signed`: download the signed zone file (BIND format)
  - Response headers include `ETag`, `X-Zone-Serial`, `X-Zone-Hash`, `Content-Disposition`.
  - If signing service is unavailable, the controller falls back to an unsigned generated zone file.

### DNSSEC

- `GET /zones/:name/ds` (alias: `GET /zones/:name/dnssec/ds`): DS records (plain text; one per line)
  - Returns `503` if signing service is not available.
  - Response headers include `X-Zone-Name`, `X-Zone-Version`.

## Examples (curl)

Set helpers:

```bash
BASE="http://localhost:8080/api/v1"
API_KEY="your-api-key" # only if auth is enabled
AUTH=(-H "X-API-Key: ${API_KEY}")
```

Create a zone (JSON):

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

List zones:

```bash
curl -s "${BASE}/zones?limit=100&offset=0" "${AUTH[@]}"
```

Update zone SOA metadata with optimistic locking:

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

List records:

```bash
curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}"
```

Add one record (example: `www A`):

```bash
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X POST "${BASE}/zones/example.com./records" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{"name":"www","type":"A","ttl":300,"value":"192.0.2.2"}'
```

Update a record:

```bash
record_id="$(curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X PUT "${BASE}/zones/example.com./records/${record_id}" \
  "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -H "If-Match: ${etag}" \
  -d '{"name":"www","type":"A","ttl":300,"value":"192.0.2.3"}'
```

Delete a record:

```bash
record_id="$(curl -s "${BASE}/zones/example.com./records" "${AUTH[@]}" | jq -r '.records[] | select(.name=="www" and .type=="A") | .id')"
etag="$(curl -sI "${BASE}/zones/example.com." "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

curl -i -X DELETE "${BASE}/zones/example.com./records/${record_id}" \
  "${AUTH[@]}" \
  -H "If-Match: ${etag}"
```

Create a zone (raw text/plain):

```bash
curl -i -X POST "${BASE}/zones/raw?origin=example.com." \
  "${AUTH[@]}" \
  -H 'Content-Type: text/plain' \
  --data-binary @example.com.zone
```

Create a zone (raw multipart/form-data):

```bash
curl -i -X POST "${BASE}/zones/raw" \
  "${AUTH[@]}" \
  -F "zonefile=@example.com.zone;filename=example.com.zone"
```

Fetch a signed zone with conditional request:

```bash
etag="$(curl -sI "${BASE}/zones/example.com./signed" "${AUTH[@]}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"
curl -i "${BASE}/zones/example.com./signed" "${AUTH[@]}" -H "If-None-Match: ${etag}"
```

Get DS records:

```bash
curl -i "${BASE}/zones/example.com./ds" "${AUTH[@]}"
```
