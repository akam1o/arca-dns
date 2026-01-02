# API Reference

The source of truth for the controller API is `api/openapi.yaml` (OpenAPI 3.0).

## Base URL

- API base: `http://<controller-host>:8080/api/v1`
- Health endpoints (no `/api/v1` prefix): `http://<controller-host>:8080`

## Authentication

If API auth is enabled in the controller config, requests must include an API key header:

```bash
X-API-Key: <api-key>
```

If auth is disabled, the header is not required.

## Endpoints

### Health

- `GET /health` (and `GET /api/v1/health`): liveness check
- `GET /ready` (and `GET /api/v1/ready`): readiness check
- `GET /status` (and `GET /api/v1/status`): basic status/version info

### Zones

- `POST /api/v1/zones` (JSON mode): create a zone
- `POST /api/v1/zones/raw` (Raw BIND mode): create a zone from a zone file
  - Query: `origin=<zone>` (optional; used when the zone file omits `$ORIGIN`)
- `GET /api/v1/zones`: list zones (`limit`, `offset`)
- `GET /api/v1/zones/:name`: get a zone (JSON)
- `PUT /api/v1/zones/:name`: update a zone (JSON)
  - Requires `If-Match: <etag>` for optimistic concurrency
- `DELETE /api/v1/zones/:name`: delete a zone

### Zone Artifacts (for agents)

- `GET /api/v1/zones/:name/signed`: download the signed zone file (BIND format)
  - Supports conditional fetch via `If-None-Match: <etag>`
  - Response headers include `ETag`, `X-Zone-Serial`, `X-Zone-Hash`

### DNSSEC

- `GET /api/v1/zones/:name/ds` (and `GET /api/v1/zones/:name/dnssec/ds`): get DS records for the parent zone

## Examples

Create a zone (JSON mode):

```bash
curl -X POST http://localhost:8080/api/v1/zones \
  -H 'Content-Type: application/json' \
  -H 'X-API-Key: your-api-key' \
  -d '{"name":"example.com.","soa":{"mname":"ns1.example.com.","rname":"admin.example.com.","refresh":3600,"retry":1800,"expire":604800,"minimum":86400},"records":[{"name":"@","type":"NS","ttl":3600,"value":"ns1.example.com."}]}'
```

Fetch a signed zone with ETag:

```bash
etag="$(curl -sI http://localhost:8080/api/v1/zones/example.com./signed | grep -i '^etag:' | awk '{print $2}' | tr -d '\r')"
curl -i http://localhost:8080/api/v1/zones/example.com./signed -H "If-None-Match: ${etag}"
```
