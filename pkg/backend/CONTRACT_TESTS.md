# Backend Contract Tests

This directory contains contract tests that verify all backend implementations comply with the ZoneStore interface contracts.

## Test Structure

Contract tests are organized into reusable test suites that validate specific interface behaviors:

1. **RunZoneStoreCRUDSuite** - Core CRUD operations, pagination, case-insensitivity, version changes
2. **RunTransactionalStoreSuite** - Commit/rollback, read-your-writes, dirty read prevention
3. **RunRevisionStoreSuite** - History retrieval, newest-first ordering, immutability, pagination
4. **RunWatchableStoreSuite** - Watch events (create/update/delete), zone filtering, cancellation, no history

## Running Contract Tests

### Memory, Git, and SQLite Backends (No External Dependencies)

```bash
# Run all contract tests (Memory + Git + SQLite)
go test -v -run Contract ./pkg/backend/

# Run specific backend
go test -v -run TestMemoryBackend_Contract ./pkg/backend/
go test -v -run TestGitBackend_Contract ./pkg/backend/
go test -v -run TestSQLiteBackend_Contract ./pkg/backend/
```

### PostgreSQL Backend (Requires PostgreSQL)

```bash
# Start PostgreSQL (Docker example)
docker run -d --name postgres-test \
  -e POSTGRES_PASSWORD=testpass \
  -e POSTGRES_DB=arca_dns_test \
  -p 5432:5432 \
  postgres:16

# Set DSN environment variable
export ARCA_POSTGRES_DSN="postgres://postgres:testpass@localhost:5432/arca_dns_test?sslmode=disable"

# Run PostgreSQL contract tests
go test -v -run TestPostgresBackend_Contract ./pkg/backend/

# Cleanup
docker rm -f postgres-test
```

### MySQL Backend (Requires MySQL)

```bash
# Start MySQL (Docker example)
docker run -d --name mysql-test \
  -e MYSQL_ROOT_PASSWORD=testpass \
  -e MYSQL_DATABASE=arca_dns_test \
  -p 3306:3306 \
  mysql:8.0

# Set DSN environment variable
export MYSQL_DSN="root:testpass@tcp(localhost:3306)/arca_dns_test?parseTime=true"

# Run MySQL contract tests
go test -v -tags=integration -run TestMySQLBackend_Contract ./pkg/backend/

# Cleanup
docker rm -f mysql-test
```

### Etcd Backend (Requires etcd)

```bash
# Start etcd (Docker example)
docker run -d --name etcd-test \
  -p 2379:2379 \
  quay.io/coreos/etcd:v3.5.0 \
  etcd \
  --listen-client-urls http://0.0.0.0:2379 \
  --advertise-client-urls http://localhost:2379

# Optional: Override endpoints
export ETCD_ENDPOINTS="localhost:2379"

# Run etcd contract tests
go test -v -tags=integration -run TestEtcdBackend_Contract ./pkg/backend/

# Cleanup
docker rm -f etcd-test
```

### Run All Backends (Including Integration Tests)

```bash
# Requires PostgreSQL, MySQL and etcd running
ARCA_POSTGRES_DSN="..." MYSQL_DSN="..." go test -v -tags=integration -run Contract ./pkg/backend/
```

## Contract Invariants Tested

### RunZoneStoreCRUDSuite (13 test cases)

- **CreateZone**: Basic zone creation with auto-generated serial/version
- **CreateZone_AlreadyExists**: Returns ErrZoneAlreadyExists for duplicates
- **GetZone**: Retrieve existing zone
- **GetZone_NotFound**: Returns ErrZoneNotFound for missing zones
- **GetZone_CaseInsensitive**: Case-insensitive zone name queries (e.g., "Example.COM" → "example.com.")
- **UpdateZone**: Version changes on every update (content-derived)
- **UpdateZone_OptimisticLocking**: Returns ErrConflict when expectedVersion mismatches
- **UpdateZone_OptionalVersionCheck**: Empty expectedVersion skips version check
- **UpdateZone_NotFound**: Returns ErrZoneNotFound when updating non-existent zone
- **DeleteZone**: Remove zone successfully
- **DeleteZone_NotFound**: Returns ErrZoneNotFound when deleting missing zone
- **ListZones_Multiple**: Deterministic ordering (sorted by name)
- **ListZones_Pagination**: Correct limit/offset behavior, no overlap, pagination consistency

### Timestamp Handling

- **CreatedAt**: Preserved across updates (uses `time.Equal()` to ignore monotonic clock)
- **UpdatedAt**: Changes on every update
- **Serial**: Auto-increments on update (YYYYMMDDnn format)

## Test Results

| Backend    | Status | Pass Rate | Notes |
|------------|--------|-----------|-------|
| SQLite     | ✅ PASS | 13/13 (100%) | Pure Go (no CGO), uses `:memory:` for tests |
| Memory     | ✅ PASS | 13/13 (100%) | Pure Go, no external deps (deprecated) |
| Git        | ✅ PASS | - | Uses temp directory (ZoneStoreCRUD + RevisionStore) |
| PostgreSQL | ⚠️ INTEGRATION | - | Requires PostgreSQL running (ARCA_POSTGRES_DSN) |
| MySQL      | ⚠️ INTEGRATION | - | Requires MySQL running (ZoneStoreCRUD + TransactionalStore) |
| etcd       | ⚠️ INTEGRATION | - | Requires etcd running (ZoneStoreCRUD + RevisionStore + WatchableStore) |

## Adding New Contract Tests

To add a new backend to contract testing:

1. Create `contract_<backend>_test.go`
2. Add `// +build integration` if external service required
3. Implement test function that calls `RunZoneStoreCRUDSuite(t, backend)`

Example:

```go
// +build integration

package backend

import "testing"

func TestNewBackend_Contract(t *testing.T) {
    backend, cleanup := setupNewBackend(t)
    defer cleanup()

    t.Run("ZoneStoreCRUD", func(t *testing.T) {
        RunZoneStoreCRUDSuite(t, backend)
    })
}
```

## Known Issues Fixed

1. **Memory backend case normalization**: Fixed to normalize zone names to lowercase with trailing dot
2. **Timestamp comparison**: Changed to use `time.Equal()` to handle JSON marshaling stripping monotonic clock
3. **Git backend timestamp preservation**: Fixed CreatedAt comparison in contract tests

## Future Work

- Add performance benchmarks for each backend
- Add concurrent access stress tests
