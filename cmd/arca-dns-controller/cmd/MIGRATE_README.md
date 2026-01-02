# Migration Tools Usage Guide

This document provides best practices and important considerations for using the `migrate` commands.

## Quick Start

### Export zones to JSON files
```bash
arca-dns-controller migrate export --backend=mysql --dsn="root:pass@/dns" --output=./backup/
```

### Import zones from JSON files
```bash
arca-dns-controller migrate import --backend=git --path=/var/dns/repo --input=./backup/
```

### Direct copy between backends
```bash
arca-dns-controller migrate copy \
  --from-backend=mysql --from-dsn="root:pass@/source" \
  --to-backend=git --to-path=/var/dns/repo
```

## Important Considerations

### Version Recomputation

**All migrations recompute zone versions** using the content-derived formula:
```
version = v{serial}-{hash8}
```

This ensures consistency across backends but means:
- ✅ **Idempotent**: Same zone data always produces same version
- ✅ **Backend-independent**: Versions are portable
- ⚠️ **Not preserved**: Original versions are lost (but saved in JSON exports for audit)

### Overwrite Behavior

The `--overwrite` flag uses **delete + recreate** pattern:

```bash
# Without --overwrite (default): Skip existing zones
arca-dns-controller migrate import --backend=git --path=/repo --input=./backup/
# Output: "Skipped (exists): example.com."

# With --overwrite: Delete and recreate existing zones
arca-dns-controller migrate import --backend=git --path=/repo --input=./backup/ --overwrite
# Output: "Overwrote: example.com. (old version: v2024..., new version: v2024...)"
```

**⚠️ Critical**: Overwrite mode implications vary by backend:
- **Git**: Creates new delete + create commits (old commits remain in history)
- **etcd**: Delete operation preserves revision history for audit
- **MySQL**: Previous zone data is permanently deleted
- **Memory**: Previous zone data is permanently deleted

**⚠️ Non-atomic operation**: Delete happens before create. If create fails, the zone is lost from destination.

**Recommendation**:
1. Always run with `--dry-run` first
2. Take backups before using `--overwrite`
3. Consider using separate branches/databases for staging

### Dry-Run Mode

Preview operations without making changes:

```bash
# Preview export
arca-dns-controller migrate export --backend=mysql --dsn="..." --output=./test/ --dry-run

# Preview copy
arca-dns-controller migrate copy \
  --from-backend=mysql --from-dsn="..." \
  --to-backend=git --to-path=/repo \
  --dry-run
```

**Note**: Some backends (especially Git) may create directories during initialization even in dry-run mode for the **source** backend. This is a limitation of the backend implementation and affects read operations only.

### Record IDs

Record ID behavior during migration varies by backend:
- **Memory**: Always reassigns new sequential IDs (1, 2, 3...) - original IDs not preserved
- **MySQL**: Assigns new auto-increment IDs - original IDs not preserved
- **Git**: May preserve IDs in JSON files
- **etcd**: May preserve IDs in key-value store

**Impact**:
- Record IDs are **not guaranteed to be preserved** across migrations
- IDs are internal identifiers and do not affect zone functionality
- DNS record content and ordering are always preserved correctly

## Backend-Specific Notes

### Memory Backend
- No configuration required
- Perfect for testing migrations
- Data is lost when process exits

```bash
arca-dns-controller migrate copy --from-backend=mysql --from-dsn="..." --to-backend=memory
```

### MySQL Backend
- Requires `--dsn` flag or config file
- Format: `user:password@tcp(host:port)/database?parseTime=true`
- Supports separate `--from-dsn` and `--to-dsn` for copy operations

```bash
arca-dns-controller migrate copy \
  --from-backend=mysql --from-dsn="user:pass@tcp(prod:3306)/dns" \
  --to-backend=mysql --to-dsn="user:pass@tcp(staging:3306)/dns"
```

### Git Backend
- Requires `--path` flag or config file
- Creates repository and directories automatically
- Each zone is a separate JSON file
- Commits are created for each change

```bash
# Export from Git
arca-dns-controller migrate export --backend=git --path=/var/dns/repo --output=./backup/

# Copy between Git repos
arca-dns-controller migrate copy \
  --from-backend=git --from-path=/var/dns/prod \
  --to-backend=git --to-path=/var/dns/staging
```

**Limitation**: Git backend initialization may create directories even for read-only operations (export source, copy source). This is inherent to the Git backend design.

### etcd Backend
- Requires etcd cluster running
- Uses `localhost:2379` by default
- Configure endpoints via config file for production

```bash
# Requires etcd running on localhost:2379
arca-dns-controller migrate import --backend=etcd --input=./backup/
```

## Migration Workflows

### Backup and Restore

```bash
# 1. Backup production to JSON
arca-dns-controller migrate export \
  --backend=mysql --dsn="prod:pass@/dns" \
  --output=./backup-2024-01-01/

# 2. Verify backup (dry-run)
arca-dns-controller migrate import \
  --backend=memory --input=./backup-2024-01-01/ \
  --dry-run

# 3. Restore to new environment
arca-dns-controller migrate import \
  --backend=mysql --dsn="staging:pass@/dns" \
  --input=./backup-2024-01-01/
```

### Cross-Backend Migration

```bash
# 1. Dry-run to preview
arca-dns-controller migrate copy \
  --from-backend=mysql --from-dsn="..." \
  --to-backend=git --to-path=/repo \
  --dry-run

# 2. Perform migration
arca-dns-controller migrate copy \
  --from-backend=mysql --from-dsn="..." \
  --to-backend=git --to-path=/repo

# 3. Verify (count zones)
# In source:
mysql -e "SELECT COUNT(*) FROM zones"
# In destination:
ls /repo/zones/ | wc -l
```

### Testing Migrations

```bash
# 1. Export production data
arca-dns-controller migrate export --backend=mysql --dsn="prod..." --output=./prod-data/

# 2. Test import to memory (fast, no side effects)
arca-dns-controller migrate import --backend=memory --input=./prod-data/

# 3. Test import to staging
arca-dns-controller migrate import --backend=mysql --dsn="staging..." --input=./prod-data/

# 4. Verify versions are recomputed correctly
# (versions should be deterministic based on content)
```

## Error Handling

### Common Errors

**"zone already exists"**: Use `--overwrite` or handle manually
```bash
# Check what would be overwritten
arca-dns-controller migrate import --backend=git --path=/repo --input=./data/ --dry-run

# Overwrite existing zones
arca-dns-controller migrate import --backend=git --path=/repo --input=./data/ --overwrite
```

**"backend requires --dsn/--path flag"**: Provide required connection parameters
```bash
# Bad:
arca-dns-controller migrate export --backend=mysql --output=./backup/

# Good:
arca-dns-controller migrate export --backend=mysql --dsn="user:pass@/db" --output=./backup/
```

**"no zone files found"**: Check input directory
```bash
# Verify files exist
ls ./backup/*.json

# Ensure correct directory
arca-dns-controller migrate import --backend=memory --input=./backup/
```

## Production Checklist

Before production migration:

- [ ] Take full backups of source backend
- [ ] Run `--dry-run` mode first
- [ ] Test on staging environment
- [ ] Verify zone counts match (source vs destination)
- [ ] Check that versions are recomputed correctly
- [ ] Document backend-native history will be lost with `--overwrite`
- [ ] Plan for rollback if needed
- [ ] Schedule during maintenance window (if using `--overwrite`)
- [ ] Monitor backend health during and after migration

## Performance Considerations

- **Memory backend**: Fastest, suitable for testing
- **Git backend**: Slowest (file I/O + Git operations), suitable for small-medium datasets
- **MySQL/etcd**: Medium speed, suitable for large datasets

For large migrations (1000+ zones):
1. Consider exporting to JSON first
2. Split JSON files if needed
3. Import in batches
4. Monitor backend resource usage

## Support

For issues or questions:
- Check contract tests: `pkg/backend/CONTRACT_TESTS.md`
- Review test examples: `cmd/arca-dns-controller/cmd/migrate_e2e_test.go`
- File issues: GitHub repository
