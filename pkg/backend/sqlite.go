package backend

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/akam1o/arca-dns/pkg/model"
)

// SQLiteBackend implements ZoneStore and TransactionalStore using SQLite.
// It uses modernc.org/sqlite (pure Go, no CGO required) for single-binary deployments.
// This is the default backend for development and small-scale production.
type SQLiteBackend struct {
	db  *sql.DB
	dsn string
}

// NewSQLiteBackend creates a new SQLite backend.
// DSN examples:
//   - "file:arca-dns.db" (file-based)
//   - "file::memory:?cache=shared" (in-memory, shared across connections)
//   - ":memory:" (in-memory, single connection)
func NewSQLiteBackend(dsn string) (*SQLiteBackend, error) {
	dsn = sqliteDSNWithDefaultPragmas(dsn)

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite: %w", err)
	}

	// SQLite performs best with limited connections in WAL mode
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping SQLite: %w", err)
	}

	return &SQLiteBackend{
		db:  db,
		dsn: dsn,
	}, nil
}

// HealthCheck verifies that SQLite is reachable without loading zone data.
func (s *SQLiteBackend) HealthCheck(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return fmt.Errorf("sqlite health check failed: %w", err)
	}
	return nil
}

func sqliteDSNWithDefaultPragmas(dsn string) string {
	defaults := []struct {
		name  string
		value string
	}{
		{name: "journal_mode", value: "journal_mode(wal)"},
		{name: "foreign_keys", value: "foreign_keys(1)"},
		{name: "busy_timeout", value: "busy_timeout(5000)"},
	}

	for _, pragma := range defaults {
		if sqliteDSNHasQueryOption(dsn, pragma.name) {
			continue
		}
		dsn += sqliteDSNQuerySeparator(dsn) + "_pragma=" + pragma.value
	}

	return dsn
}

func sqliteDSNHasQueryOption(dsn, option string) bool {
	queryIndex := strings.Index(dsn, "?")
	if queryIndex == -1 {
		return false
	}

	query := strings.ToLower(dsn[queryIndex+1:])
	return strings.Contains(query, strings.ToLower(option))
}

func sqliteDSNQuerySeparator(dsn string) string {
	if strings.HasSuffix(dsn, "?") || strings.HasSuffix(dsn, "&") {
		return ""
	}
	if strings.Contains(dsn, "?") {
		return "&"
	}
	return "?"
}

const sqliteSchemaSQL = `
	CREATE TABLE IF NOT EXISTS zones (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE NOT NULL,
		version TEXT NOT NULL,
		soa_mname TEXT NOT NULL,
		soa_rname TEXT NOT NULL,
		soa_serial INTEGER NOT NULL,
		soa_refresh INTEGER NOT NULL,
		soa_retry INTEGER NOT NULL,
		soa_expire INTEGER NOT NULL,
		soa_minimum INTEGER NOT NULL,
		dnssec_enabled INTEGER DEFAULT 0,
		dnssec_algorithm INTEGER,
		dnssec_ksk_key_tag INTEGER,
		dnssec_zsk_key_tag INTEGER,
		dnssec_nsec3_enabled INTEGER DEFAULT 0,
		dnssec_nsec3_iterations INTEGER,
		dnssec_nsec3_salt TEXT,
		dnssec_signature_expiration TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL
	);
	CREATE TABLE IF NOT EXISTS records (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		ttl INTEGER NOT NULL,
		value TEXT NOT NULL,
		value_hash TEXT NOT NULL,
		priority INTEGER,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	CREATE INDEX IF NOT EXISTS idx_zones_version ON zones(version);
	CREATE INDEX IF NOT EXISTS idx_zones_updated ON zones(updated_at);
	CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id);
	CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(zone_id, name, type);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_records_unique ON records(zone_id, name, type, ttl, value_hash);
	`

// InitSchema creates the database schema inline (for in-memory or first-run usage).
func (s *SQLiteBackend) InitSchema() error {
	_, err := s.db.Exec(sqliteSchemaSQL)
	return err
}

// GetZone retrieves a zone by name.
func (s *SQLiteBackend) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	name = normalizeZoneName(name)

	zone, err := s.scanZone(ctx, s.db, name)
	if err != nil {
		return nil, err
	}

	records, err := s.loadRecordsDB(ctx, s.db, zone.Name)
	if err != nil {
		return nil, err
	}
	zone.Records = records

	return zone, nil
}

// ListZones returns all zones, optionally paginated.
func (s *SQLiteBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	offset := normalizeListOffset(opts.Offset)
	query := `
		SELECT
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		FROM zones
		ORDER BY name
	`
	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, opts.Limit, offset)
	} else if offset > 0 {
		query += " LIMIT -1 OFFSET ?"
		args = append(args, offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %w", err)
	}
	defer rows.Close()

	zones := make([]*model.Zone, 0)
	for rows.Next() {
		zone, err := s.scanZoneRow(rows)
		if err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating zones: %w", err)
	}

	if err := s.loadRecordsForZonesDB(ctx, s.db, zones); err != nil {
		return nil, err
	}

	return zones, nil
}

// ListZoneSummaries returns zone names and versions without loading records.
func (s *SQLiteBackend) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	offset := normalizeListOffset(opts.Offset)
	query := `
		SELECT name, version
		FROM zones
		ORDER BY name
	`
	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, opts.Limit, offset)
	} else if offset > 0 {
		query += " LIMIT -1 OFFSET ?"
		args = append(args, offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query zone summaries: %w", err)
	}
	defer rows.Close()

	summaries := make([]*ZoneSummary, 0)
	for rows.Next() {
		summary := &ZoneSummary{}
		if err := rows.Scan(&summary.Name, &summary.Version); err != nil {
			return nil, fmt.Errorf("failed to scan zone summary: %w", err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating zone summaries: %w", err)
	}

	return summaries, nil
}

// CreateZone creates a new zone.
func (s *SQLiteBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	writeZone, err := prepareZoneForCreate(zone, normalizeZoneName)
	if err != nil {
		return err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	zoneID, err := s.insertZoneTx(ctx, tx, writeZone)
	if err != nil {
		return err
	}

	if err := s.insertRecordsTx(ctx, tx, zoneID, writeZone.Records, nil); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	copyZoneInto(zone, writeZone)
	return nil
}

// UpdateZone updates an existing zone.
func (s *SQLiteBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)
	zone.UpdatedAt = time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Preserve CreatedAt and advance from the stored SOA serial, not client input.
	var createdAt, currentVersion string
	var currentSerial uint32
	err = tx.QueryRowContext(ctx, "SELECT created_at, soa_serial, version FROM zones WHERE name = ?", zone.Name).Scan(&createdAt, &currentSerial, &currentVersion)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("query zone: %w", err)
	}
	parsedCreatedAt, err := parseSQLiteTimeField("created_at", createdAt)
	if err != nil {
		return fmt.Errorf("query zone: %w", err)
	}
	zone.CreatedAt = parsedCreatedAt
	zone.SOA.Serial = updateSOASerial(currentSerial, zone.SOA.Serial)
	if err := ensureZoneUpdateVersion(zone, currentVersion); err != nil {
		return err
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	// CAS update
	query := `
		UPDATE zones SET
			version = ?,
			soa_mname = ?, soa_rname = ?, soa_serial = ?, soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?,
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ?
	`
	args := s.zoneUpdateArgs(zone)

	if expectedVersion != "" {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update zone: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		if expectedVersion != "" {
			// Zone exists (we already queried it above) but version didn't match
			return model.ErrConflict
		}
		return model.ErrZoneNotFound
	}

	// Get zone ID
	var zoneID int64
	if err := tx.QueryRowContext(ctx, "SELECT id FROM zones WHERE name = ?", zone.Name).Scan(&zoneID); err != nil {
		return fmt.Errorf("get zone ID: %w", err)
	}
	recordIDs, err := loadSQLRecordIDSet(ctx, tx, "SELECT id FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("load record IDs: %w", err)
	}

	// Replace records
	if _, err := tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID); err != nil {
		return fmt.Errorf("delete old records: %w", err)
	}
	if err := s.insertRecordsTx(ctx, tx, zoneID, zone.Records, recordIDs); err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateDNSSECMetadata updates DNSSEC metadata without changing zone version or SOA serial.
func (s *SQLiteBackend) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	name := normalizeZoneName(zoneName)

	query := `
		UPDATE zones SET
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ?
	`
	args := s.dnssecMetadataUpdateArgs(name, dnssec)

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update DNSSEC metadata: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		var exists bool
		if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", name).Scan(&exists); err != nil {
			return fmt.Errorf("check zone existence: %w", err)
		}
		if !exists {
			return model.ErrZoneNotFound
		}
	}
	return nil
}

// DeleteZone removes a zone and all its records.
func (s *SQLiteBackend) DeleteZone(ctx context.Context, name string) error {
	name = normalizeZoneName(name)

	result, err := s.db.ExecContext(ctx, "DELETE FROM zones WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return model.ErrZoneNotFound
	}
	return nil
}

// DeleteZoneWithVersion removes a zone only when its current version matches.
func (s *SQLiteBackend) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = ?"
	args := []interface{}{name}
	if expectedVersion != "" {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows > 0 {
		return nil
	}

	var exists bool
	if err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", name).Scan(&exists); err != nil {
		return fmt.Errorf("check zone existence: %w", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrZoneNotFound
}

// Close releases resources.
func (s *SQLiteBackend) Close() error {
	return s.db.Close()
}

// Info returns backend metadata.
func (s *SQLiteBackend) Info() BackendInfo {
	return BackendInfo{
		Type: "sqlite",
		Capabilities: []string{
			CapabilityZoneStore,
			CapabilityZoneSummaryStore,
			CapabilityHealthStore,
			CapabilityTransactionalStore,
			CapabilityDNSSECMetadataStore,
			CapabilityConditionalDeleteStore,
		},
		Consistency: "strong",
		Description: "SQLite storage (default, single-binary, WAL mode)",
	}
}

// BeginTx starts a new transaction (implements TransactionalStore).
func (s *SQLiteBackend) BeginTx(ctx context.Context) (Tx, error) {
	sqlTx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	return &sqliteTx{backend: s, tx: sqlTx}, nil
}

// --- internal helpers ---

type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

func (s *SQLiteBackend) scanZone(ctx context.Context, q querier, name string) (*model.Zone, error) {
	query := `
		SELECT
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		FROM zones WHERE name = ?
	`

	zone := &model.Zone{SOA: model.SOARecord{}}
	var dnssecEnabled, dnssecNSEC3Enabled int
	var dnssecAlgo, dnssecKSK, dnssecZSK, dnssecNSEC3Iter sql.NullInt64
	var dnssecSalt, dnssecSigExp sql.NullString
	var createdAt, updatedAt string

	err := q.QueryRowContext(ctx, query, name).Scan(
		&zone.Name, &zone.Version,
		&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
		&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
		&dnssecEnabled, &dnssecAlgo, &dnssecKSK, &dnssecZSK,
		&dnssecNSEC3Enabled, &dnssecNSEC3Iter, &dnssecSalt, &dnssecSigExp,
		&createdAt, &updatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("query zone: %w", err)
	}

	if err := applySQLiteZoneTimestamps(zone, createdAt, updatedAt); err != nil {
		return nil, fmt.Errorf("query zone: %w", err)
	}

	if dnssecEnabled != 0 {
		zone.DNSSEC = &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       uint8(dnssecAlgo.Int64),
			KSKKeyTag:       uint16(dnssecKSK.Int64),
			ZSKKeyTag:       uint16(dnssecZSK.Int64),
			NSEC3Enabled:    dnssecNSEC3Enabled != 0,
			NSEC3Iterations: uint16(dnssecNSEC3Iter.Int64),
			NSEC3Salt:       dnssecSalt.String,
		}
		if err := applySQLiteSignatureExpiration(zone.DNSSEC, dnssecSigExp); err != nil {
			return nil, fmt.Errorf("query zone: %w", err)
		}
	}

	return zone, nil
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func (s *SQLiteBackend) scanZoneRow(row scannable) (*model.Zone, error) {
	zone := &model.Zone{SOA: model.SOARecord{}}
	var dnssecEnabled, dnssecNSEC3Enabled int
	var dnssecAlgo, dnssecKSK, dnssecZSK, dnssecNSEC3Iter sql.NullInt64
	var dnssecSalt, dnssecSigExp sql.NullString
	var createdAt, updatedAt string

	if err := row.Scan(
		&zone.Name, &zone.Version,
		&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
		&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
		&dnssecEnabled, &dnssecAlgo, &dnssecKSK, &dnssecZSK,
		&dnssecNSEC3Enabled, &dnssecNSEC3Iter, &dnssecSalt, &dnssecSigExp,
		&createdAt, &updatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan zone: %w", err)
	}

	if err := applySQLiteZoneTimestamps(zone, createdAt, updatedAt); err != nil {
		return nil, err
	}

	if dnssecEnabled != 0 {
		zone.DNSSEC = &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       uint8(dnssecAlgo.Int64),
			KSKKeyTag:       uint16(dnssecKSK.Int64),
			ZSKKeyTag:       uint16(dnssecZSK.Int64),
			NSEC3Enabled:    dnssecNSEC3Enabled != 0,
			NSEC3Iterations: uint16(dnssecNSEC3Iter.Int64),
			NSEC3Salt:       dnssecSalt.String,
		}
		if err := applySQLiteSignatureExpiration(zone.DNSSEC, dnssecSigExp); err != nil {
			return nil, err
		}
	}

	return zone, nil
}

func (s *SQLiteBackend) loadRecordsDB(ctx context.Context, q querier, zoneName string) ([]model.Record, error) {
	query := `
		SELECT r.id, r.name, r.type, r.ttl, r.value, r.priority
		FROM records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ?
		ORDER BY r.name, r.type, r.id
	`
	rows, err := q.QueryContext(ctx, query, zoneName)
	if err != nil {
		return nil, fmt.Errorf("query records: %w", err)
	}
	defer rows.Close()

	records := make([]model.Record, 0)
	for rows.Next() {
		var rec model.Record
		var id int64
		var priority sql.NullInt64
		if err := rows.Scan(&id, &rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		rec.ID = formatSQLRecordID(id)
		if priority.Valid {
			p := uint16(priority.Int64)
			rec.Priority = &p
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

func applySQLiteZoneTimestamps(zone *model.Zone, createdAt, updatedAt string) error {
	parsedCreatedAt, err := parseSQLiteTimeField("created_at", createdAt)
	if err != nil {
		return err
	}
	parsedUpdatedAt, err := parseSQLiteTimeField("updated_at", updatedAt)
	if err != nil {
		return err
	}
	zone.CreatedAt = parsedCreatedAt
	zone.UpdatedAt = parsedUpdatedAt
	return nil
}

func applySQLiteSignatureExpiration(dnssec *model.DNSSECConfig, value sql.NullString) error {
	if !value.Valid || value.String == "" {
		return nil
	}
	parsed, err := parseSQLiteTimeField("dnssec_signature_expiration", value.String)
	if err != nil {
		return err
	}
	dnssec.SignatureExpiration = &parsed
	return nil
}

func parseSQLiteTimeField(field string, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse %s: %w", field, err)
	}
	return parsed, nil
}

func (s *SQLiteBackend) loadRecordsForZonesDB(ctx context.Context, q querier, zones []*model.Zone) error {
	if len(zones) == 0 {
		return nil
	}

	recordsByZone := make(map[string][]model.Record, len(zones))
	for start := 0; start < len(zones); {
		end := sqlBatchEnd(start, len(zones))
		query := fmt.Sprintf(`
			SELECT z.name, r.id, r.name, r.type, r.ttl, r.value, r.priority
			FROM records r
			JOIN zones z ON r.zone_id = z.id
			WHERE z.name IN (%s)
			ORDER BY z.name, r.name, r.type, r.id
		`, sqlQuestionPlaceholders(end-start))

		rows, err := q.QueryContext(ctx, query, sqlZoneNameArgs(zones, start, end)...)
		if err != nil {
			return fmt.Errorf("query records for zones: %w", err)
		}

		for rows.Next() {
			var zoneName string
			var rec model.Record
			var id int64
			var priority sql.NullInt64
			if err := rows.Scan(&zoneName, &id, &rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
				rows.Close()
				return fmt.Errorf("scan record: %w", err)
			}
			rec.ID = formatSQLRecordID(id)
			if priority.Valid {
				p := uint16(priority.Int64)
				rec.Priority = &p
			}
			recordsByZone[zoneName] = append(recordsByZone[zoneName], rec)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate records for zones: %w", err)
		}
		rows.Close()
		start = end
	}

	assignZoneRecords(zones, recordsByZone)
	return nil
}

func (s *SQLiteBackend) insertZoneTx(ctx context.Context, tx *sql.Tx, zone *model.Zone) (int64, error) {
	query := `
		INSERT INTO zones (
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	dnssecEnabled := 0
	var dnssecAlgo, dnssecKSK, dnssecZSK interface{}
	dnssecNSEC3 := 0
	var dnssecNSEC3Iter interface{}
	var dnssecSalt, dnssecSigExp interface{}

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = 1
		dnssecAlgo = zone.DNSSEC.Algorithm
		dnssecKSK = zone.DNSSEC.KSKKeyTag
		dnssecZSK = zone.DNSSEC.ZSKKeyTag
		if zone.DNSSEC.NSEC3Enabled {
			dnssecNSEC3 = 1
		}
		dnssecNSEC3Iter = zone.DNSSEC.NSEC3Iterations
		dnssecSalt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSigExp = zone.DNSSEC.SignatureExpiration.Format(time.RFC3339Nano)
		}
	}

	result, err := tx.ExecContext(ctx, query,
		zone.Name, zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgo, dnssecKSK, dnssecZSK,
		dnssecNSEC3, dnssecNSEC3Iter, dnssecSalt, dnssecSigExp,
		zone.CreatedAt.Format(time.RFC3339Nano), zone.UpdatedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		if isSQLiteConstraintError(err) {
			return 0, model.ErrZoneAlreadyExists
		}
		return 0, fmt.Errorf("insert zone: %w", err)
	}

	return result.LastInsertId()
}

func (s *SQLiteBackend) insertRecordsTx(ctx context.Context, tx *sql.Tx, zoneID int64, records []model.Record, allowedRecordIDs sqlRecordIDSet) error {
	if len(records) == 0 {
		return nil
	}

	autoIDQuery := `INSERT INTO records (zone_id, name, type, ttl, value, value_hash, priority) VALUES (?, ?, ?, ?, ?, ?, ?)`
	autoIDStmt, err := tx.PrepareContext(ctx, autoIDQuery)
	if err != nil {
		return fmt.Errorf("prepare record insert: %w", err)
	}
	defer autoIDStmt.Close()

	explicitIDQuery := `INSERT INTO records (id, zone_id, name, type, ttl, value, value_hash, priority) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	explicitIDStmt, err := tx.PrepareContext(ctx, explicitIDQuery)
	if err != nil {
		return fmt.Errorf("prepare record insert with id: %w", err)
	}
	defer explicitIDStmt.Close()

	for _, rec := range records {
		hash := sha256.Sum256([]byte(rec.Value))
		valueHash := hex.EncodeToString(hash[:])
		var priority interface{}
		if rec.Priority != nil {
			priority = *rec.Priority
		}

		if recordID, ok := parseSQLRecordID(rec.ID); ok && allowedRecordIDs.allows(recordID) {
			if _, err := explicitIDStmt.ExecContext(ctx, recordID, zoneID, rec.Name, rec.Type, rec.TTL, rec.Value, valueHash, priority); err != nil {
				return fmt.Errorf("insert record: %w", err)
			}
			continue
		}

		if _, err := autoIDStmt.ExecContext(ctx, zoneID, rec.Name, rec.Type, rec.TTL, rec.Value, valueHash, priority); err != nil {
			return fmt.Errorf("insert record: %w", err)
		}
	}
	return nil
}

func (s *SQLiteBackend) zoneUpdateArgs(zone *model.Zone) []interface{} {
	dnssecEnabled := 0
	var dnssecAlgo, dnssecKSK, dnssecZSK interface{}
	dnssecNSEC3 := 0
	var dnssecNSEC3Iter interface{}
	var dnssecSalt, dnssecSigExp interface{}

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = 1
		dnssecAlgo = zone.DNSSEC.Algorithm
		dnssecKSK = zone.DNSSEC.KSKKeyTag
		dnssecZSK = zone.DNSSEC.ZSKKeyTag
		if zone.DNSSEC.NSEC3Enabled {
			dnssecNSEC3 = 1
		}
		dnssecNSEC3Iter = zone.DNSSEC.NSEC3Iterations
		dnssecSalt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSigExp = zone.DNSSEC.SignatureExpiration.Format(time.RFC3339Nano)
		}
	}

	return []interface{}{
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgo, dnssecKSK, dnssecZSK,
		dnssecNSEC3, dnssecNSEC3Iter, dnssecSalt, dnssecSigExp,
		zone.UpdatedAt.Format(time.RFC3339Nano),
		zone.Name,
	}
}

func (s *SQLiteBackend) dnssecMetadataUpdateArgs(zoneName string, dnssec *model.DNSSECConfig) []interface{} {
	enabled, algorithm, kskKeyTag, zskKeyTag, nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration := dnssecColumnValues(dnssec)

	dnssecEnabled := 0
	if enabled {
		dnssecEnabled = 1
	}
	dnssecNSEC3Enabled := 0
	if nsec3Enabled {
		dnssecNSEC3Enabled = 1
	}
	if expiration, ok := signatureExpiration.(*time.Time); ok {
		signatureExpiration = expiration.Format(time.RFC3339Nano)
	}

	return []interface{}{
		dnssecEnabled, algorithm, kskKeyTag, zskKeyTag,
		dnssecNSEC3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration,
		time.Now().Format(time.RFC3339Nano),
		zoneName,
	}
}

func isSQLiteConstraintError(err error) bool {
	return strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// --- Transaction implementation ---

type sqliteTx struct {
	backend *SQLiteBackend
	tx      *sql.Tx
}

func (t *sqliteTx) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	name = normalizeZoneName(name)
	zone, err := t.backend.scanZone(ctx, t.tx, name)
	if err != nil {
		return nil, err
	}
	records, err := t.backend.loadRecordsDB(ctx, t.tx, zone.Name)
	if err != nil {
		return nil, err
	}
	zone.Records = records
	return zone, nil
}

func (t *sqliteTx) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	offset := normalizeListOffset(opts.Offset)
	query := `
		SELECT
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		FROM zones ORDER BY name
	`
	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, opts.Limit, offset)
	} else if offset > 0 {
		query += " LIMIT -1 OFFSET ?"
		args = append(args, offset)
	}

	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query zones: %w", err)
	}
	defer rows.Close()

	zones := make([]*model.Zone, 0)
	for rows.Next() {
		zone, err := t.backend.scanZoneRow(rows)
		if err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zones: %w", err)
	}

	if err := t.backend.loadRecordsForZonesDB(ctx, t.tx, zones); err != nil {
		return nil, err
	}
	return zones, nil
}

func (t *sqliteTx) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	offset := normalizeListOffset(opts.Offset)
	query := `
		SELECT name, version
		FROM zones
		ORDER BY name
	`
	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, opts.Limit, offset)
	} else if offset > 0 {
		query += " LIMIT -1 OFFSET ?"
		args = append(args, offset)
	}

	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query zone summaries: %w", err)
	}
	defer rows.Close()

	summaries := make([]*ZoneSummary, 0)
	for rows.Next() {
		summary := &ZoneSummary{}
		if err := rows.Scan(&summary.Name, &summary.Version); err != nil {
			return nil, fmt.Errorf("scan zone summary: %w", err)
		}
		summaries = append(summaries, summary)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zone summaries: %w", err)
	}
	return summaries, nil
}

func (t *sqliteTx) CreateZone(ctx context.Context, zone *model.Zone) error {
	writeZone, err := prepareZoneForCreate(zone, normalizeZoneName)
	if err != nil {
		return err
	}

	zoneID, err := t.backend.insertZoneTx(ctx, t.tx, writeZone)
	if err != nil {
		return err
	}
	if err := t.backend.insertRecordsTx(ctx, t.tx, zoneID, writeZone.Records, nil); err != nil {
		return err
	}
	copyZoneInto(zone, writeZone)
	return nil
}

func (t *sqliteTx) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)
	zone.UpdatedAt = time.Now()

	// Preserve CreatedAt and advance from the stored SOA serial, not client input.
	var createdAt, currentVersion string
	var currentSerial uint32
	err := t.tx.QueryRowContext(ctx, "SELECT created_at, soa_serial, version FROM zones WHERE name = ?", zone.Name).Scan(&createdAt, &currentSerial, &currentVersion)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("query zone: %w", err)
	}
	parsedCreatedAt, err := parseSQLiteTimeField("created_at", createdAt)
	if err != nil {
		return fmt.Errorf("query zone: %w", err)
	}
	zone.CreatedAt = parsedCreatedAt
	zone.SOA.Serial = updateSOASerial(currentSerial, zone.SOA.Serial)
	if err := ensureZoneUpdateVersion(zone, currentVersion); err != nil {
		return err
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	query := `
		UPDATE zones SET
			version = ?,
			soa_mname = ?, soa_rname = ?, soa_serial = ?, soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?,
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ?
	`
	args := t.backend.zoneUpdateArgs(zone)
	if expectedVersion != "" {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := t.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update zone: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		if expectedVersion != "" {
			return model.ErrConflict
		}
		return model.ErrZoneNotFound
	}

	var zoneID int64
	if err := t.tx.QueryRowContext(ctx, "SELECT id FROM zones WHERE name = ?", zone.Name).Scan(&zoneID); err != nil {
		return fmt.Errorf("get zone ID: %w", err)
	}
	recordIDs, err := loadSQLRecordIDSet(ctx, t.tx, "SELECT id FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("load record IDs: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID); err != nil {
		return fmt.Errorf("delete records: %w", err)
	}
	return t.backend.insertRecordsTx(ctx, t.tx, zoneID, zone.Records, recordIDs)
}

func (t *sqliteTx) DeleteZone(ctx context.Context, name string) error {
	name = normalizeZoneName(name)
	result, err := t.tx.ExecContext(ctx, "DELETE FROM zones WHERE name = ?", name)
	if err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows == 0 {
		return model.ErrZoneNotFound
	}
	return nil
}

func (t *sqliteTx) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = ?"
	args := []interface{}{name}
	if expectedVersion != "" {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := t.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rows > 0 {
		return nil
	}

	var exists bool
	if err := t.tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", name).Scan(&exists); err != nil {
		return fmt.Errorf("check zone existence: %w", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrZoneNotFound
}

func (t *sqliteTx) Close() error                       { return nil }
func (t *sqliteTx) Commit(ctx context.Context) error   { return t.tx.Commit() }
func (t *sqliteTx) Rollback(ctx context.Context) error { return t.tx.Rollback() }

func init() {
	RegisterBackend("sqlite", func(cfg map[string]interface{}) (ZoneStore, error) {
		dsn, _ := cfg["dsn"].(string)
		if dsn == "" {
			dsn = "file:arca-dns.db"
		}
		backend, err := NewSQLiteBackend(dsn)
		if err != nil {
			return nil, err
		}
		if err := backend.InitSchema(); err != nil {
			backend.Close()
			return nil, fmt.Errorf("init schema: %w", err)
		}
		return backend, nil
	})
}
