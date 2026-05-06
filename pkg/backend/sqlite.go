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
	// Append WAL mode and foreign keys pragmas if not already present
	if !strings.Contains(dsn, "_pragma") && !strings.Contains(dsn, "?") {
		dsn += "?_pragma=journal_mode(wal)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	} else if !strings.Contains(dsn, "journal_mode") {
		dsn += "&_pragma=journal_mode(wal)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	}

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

// InitSchema creates the database schema inline (for in-memory or first-run usage).
func (s *SQLiteBackend) InitSchema() error {
	schema := `
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
	_, err := s.db.Exec(schema)
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
		args = append(args, opts.Limit, opts.Offset)
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

	for _, zone := range zones {
		records, err := s.loadRecordsDB(ctx, s.db, zone.Name)
		if err != nil {
			return nil, err
		}
		zone.Records = records
	}

	return zones, nil
}

// CreateZone creates a new zone.
func (s *SQLiteBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	zone.Name = normalizeZoneName(zone.Name)

	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = generateSerial(0)
	}
	if zone.Version == "" {
		v, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = v
	}

	now := time.Now()
	zone.CreatedAt = now
	zone.UpdatedAt = now

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	zoneID, err := s.insertZoneTx(ctx, tx, zone)
	if err != nil {
		return err
	}

	if err := s.insertRecordsTx(ctx, tx, zoneID, zone.Records); err != nil {
		return err
	}

	return tx.Commit()
}

// UpdateZone updates an existing zone.
func (s *SQLiteBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)

	if zone.Version == "" || expectedVersion == "" || zone.Version == expectedVersion {
		v, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = v
	}
	zone.UpdatedAt = time.Now()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Preserve CreatedAt and advance from the stored SOA serial, not client input.
	var createdAt string
	var currentSerial uint32
	err = tx.QueryRowContext(ctx, "SELECT created_at, soa_serial FROM zones WHERE name = ?", zone.Name).Scan(&createdAt, &currentSerial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("query zone: %w", err)
	}
	zone.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	zone.SOA.Serial = generateSerial(currentSerial)

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

	// Replace records
	if _, err := tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID); err != nil {
		return fmt.Errorf("delete old records: %w", err)
	}
	if err := s.insertRecordsTx(ctx, tx, zoneID, zone.Records); err != nil {
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

// Close releases resources.
func (s *SQLiteBackend) Close() error {
	return s.db.Close()
}

// Info returns backend metadata.
func (s *SQLiteBackend) Info() BackendInfo {
	return BackendInfo{
		Type:         "sqlite",
		Capabilities: []string{"ZoneStore", "TransactionalStore", "DNSSECMetadataStore"},
		Consistency:  "strong",
		Description:  "SQLite storage (default, single-binary, WAL mode)",
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

	zone.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	zone.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)

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
		if dnssecSigExp.Valid && dnssecSigExp.String != "" {
			t, err := time.Parse(time.RFC3339Nano, dnssecSigExp.String)
			if err == nil {
				zone.DNSSEC.SignatureExpiration = &t
			}
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

	zone.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	zone.UpdatedAt, _ = time.Parse(time.RFC3339Nano, updatedAt)

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
		if dnssecSigExp.Valid && dnssecSigExp.String != "" {
			t, err := time.Parse(time.RFC3339Nano, dnssecSigExp.String)
			if err == nil {
				zone.DNSSEC.SignatureExpiration = &t
			}
		}
	}

	return zone, nil
}

func (s *SQLiteBackend) loadRecordsDB(ctx context.Context, q querier, zoneName string) ([]model.Record, error) {
	query := `
		SELECT r.name, r.type, r.ttl, r.value, r.priority
		FROM records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ?
		ORDER BY r.name, r.type
	`
	rows, err := q.QueryContext(ctx, query, zoneName)
	if err != nil {
		return nil, fmt.Errorf("query records: %w", err)
	}
	defer rows.Close()

	records := make([]model.Record, 0)
	for rows.Next() {
		var rec model.Record
		var priority sql.NullInt64
		if err := rows.Scan(&rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
			return nil, fmt.Errorf("scan record: %w", err)
		}
		if priority.Valid {
			p := uint16(priority.Int64)
			rec.Priority = &p
		}
		records = append(records, rec)
	}
	return records, rows.Err()
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

func (s *SQLiteBackend) insertRecordsTx(ctx context.Context, tx *sql.Tx, zoneID int64, records []model.Record) error {
	if len(records) == 0 {
		return nil
	}

	query := `INSERT INTO records (zone_id, name, type, ttl, value, value_hash, priority) VALUES (?, ?, ?, ?, ?, ?, ?)`
	stmt, err := tx.PrepareContext(ctx, query)
	if err != nil {
		return fmt.Errorf("prepare record insert: %w", err)
	}
	defer stmt.Close()

	for _, rec := range records {
		hash := sha256.Sum256([]byte(rec.Value))
		valueHash := hex.EncodeToString(hash[:])
		var priority interface{}
		if rec.Priority != nil && *rec.Priority > 0 {
			priority = *rec.Priority
		}
		if _, err := stmt.ExecContext(ctx, zoneID, rec.Name, rec.Type, rec.TTL, rec.Value, valueHash, priority); err != nil {
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
		args = append(args, opts.Limit, opts.Offset)
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

	for _, zone := range zones {
		records, err := t.backend.loadRecordsDB(ctx, t.tx, zone.Name)
		if err != nil {
			return nil, err
		}
		zone.Records = records
	}
	return zones, nil
}

func (t *sqliteTx) CreateZone(ctx context.Context, zone *model.Zone) error {
	zone.Name = normalizeZoneName(zone.Name)
	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = generateSerial(0)
	}
	if zone.Version == "" {
		v, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate version: %w", err)
		}
		zone.Version = v
	}
	now := time.Now()
	zone.CreatedAt = now
	zone.UpdatedAt = now

	zoneID, err := t.backend.insertZoneTx(ctx, t.tx, zone)
	if err != nil {
		return err
	}
	return t.backend.insertRecordsTx(ctx, t.tx, zoneID, zone.Records)
}

func (t *sqliteTx) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)

	if zone.Version == "" || expectedVersion == "" || zone.Version == expectedVersion {
		v, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate version: %w", err)
		}
		zone.Version = v
	}
	zone.UpdatedAt = time.Now()

	// Preserve CreatedAt and advance from the stored SOA serial, not client input.
	var createdAt string
	var currentSerial uint32
	err := t.tx.QueryRowContext(ctx, "SELECT created_at, soa_serial FROM zones WHERE name = ?", zone.Name).Scan(&createdAt, &currentSerial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("query zone: %w", err)
	}
	zone.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	zone.SOA.Serial = generateSerial(currentSerial)

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
	if _, err := t.tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID); err != nil {
		return fmt.Errorf("delete records: %w", err)
	}
	return t.backend.insertRecordsTx(ctx, t.tx, zoneID, zone.Records)
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
