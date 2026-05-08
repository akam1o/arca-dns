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

	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/mysql"
	_ "github.com/golang-migrate/migrate/v4/source/file"

	"github.com/akam1o/arca-dns/pkg/model"
)

// MySQLBackend implements ZoneStore and TransactionalStore using MySQL.
type MySQLBackend struct {
	db  *sql.DB
	dsn string
}

// NewMySQLBackend creates a new MySQL backend.
// DSN format: user:password@tcp(host:port)/dbname?parseTime=true
func NewMySQLBackend(dsn string) (*MySQLBackend, error) {
	return NewMySQLBackendWithPool(dsn, SQLPoolConfig{})
}

// NewMySQLBackendWithPool creates a new MySQL backend with connection pool settings.
func NewMySQLBackendWithPool(dsn string, pool SQLPoolConfig) (*MySQLBackend, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	applySQLPoolConfig(db, pool)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping MySQL: %w", err)
	}

	return &MySQLBackend{
		db:  db,
		dsn: dsn,
	}, nil
}

// RunMigrations applies database migrations.
func (m *MySQLBackend) RunMigrations(migrationsPath string) error {
	driver, err := mysql.WithInstance(m.db, &mysql.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration driver: %w", err)
	}

	mig, err := migrate.NewWithDatabaseInstance(
		"file://"+migrationsPath,
		"mysql",
		driver,
	)
	if err != nil {
		return fmt.Errorf("failed to create migrator: %w", err)
	}
	defer mig.Close()

	if err := mig.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	return nil
}

// GetZone retrieves a zone by name.
func (m *MySQLBackend) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	name = normalizeZoneName(name)

	query := `
		SELECT
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		FROM zones
		WHERE name = ?
	`

	zone := &model.Zone{
		SOA: model.SOARecord{},
	}

	var dnssecEnabled bool
	var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag sql.NullInt64
	var dnssecNSEC3Enabled bool
	var dnssecNSEC3Iterations sql.NullInt64
	var dnssecNSEC3Salt sql.NullString
	var dnssecSignatureExpiration sql.NullTime

	err := m.db.QueryRowContext(ctx, query, name).Scan(
		&zone.Name, &zone.Version,
		&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
		&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
		&dnssecEnabled, &dnssecAlgorithm, &dnssecKSKKeyTag, &dnssecZSKKeyTag,
		&dnssecNSEC3Enabled, &dnssecNSEC3Iterations, &dnssecNSEC3Salt, &dnssecSignatureExpiration,
		&zone.CreatedAt, &zone.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("failed to query zone: %w", err)
	}

	// Populate DNSSEC config if enabled
	if dnssecEnabled {
		zone.DNSSEC = &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       uint8(dnssecAlgorithm.Int64),
			KSKKeyTag:       uint16(dnssecKSKKeyTag.Int64),
			ZSKKeyTag:       uint16(dnssecZSKKeyTag.Int64),
			NSEC3Enabled:    dnssecNSEC3Enabled,
			NSEC3Iterations: uint16(dnssecNSEC3Iterations.Int64),
			NSEC3Salt:       dnssecNSEC3Salt.String,
		}
		if dnssecSignatureExpiration.Valid {
			zone.DNSSEC.SignatureExpiration = &dnssecSignatureExpiration.Time
		}
	}

	// Load records
	records, err := m.loadRecords(ctx, zone.Name)
	if err != nil {
		return nil, err
	}
	zone.Records = records

	return zone, nil
}

// loadRecords loads all records for a zone.
func (m *MySQLBackend) loadRecords(ctx context.Context, zoneName string) ([]model.Record, error) {
	query := `
		SELECT r.id, r.name, r.type, r.ttl, r.value, r.priority
		FROM records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ?
		ORDER BY r.name, r.type, r.id
	`

	rows, err := m.db.QueryContext(ctx, query, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer rows.Close()

	records := make([]model.Record, 0)
	for rows.Next() {
		var rec model.Record
		var id int64
		var priority sql.NullInt64

		if err := rows.Scan(&id, &rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}

		rec.ID = formatSQLRecordID(id)
		if priority.Valid {
			p := uint16(priority.Int64)
			rec.Priority = &p
		}

		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating records: %w", err)
	}

	return records, nil
}

// ListZones returns all zones, optionally paginated.
func (m *MySQLBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
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

	rows, err := m.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %w", err)
	}
	defer rows.Close()

	zones := make([]*model.Zone, 0)
	for rows.Next() {
		zone := &model.Zone{
			SOA: model.SOARecord{},
		}

		var dnssecEnabled bool
		var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag sql.NullInt64
		var dnssecNSEC3Enabled bool
		var dnssecNSEC3Iterations sql.NullInt64
		var dnssecNSEC3Salt sql.NullString
		var dnssecSignatureExpiration sql.NullTime

		if err := rows.Scan(
			&zone.Name, &zone.Version,
			&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
			&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
			&dnssecEnabled, &dnssecAlgorithm, &dnssecKSKKeyTag, &dnssecZSKKeyTag,
			&dnssecNSEC3Enabled, &dnssecNSEC3Iterations, &dnssecNSEC3Salt, &dnssecSignatureExpiration,
			&zone.CreatedAt, &zone.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan zone: %w", err)
		}

		// Populate DNSSEC config if enabled
		if dnssecEnabled {
			zone.DNSSEC = &model.DNSSECConfig{
				Enabled:         true,
				Algorithm:       uint8(dnssecAlgorithm.Int64),
				KSKKeyTag:       uint16(dnssecKSKKeyTag.Int64),
				ZSKKeyTag:       uint16(dnssecZSKKeyTag.Int64),
				NSEC3Enabled:    dnssecNSEC3Enabled,
				NSEC3Iterations: uint16(dnssecNSEC3Iterations.Int64),
				NSEC3Salt:       dnssecNSEC3Salt.String,
			}
			if dnssecSignatureExpiration.Valid {
				zone.DNSSEC.SignatureExpiration = &dnssecSignatureExpiration.Time
			}
		}

		zones = append(zones, zone)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating zones: %w", err)
	}

	// Load records for each zone (not optimal, but simple)
	for _, zone := range zones {
		records, err := m.loadRecords(ctx, zone.Name)
		if err != nil {
			return nil, err
		}
		zone.Records = records
	}

	return zones, nil
}

// ListZoneSummaries returns zone names and versions without loading records.
func (m *MySQLBackend) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	query := `
		SELECT name, version
		FROM zones
		ORDER BY name
	`

	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, opts.Limit, opts.Offset)
	}

	rows, err := m.db.QueryContext(ctx, query, args...)
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
func (m *MySQLBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	writeZone, err := prepareZoneForCreate(zone, normalizeZoneName)
	if err != nil {
		return err
	}

	if err := m.withRetry(ctx, func(ctx context.Context) error {
		return m.createZone(ctx, writeZone)
	}); err != nil {
		return err
	}
	copyZoneInto(zone, writeZone)
	return nil
}

func (m *MySQLBackend) createZone(ctx context.Context, zone *model.Zone) error {
	// Start transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := m.insertZone(ctx, tx, zone); err != nil {
		return err
	}

	return tx.Commit()
}

func (m *MySQLBackend) insertZone(ctx context.Context, tx *sql.Tx, zone *model.Zone) error {
	// Insert zone
	zoneQuery := `
		INSERT INTO zones (
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag interface{}
	var dnssecNSEC3Iterations interface{}
	var dnssecNSEC3Salt, dnssecSignatureExpiration interface{}
	dnssecEnabled := false
	dnssecNSEC3Enabled := false

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = true
		dnssecAlgorithm = zone.DNSSEC.Algorithm
		dnssecKSKKeyTag = zone.DNSSEC.KSKKeyTag
		dnssecZSKKeyTag = zone.DNSSEC.ZSKKeyTag
		dnssecNSEC3Enabled = zone.DNSSEC.NSEC3Enabled
		dnssecNSEC3Iterations = zone.DNSSEC.NSEC3Iterations
		dnssecNSEC3Salt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSignatureExpiration = zone.DNSSEC.SignatureExpiration
		}
	}

	result, err := tx.ExecContext(ctx, zoneQuery,
		zone.Name, zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag,
		dnssecNSEC3Enabled, dnssecNSEC3Iterations, dnssecNSEC3Salt, dnssecSignatureExpiration,
		zone.CreatedAt, zone.UpdatedAt,
	)

	if err != nil {
		if isMySQLDuplicateError(err) {
			return model.ErrZoneAlreadyExists
		}
		return fmt.Errorf("failed to insert zone: %w", err)
	}

	zoneID, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %w", err)
	}

	// Insert records
	if err := m.insertRecords(ctx, tx, zoneID, zone.Records, nil); err != nil {
		return err
	}

	return nil
}

// UpdateZone updates an existing zone.
func (m *MySQLBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	return m.withRetry(ctx, func(ctx context.Context) error {
		return m.updateZone(ctx, zone, expectedVersion)
	})
}

// UpdateDNSSECMetadata updates DNSSEC metadata without changing zone version or SOA serial.
func (m *MySQLBackend) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	return m.withRetry(ctx, func(ctx context.Context) error {
		return m.updateDNSSECMetadata(ctx, zoneName, dnssec)
	})
}

func (m *MySQLBackend) updateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	name := normalizeZoneName(zoneName)
	enabled, algorithm, kskKeyTag, zskKeyTag, nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration := dnssecColumnValues(dnssec)

	query := `
		UPDATE zones SET
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ?
	`

	result, err := m.db.ExecContext(ctx, query,
		enabled, algorithm, kskKeyTag, zskKeyTag,
		nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration,
		time.Now(), name,
	)
	if err != nil {
		return fmt.Errorf("failed to update DNSSEC metadata: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected == 0 {
		var exists bool
		err := m.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check zone existence: %w", err)
		}
		if !exists {
			return model.ErrZoneNotFound
		}
	}
	return nil
}

func (m *MySQLBackend) updateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// Start transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Advance from the stored SOA serial, not client input.
	var currentVersion string
	var currentSerial uint32
	err = tx.QueryRowContext(ctx, "SELECT version, soa_serial FROM zones WHERE name = ? FOR UPDATE", zone.Name).Scan(&currentVersion, &currentSerial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("failed to query zone serial: %w", err)
	}
	zone.SOA.Serial = updateSOASerial(currentSerial, zone.SOA.Serial)
	if err := ensureZoneUpdateVersion(zone, currentVersion); err != nil {
		return err
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	// Update zone. Add CAS condition only when an expected version is provided.
	zoneQuery := `
		UPDATE zones SET
			version = ?,
			soa_mname = ?, soa_rname = ?, soa_serial = ?, soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?,
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ?
	`

	var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag interface{}
	var dnssecNSEC3Iterations interface{}
	var dnssecNSEC3Salt, dnssecSignatureExpiration interface{}
	dnssecEnabled := false
	dnssecNSEC3Enabled := false

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = true
		dnssecAlgorithm = zone.DNSSEC.Algorithm
		dnssecKSKKeyTag = zone.DNSSEC.KSKKeyTag
		dnssecZSKKeyTag = zone.DNSSEC.ZSKKeyTag
		dnssecNSEC3Enabled = zone.DNSSEC.NSEC3Enabled
		dnssecNSEC3Iterations = zone.DNSSEC.NSEC3Iterations
		dnssecNSEC3Salt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSignatureExpiration = zone.DNSSEC.SignatureExpiration
		}
	}

	args := []interface{}{
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag,
		dnssecNSEC3Enabled, dnssecNSEC3Iterations, dnssecNSEC3Salt, dnssecSignatureExpiration,
		zone.UpdatedAt,
		zone.Name,
	}
	if expectedVersion != "" {
		zoneQuery += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := tx.ExecContext(ctx, zoneQuery, args...)

	if err != nil {
		return fmt.Errorf("failed to update zone: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// Check if zone exists
		var exists bool
		err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", zone.Name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check zone existence: %w", err)
		}
		if !exists {
			return model.ErrZoneNotFound
		}
		return model.ErrConflict
	}

	// Get zone ID
	var zoneID int64
	err = tx.QueryRowContext(ctx, "SELECT id FROM zones WHERE name = ?", zone.Name).Scan(&zoneID)
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %w", err)
	}
	recordIDs, err := loadSQLRecordIDSet(ctx, tx, "SELECT id FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to load record IDs: %w", err)
	}

	// Delete old records
	_, err = tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to delete old records: %w", err)
	}

	// Insert new records
	if err := m.insertRecords(ctx, tx, zoneID, zone.Records, recordIDs); err != nil {
		return err
	}

	return tx.Commit()
}

// DeleteZone removes a zone and all its records.
func (m *MySQLBackend) DeleteZone(ctx context.Context, name string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = ?"
	result, err := m.db.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return model.ErrZoneNotFound
	}

	return nil
}

// DeleteZoneWithVersion removes a zone only when its current version matches.
func (m *MySQLBackend) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	return m.withRetry(ctx, func(ctx context.Context) error {
		return m.deleteZoneWithVersion(ctx, name, expectedVersion)
	})
}

func (m *MySQLBackend) deleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = ?"
	args := []interface{}{name}
	if expectedVersion != "" {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := m.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected > 0 {
		return nil
	}

	var exists bool
	if err := m.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", name).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check zone existence: %w", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrZoneNotFound
}

// Close releases resources held by the backend.
func (m *MySQLBackend) Close() error {
	return m.db.Close()
}

// BeginTx starts a new transaction (implements TransactionalStore).
func (m *MySQLBackend) BeginTx(ctx context.Context) (Tx, error) {
	sqlTx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}

	return &MySQLTx{
		backend: m,
		tx:      sqlTx,
	}, nil
}

// MySQLTx implements the Tx interface for MySQL transactions.
type MySQLTx struct {
	backend *MySQLBackend
	tx      *sql.Tx
}

// GetZone retrieves a zone by name within the transaction.
func (t *MySQLTx) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	name = normalizeZoneName(name)

	query := `
		SELECT
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		FROM zones
		WHERE name = ?
		FOR UPDATE
	`

	zone := &model.Zone{
		SOA: model.SOARecord{},
	}

	var dnssecEnabled bool
	var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag sql.NullInt64
	var dnssecNSEC3Enabled bool
	var dnssecNSEC3Iterations sql.NullInt64
	var dnssecNSEC3Salt sql.NullString
	var dnssecSignatureExpiration sql.NullTime

	err := t.tx.QueryRowContext(ctx, query, name).Scan(
		&zone.Name, &zone.Version,
		&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
		&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
		&dnssecEnabled, &dnssecAlgorithm, &dnssecKSKKeyTag, &dnssecZSKKeyTag,
		&dnssecNSEC3Enabled, &dnssecNSEC3Iterations, &dnssecNSEC3Salt, &dnssecSignatureExpiration,
		&zone.CreatedAt, &zone.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("failed to query zone: %w", err)
	}

	// Populate DNSSEC config if enabled
	if dnssecEnabled {
		zone.DNSSEC = &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       uint8(dnssecAlgorithm.Int64),
			KSKKeyTag:       uint16(dnssecKSKKeyTag.Int64),
			ZSKKeyTag:       uint16(dnssecZSKKeyTag.Int64),
			NSEC3Enabled:    dnssecNSEC3Enabled,
			NSEC3Iterations: uint16(dnssecNSEC3Iterations.Int64),
			NSEC3Salt:       dnssecNSEC3Salt.String,
		}
		if dnssecSignatureExpiration.Valid {
			zone.DNSSEC.SignatureExpiration = &dnssecSignatureExpiration.Time
		}
	}

	// Load records
	records, err := t.loadRecords(ctx, zone.Name)
	if err != nil {
		return nil, err
	}
	zone.Records = records

	return zone, nil
}

// loadRecords loads all records for a zone within the transaction.
func (t *MySQLTx) loadRecords(ctx context.Context, zoneName string) ([]model.Record, error) {
	query := `
		SELECT r.id, r.name, r.type, r.ttl, r.value, r.priority
		FROM records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ?
		ORDER BY r.name, r.type, r.id
	`

	rows, err := t.tx.QueryContext(ctx, query, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer rows.Close()

	records := make([]model.Record, 0)
	for rows.Next() {
		var rec model.Record
		var id int64
		var priority sql.NullInt64

		if err := rows.Scan(&id, &rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}

		rec.ID = formatSQLRecordID(id)
		if priority.Valid {
			p := uint16(priority.Int64)
			rec.Priority = &p
		}

		records = append(records, rec)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating records: %w", err)
	}

	return records, nil
}

// ListZones returns all zones within the transaction.
func (t *MySQLTx) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	// Transaction version doesn't lock all zones (performance concern)
	// Just query normally
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

	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query zones: %w", err)
	}
	defer rows.Close()

	zones := make([]*model.Zone, 0)
	for rows.Next() {
		zone := &model.Zone{
			SOA: model.SOARecord{},
		}

		var dnssecEnabled bool
		var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag sql.NullInt64
		var dnssecNSEC3Enabled bool
		var dnssecNSEC3Iterations sql.NullInt64
		var dnssecNSEC3Salt sql.NullString
		var dnssecSignatureExpiration sql.NullTime

		if err := rows.Scan(
			&zone.Name, &zone.Version,
			&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
			&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
			&dnssecEnabled, &dnssecAlgorithm, &dnssecKSKKeyTag, &dnssecZSKKeyTag,
			&dnssecNSEC3Enabled, &dnssecNSEC3Iterations, &dnssecNSEC3Salt, &dnssecSignatureExpiration,
			&zone.CreatedAt, &zone.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan zone: %w", err)
		}

		// Populate DNSSEC config if enabled
		if dnssecEnabled {
			zone.DNSSEC = &model.DNSSECConfig{
				Enabled:         true,
				Algorithm:       uint8(dnssecAlgorithm.Int64),
				KSKKeyTag:       uint16(dnssecKSKKeyTag.Int64),
				ZSKKeyTag:       uint16(dnssecZSKKeyTag.Int64),
				NSEC3Enabled:    dnssecNSEC3Enabled,
				NSEC3Iterations: uint16(dnssecNSEC3Iterations.Int64),
				NSEC3Salt:       dnssecNSEC3Salt.String,
			}
			if dnssecSignatureExpiration.Valid {
				zone.DNSSEC.SignatureExpiration = &dnssecSignatureExpiration.Time
			}
		}

		zones = append(zones, zone)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating zones: %w", err)
	}

	// Load records for each zone
	for _, zone := range zones {
		records, err := t.loadRecords(ctx, zone.Name)
		if err != nil {
			return nil, err
		}
		zone.Records = records
	}

	return zones, nil
}

func (t *MySQLTx) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	query := `
		SELECT name, version
		FROM zones
		ORDER BY name
	`

	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT ? OFFSET ?"
		args = append(args, opts.Limit, opts.Offset)
	}

	rows, err := t.tx.QueryContext(ctx, query, args...)
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

// CreateZone creates a new zone within the transaction.
func (t *MySQLTx) CreateZone(ctx context.Context, zone *model.Zone) error {
	writeZone, err := prepareZoneForCreate(zone, normalizeZoneName)
	if err != nil {
		return err
	}

	if err := t.backend.insertZone(ctx, t.tx, writeZone); err != nil {
		return err
	}

	copyZoneInto(zone, writeZone)
	return nil
}

// UpdateZone updates an existing zone within the transaction.
func (t *MySQLTx) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// Advance from the stored SOA serial, not client input.
	var currentVersion string
	var currentSerial uint32
	err := t.tx.QueryRowContext(ctx, "SELECT version, soa_serial FROM zones WHERE name = ? FOR UPDATE", zone.Name).Scan(&currentVersion, &currentSerial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("failed to query zone serial: %w", err)
	}
	zone.SOA.Serial = updateSOASerial(currentSerial, zone.SOA.Serial)
	if err := ensureZoneUpdateVersion(zone, currentVersion); err != nil {
		return err
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	// Update zone. Add CAS condition only when an expected version is provided.
	zoneQuery := `
		UPDATE zones SET
			version = ?,
			soa_mname = ?, soa_rname = ?, soa_serial = ?, soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?,
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ?
	`

	var dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag interface{}
	var dnssecNSEC3Iterations interface{}
	var dnssecNSEC3Salt, dnssecSignatureExpiration interface{}
	dnssecEnabled := false
	dnssecNSEC3Enabled := false

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = true
		dnssecAlgorithm = zone.DNSSEC.Algorithm
		dnssecKSKKeyTag = zone.DNSSEC.KSKKeyTag
		dnssecZSKKeyTag = zone.DNSSEC.ZSKKeyTag
		dnssecNSEC3Enabled = zone.DNSSEC.NSEC3Enabled
		dnssecNSEC3Iterations = zone.DNSSEC.NSEC3Iterations
		dnssecNSEC3Salt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSignatureExpiration = zone.DNSSEC.SignatureExpiration
		}
	}

	args := []interface{}{
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag,
		dnssecNSEC3Enabled, dnssecNSEC3Iterations, dnssecNSEC3Salt, dnssecSignatureExpiration,
		zone.UpdatedAt,
		zone.Name,
	}
	if expectedVersion != "" {
		zoneQuery += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := t.tx.ExecContext(ctx, zoneQuery, args...)

	if err != nil {
		return fmt.Errorf("failed to update zone: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		// Check if zone exists
		var exists bool
		err := t.tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", zone.Name).Scan(&exists)
		if err != nil {
			return fmt.Errorf("failed to check zone existence: %w", err)
		}
		if !exists {
			return model.ErrZoneNotFound
		}
		return model.ErrConflict
	}

	// Get zone ID
	var zoneID int64
	err = t.tx.QueryRowContext(ctx, "SELECT id FROM zones WHERE name = ?", zone.Name).Scan(&zoneID)
	if err != nil {
		return fmt.Errorf("failed to get zone ID: %w", err)
	}
	recordIDs, err := loadSQLRecordIDSet(ctx, t.tx, "SELECT id FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to load record IDs: %w", err)
	}

	// Delete old records
	_, err = t.tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to delete old records: %w", err)
	}

	// Insert new records
	return t.backend.insertRecords(ctx, t.tx, zoneID, zone.Records, recordIDs)
}

// DeleteZone removes a zone within the transaction.
func (t *MySQLTx) DeleteZone(ctx context.Context, name string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = ?"
	result, err := t.tx.ExecContext(ctx, query, name)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}

	if rowsAffected == 0 {
		return model.ErrZoneNotFound
	}

	return nil
}

func (t *MySQLTx) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = ?"
	args := []interface{}{name}
	if expectedVersion != "" {
		query += " AND version = ?"
		args = append(args, expectedVersion)
	}

	result, err := t.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete zone: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected: %w", err)
	}
	if rowsAffected > 0 {
		return nil
	}

	var exists bool
	if err := t.tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = ?)", name).Scan(&exists); err != nil {
		return fmt.Errorf("failed to check zone existence: %w", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrZoneNotFound
}

// Close is a no-op for transactions (use Commit or Rollback instead).
func (t *MySQLTx) Close() error {
	return nil
}

// Commit commits the transaction.
func (t *MySQLTx) Commit(ctx context.Context) error {
	return t.tx.Commit()
}

// Rollback aborts the transaction.
func (t *MySQLTx) Rollback(ctx context.Context) error {
	return t.tx.Rollback()
}

// insertRecords inserts records for a zone within a transaction.
func (m *MySQLBackend) insertRecords(ctx context.Context, tx *sql.Tx, zoneID int64, records []model.Record, allowedRecordIDs sqlRecordIDSet) error {
	if len(records) == 0 {
		return nil
	}

	autoIDQuery := `
		INSERT INTO records (zone_id, name, type, ttl, value, value_hash, priority)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	autoIDStmt, err := tx.PrepareContext(ctx, autoIDQuery)
	if err != nil {
		return fmt.Errorf("failed to prepare record statement: %w", err)
	}
	defer autoIDStmt.Close()

	explicitIDQuery := `
		INSERT INTO records (id, zone_id, name, type, ttl, value, value_hash, priority)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	explicitIDStmt, err := tx.PrepareContext(ctx, explicitIDQuery)
	if err != nil {
		return fmt.Errorf("failed to prepare record statement with id: %w", err)
	}
	defer explicitIDStmt.Close()

	for _, rec := range records {
		valueHash := computeValueHash(rec.Value)
		var priority interface{}
		if rec.Priority != nil && *rec.Priority > 0 {
			priority = *rec.Priority
		}

		if recordID, ok := parseSQLRecordID(rec.ID); ok && allowedRecordIDs.allows(recordID) {
			if _, err := explicitIDStmt.ExecContext(ctx, recordID, zoneID, rec.Name, rec.Type, rec.TTL, rec.Value, valueHash, priority); err != nil {
				return fmt.Errorf("failed to insert record: %w", err)
			}
			continue
		}

		if _, err := autoIDStmt.ExecContext(ctx, zoneID, rec.Name, rec.Type, rec.TTL, rec.Value, valueHash, priority); err != nil {
			return fmt.Errorf("failed to insert record: %w", err)
		}
	}

	return nil
}

// withRetry executes a function with deadlock retry logic.
func (m *MySQLBackend) withRetry(ctx context.Context, fn func(context.Context) error) error {
	const maxRetries = 3
	backoff := 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}

		if !isMySQLDeadlock(err) {
			return err
		}

		if i < maxRetries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(backoff):
				backoff *= 2 // Exponential backoff
			}
		}
	}

	return fmt.Errorf("operation failed after %d retries due to deadlock", maxRetries)
}

// Helper functions

func normalizeZoneName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func computeValueHash(value string) string {
	hash := sha256.Sum256([]byte(value))
	return hex.EncodeToString(hash[:])
}

func isMySQLDuplicateError(err error) bool {
	return strings.Contains(err.Error(), "Duplicate entry") || strings.Contains(err.Error(), "Error 1062")
}

func isMySQLDeadlock(err error) bool {
	return strings.Contains(err.Error(), "Deadlock") || strings.Contains(err.Error(), "Error 1213")
}

func init() {
	RegisterBackend("mysql", func(cfg map[string]interface{}) (ZoneStore, error) {
		dsn, ok := cfg["dsn"].(string)
		if !ok {
			return nil, fmt.Errorf("MySQL DSN is required")
		}
		return NewMySQLBackendWithPool(dsn, sqlPoolConfigFromMap(cfg))
	})
}
