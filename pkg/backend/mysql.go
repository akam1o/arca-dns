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
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open MySQL connection: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

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
		SELECT r.name, r.type, r.ttl, r.value, r.priority
		FROM records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ?
		ORDER BY r.name, r.type
	`

	rows, err := m.db.QueryContext(ctx, query, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer rows.Close()

	records := make([]model.Record, 0)
	for rows.Next() {
		var rec model.Record
		var priority sql.NullInt64

		if err := rows.Scan(&rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}

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

// CreateZone creates a new zone.
func (m *MySQLBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	return m.withRetry(ctx, func(ctx context.Context) error {
		return m.createZone(ctx, zone)
	})
}

func (m *MySQLBackend) createZone(ctx context.Context, zone *model.Zone) error {
	zone.Name = normalizeZoneName(zone.Name)

	// Auto-generate serial if not set
	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = generateSerial(0)
	}

	// Ensure version is set (normally issued by controller).
	if zone.Version == "" {
		version, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = version
	}

	// Set timestamps
	now := time.Now()
	zone.CreatedAt = now
	zone.UpdatedAt = now

	// Start transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

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
	if err := m.insertRecords(ctx, tx, zoneID, zone.Records); err != nil {
		return err
	}

	return tx.Commit()
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

	// Auto-increment serial
	zone.SOA.Serial = generateSerial(zone.SOA.Serial)

	// Ensure version changes on update (normally issued by controller).
	if zone.Version == "" || expectedVersion == "" || zone.Version == expectedVersion {
		newVersion, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = newVersion
	}

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// Start transaction
	tx, err := m.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// CAS update on zone
	zoneQuery := `
		UPDATE zones SET
			version = ?,
			soa_mname = ?, soa_rname = ?, soa_serial = ?, soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?,
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ? AND version = ?
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
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag,
		dnssecNSEC3Enabled, dnssecNSEC3Iterations, dnssecNSEC3Salt, dnssecSignatureExpiration,
		zone.UpdatedAt,
		zone.Name, expectedVersion,
	)

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

	// Delete old records
	_, err = tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to delete old records: %w", err)
	}

	// Insert new records
	if err := m.insertRecords(ctx, tx, zoneID, zone.Records); err != nil {
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
		SELECT r.name, r.type, r.ttl, r.value, r.priority
		FROM records r
		JOIN zones z ON r.zone_id = z.id
		WHERE z.name = ?
		ORDER BY r.name, r.type
	`

	rows, err := t.tx.QueryContext(ctx, query, zoneName)
	if err != nil {
		return nil, fmt.Errorf("failed to query records: %w", err)
	}
	defer rows.Close()

	records := make([]model.Record, 0)
	for rows.Next() {
		var rec model.Record
		var priority sql.NullInt64

		if err := rows.Scan(&rec.Name, &rec.Type, &rec.TTL, &rec.Value, &priority); err != nil {
			return nil, fmt.Errorf("failed to scan record: %w", err)
		}

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

// CreateZone creates a new zone within the transaction.
func (t *MySQLTx) CreateZone(ctx context.Context, zone *model.Zone) error {
	zone.Name = normalizeZoneName(zone.Name)

	// Auto-generate serial if not set
	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = generateSerial(0)
	}

	// Ensure version is set (normally issued by controller).
	if zone.Version == "" {
		version, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = version
	}

	// Set timestamps
	now := time.Now()
	zone.CreatedAt = now
	zone.UpdatedAt = now

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

	result, err := t.tx.ExecContext(ctx, zoneQuery,
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
	return t.backend.insertRecords(ctx, t.tx, zoneID, zone.Records)
}

// UpdateZone updates an existing zone within the transaction.
func (t *MySQLTx) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)

	// Auto-increment serial
	zone.SOA.Serial = generateSerial(zone.SOA.Serial)

	// Ensure version changes on update (normally issued by controller).
	if zone.Version == "" || expectedVersion == "" || zone.Version == expectedVersion {
		newVersion, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = newVersion
	}

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// CAS update on zone
	zoneQuery := `
		UPDATE zones SET
			version = ?,
			soa_mname = ?, soa_rname = ?, soa_serial = ?, soa_refresh = ?, soa_retry = ?, soa_expire = ?, soa_minimum = ?,
			dnssec_enabled = ?, dnssec_algorithm = ?, dnssec_ksk_key_tag = ?, dnssec_zsk_key_tag = ?,
			dnssec_nsec3_enabled = ?, dnssec_nsec3_iterations = ?, dnssec_nsec3_salt = ?, dnssec_signature_expiration = ?,
			updated_at = ?
		WHERE name = ? AND version = ?
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

	result, err := t.tx.ExecContext(ctx, zoneQuery,
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgorithm, dnssecKSKKeyTag, dnssecZSKKeyTag,
		dnssecNSEC3Enabled, dnssecNSEC3Iterations, dnssecNSEC3Salt, dnssecSignatureExpiration,
		zone.UpdatedAt,
		zone.Name, expectedVersion,
	)

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

	// Delete old records
	_, err = t.tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = ?", zoneID)
	if err != nil {
		return fmt.Errorf("failed to delete old records: %w", err)
	}

	// Insert new records
	return t.backend.insertRecords(ctx, t.tx, zoneID, zone.Records)
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
func (m *MySQLBackend) insertRecords(ctx context.Context, tx *sql.Tx, zoneID int64, records []model.Record) error {
	if len(records) == 0 {
		return nil
	}

	recordQuery := `
		INSERT INTO records (zone_id, name, type, ttl, value, value_hash, priority)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`

	stmt, err := tx.PrepareContext(ctx, recordQuery)
	if err != nil {
		return fmt.Errorf("failed to prepare record statement: %w", err)
	}
	defer stmt.Close()

	for _, rec := range records {
		valueHash := computeValueHash(rec.Value)
		var priority interface{}
		if rec.Priority != nil && *rec.Priority > 0 {
			priority = *rec.Priority
		}

		_, err := stmt.ExecContext(ctx, zoneID, rec.Name, rec.Type, rec.TTL, rec.Value, valueHash, priority)
		if err != nil {
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
		return NewMySQLBackend(dsn)
	})
}
