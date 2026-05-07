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

	_ "github.com/lib/pq"

	"github.com/akam1o/arca-dns/pkg/model"
)

// PostgresBackend implements ZoneStore and TransactionalStore using PostgreSQL.
type PostgresBackend struct {
	db  *sql.DB
	dsn string
}

// NewPostgresBackend creates a new PostgreSQL backend.
// DSN format: "postgres://user:password@host:port/dbname?sslmode=disable"
func NewPostgresBackend(dsn string) (*PostgresBackend, error) {
	return NewPostgresBackendWithPool(dsn, SQLPoolConfig{})
}

// NewPostgresBackendWithPool creates a new PostgreSQL backend with connection pool settings.
func NewPostgresBackendWithPool(dsn string, pool SQLPoolConfig) (*PostgresBackend, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open PostgreSQL connection: %w", err)
	}

	applySQLPoolConfig(db, pool)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
	}

	return &PostgresBackend{db: db, dsn: dsn}, nil
}

// InitSchema creates tables if they don't exist (for simple deployments).
func (p *PostgresBackend) InitSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS zones (
		id SERIAL PRIMARY KEY,
		name VARCHAR(255) UNIQUE NOT NULL,
		version VARCHAR(64) NOT NULL,
		soa_mname VARCHAR(255) NOT NULL,
		soa_rname VARCHAR(255) NOT NULL,
		soa_serial BIGINT NOT NULL,
		soa_refresh INTEGER NOT NULL,
		soa_retry INTEGER NOT NULL,
		soa_expire INTEGER NOT NULL,
		soa_minimum INTEGER NOT NULL,
		dnssec_enabled BOOLEAN DEFAULT FALSE,
		dnssec_algorithm SMALLINT,
		dnssec_ksk_key_tag INTEGER,
		dnssec_zsk_key_tag INTEGER,
		dnssec_nsec3_enabled BOOLEAN DEFAULT FALSE,
		dnssec_nsec3_iterations SMALLINT,
		dnssec_nsec3_salt VARCHAR(64),
		dnssec_signature_expiration TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_zones_version ON zones(version);
	CREATE INDEX IF NOT EXISTS idx_zones_updated ON zones(updated_at);

	CREATE TABLE IF NOT EXISTS records (
		id SERIAL PRIMARY KEY,
		zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
		name VARCHAR(255) NOT NULL,
		type VARCHAR(10) NOT NULL,
		ttl INTEGER NOT NULL,
		value TEXT NOT NULL,
		value_hash CHAR(64) NOT NULL,
		priority SMALLINT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);
	CREATE INDEX IF NOT EXISTS idx_records_zone ON records(zone_id);
	CREATE INDEX IF NOT EXISTS idx_records_name_type ON records(zone_id, name, type);
	CREATE UNIQUE INDEX IF NOT EXISTS idx_records_unique ON records(zone_id, name, type, ttl, value_hash);
	`
	_, err := p.db.Exec(schema)
	return err
}

// GetZone retrieves a zone by name.
func (p *PostgresBackend) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	name = normalizeZoneName(name)

	zone, err := p.scanZonePG(ctx, p.db, name)
	if err != nil {
		return nil, err
	}

	records, err := p.loadRecordsPG(ctx, p.db, zone.Name)
	if err != nil {
		return nil, err
	}
	zone.Records = records
	return zone, nil
}

// ListZones returns all zones, optionally paginated.
func (p *PostgresBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
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
	argN := 1
	if opts.Limit > 0 {
		query += fmt.Sprintf(" LIMIT $%d OFFSET $%d", argN, argN+1)
		args = append(args, opts.Limit, opts.Offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query zones: %w", err)
	}
	defer rows.Close()

	zones := make([]*model.Zone, 0)
	for rows.Next() {
		zone, err := p.scanZoneRowPG(rows)
		if err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zones: %w", err)
	}

	for _, zone := range zones {
		records, err := p.loadRecordsPG(ctx, p.db, zone.Name)
		if err != nil {
			return nil, err
		}
		zone.Records = records
	}
	return zones, nil
}

// ListZoneSummaries returns zone names and versions without loading records.
func (p *PostgresBackend) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	query := `
		SELECT name, version
		FROM zones ORDER BY name
	`
	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT $1 OFFSET $2"
		args = append(args, opts.Limit, opts.Offset)
	}

	rows, err := p.db.QueryContext(ctx, query, args...)
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

// CreateZone creates a new zone.
func (p *PostgresBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
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

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	zoneID, err := p.insertZonePGTx(ctx, tx, zone)
	if err != nil {
		return err
	}
	if err := p.insertRecordsPGTx(ctx, tx, zoneID, zone.Records, nil); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateZone updates an existing zone.
func (p *PostgresBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)

	if zone.Version == "" || expectedVersion == "" || zone.Version == expectedVersion {
		v, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate version: %w", err)
		}
		zone.Version = v
	}
	zone.UpdatedAt = time.Now()

	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Preserve CreatedAt and advance from the stored SOA serial, not client input.
	var createdAt time.Time
	var currentSerial uint32
	err = tx.QueryRowContext(ctx, "SELECT created_at, soa_serial FROM zones WHERE name = $1 FOR UPDATE", zone.Name).Scan(&createdAt, &currentSerial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("query zone: %w", err)
	}
	zone.CreatedAt = createdAt
	zone.SOA.Serial = updateSOASerial(currentSerial, zone.SOA.Serial)

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	// CAS update
	dnssecEnabled := false
	var dnssecAlgo, dnssecKSK, dnssecZSK interface{}
	dnssecNSEC3 := false
	var dnssecNSEC3Iter interface{}
	var dnssecSalt, dnssecSigExp interface{}

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = true
		dnssecAlgo = zone.DNSSEC.Algorithm
		dnssecKSK = zone.DNSSEC.KSKKeyTag
		dnssecZSK = zone.DNSSEC.ZSKKeyTag
		dnssecNSEC3 = zone.DNSSEC.NSEC3Enabled
		dnssecNSEC3Iter = zone.DNSSEC.NSEC3Iterations
		dnssecSalt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSigExp = zone.DNSSEC.SignatureExpiration
		}
	}

	query := `
		UPDATE zones SET
			version = $1,
			soa_mname = $2, soa_rname = $3, soa_serial = $4, soa_refresh = $5, soa_retry = $6, soa_expire = $7, soa_minimum = $8,
			dnssec_enabled = $9, dnssec_algorithm = $10, dnssec_ksk_key_tag = $11, dnssec_zsk_key_tag = $12,
			dnssec_nsec3_enabled = $13, dnssec_nsec3_iterations = $14, dnssec_nsec3_salt = $15, dnssec_signature_expiration = $16,
			updated_at = $17
		WHERE name = $18
	`
	args := []interface{}{
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgo, dnssecKSK, dnssecZSK,
		dnssecNSEC3, dnssecNSEC3Iter, dnssecSalt, dnssecSigExp,
		zone.UpdatedAt,
		zone.Name,
	}

	if expectedVersion != "" {
		query += " AND version = $19"
		args = append(args, expectedVersion)
	}

	result, err := tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update zone: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		if expectedVersion != "" {
			return model.ErrConflict
		}
		return model.ErrZoneNotFound
	}

	var zoneID int64
	if err := tx.QueryRowContext(ctx, "SELECT id FROM zones WHERE name = $1", zone.Name).Scan(&zoneID); err != nil {
		return fmt.Errorf("get zone ID: %w", err)
	}
	recordIDs, err := loadSQLRecordIDSet(ctx, tx, "SELECT id FROM records WHERE zone_id = $1", zoneID)
	if err != nil {
		return fmt.Errorf("load record IDs: %w", err)
	}
	if _, err := tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = $1", zoneID); err != nil {
		return fmt.Errorf("delete records: %w", err)
	}
	if err := p.insertRecordsPGTx(ctx, tx, zoneID, zone.Records, recordIDs); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateDNSSECMetadata updates DNSSEC metadata without changing zone version or SOA serial.
func (p *PostgresBackend) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	name := normalizeZoneName(zoneName)
	enabled, algorithm, kskKeyTag, zskKeyTag, nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration := dnssecColumnValues(dnssec)

	query := `
		UPDATE zones SET
			dnssec_enabled = $1, dnssec_algorithm = $2, dnssec_ksk_key_tag = $3, dnssec_zsk_key_tag = $4,
			dnssec_nsec3_enabled = $5, dnssec_nsec3_iterations = $6, dnssec_nsec3_salt = $7, dnssec_signature_expiration = $8,
			updated_at = $9
		WHERE name = $10
	`
	result, err := p.db.ExecContext(ctx, query,
		enabled, algorithm, kskKeyTag, zskKeyTag,
		nsec3Enabled, nsec3Iterations, nsec3Salt, signatureExpiration,
		time.Now(), name,
	)
	if err != nil {
		return fmt.Errorf("update DNSSEC metadata: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		var exists bool
		if err := p.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = $1)", name).Scan(&exists); err != nil {
			return fmt.Errorf("check zone existence: %w", err)
		}
		if !exists {
			return model.ErrZoneNotFound
		}
	}
	return nil
}

// DeleteZone removes a zone.
func (p *PostgresBackend) DeleteZone(ctx context.Context, name string) error {
	name = normalizeZoneName(name)
	result, err := p.db.ExecContext(ctx, "DELETE FROM zones WHERE name = $1", name)
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
func (p *PostgresBackend) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = $1"
	args := []interface{}{name}
	if expectedVersion != "" {
		query += " AND version = $2"
		args = append(args, expectedVersion)
	}

	result, err := p.db.ExecContext(ctx, query, args...)
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
	if err := p.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = $1)", name).Scan(&exists); err != nil {
		return fmt.Errorf("check zone existence: %w", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrZoneNotFound
}

// Close releases resources.
func (p *PostgresBackend) Close() error { return p.db.Close() }

// Info returns backend metadata.
func (p *PostgresBackend) Info() BackendInfo {
	return BackendInfo{
		Type:         "postgres",
		Capabilities: []string{"ZoneStore", "TransactionalStore", "DNSSECMetadataStore"},
		Consistency:  "strong",
		Description:  "PostgreSQL storage (recommended for large-scale production)",
	}
}

// BeginTx starts a new transaction.
func (p *PostgresBackend) BeginTx(ctx context.Context) (Tx, error) {
	sqlTx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	return &pgTx{backend: p, tx: sqlTx}, nil
}

// --- internal helpers ---

type pgQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...interface{}) *sql.Row
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...interface{}) (sql.Result, error)
}

func (p *PostgresBackend) scanZonePG(ctx context.Context, q pgQuerier, name string) (*model.Zone, error) {
	query := `
		SELECT
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		FROM zones WHERE name = $1
	`

	zone := &model.Zone{SOA: model.SOARecord{}}
	var dnssecEnabled, dnssecNSEC3Enabled bool
	var dnssecAlgo, dnssecKSK, dnssecZSK sql.NullInt64
	var dnssecNSEC3Iter sql.NullInt64
	var dnssecSalt sql.NullString
	var dnssecSigExp sql.NullTime

	err := q.QueryRowContext(ctx, query, name).Scan(
		&zone.Name, &zone.Version,
		&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
		&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
		&dnssecEnabled, &dnssecAlgo, &dnssecKSK, &dnssecZSK,
		&dnssecNSEC3Enabled, &dnssecNSEC3Iter, &dnssecSalt, &dnssecSigExp,
		&zone.CreatedAt, &zone.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("query zone: %w", err)
	}

	if dnssecEnabled {
		zone.DNSSEC = &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       uint8(dnssecAlgo.Int64),
			KSKKeyTag:       uint16(dnssecKSK.Int64),
			ZSKKeyTag:       uint16(dnssecZSK.Int64),
			NSEC3Enabled:    dnssecNSEC3Enabled,
			NSEC3Iterations: uint16(dnssecNSEC3Iter.Int64),
			NSEC3Salt:       dnssecSalt.String,
		}
		if dnssecSigExp.Valid {
			zone.DNSSEC.SignatureExpiration = &dnssecSigExp.Time
		}
	}
	return zone, nil
}

func (p *PostgresBackend) scanZoneRowPG(row scannable) (*model.Zone, error) {
	zone := &model.Zone{SOA: model.SOARecord{}}
	var dnssecEnabled, dnssecNSEC3Enabled bool
	var dnssecAlgo, dnssecKSK, dnssecZSK sql.NullInt64
	var dnssecNSEC3Iter sql.NullInt64
	var dnssecSalt sql.NullString
	var dnssecSigExp sql.NullTime

	if err := row.Scan(
		&zone.Name, &zone.Version,
		&zone.SOA.MName, &zone.SOA.RName, &zone.SOA.Serial, &zone.SOA.Refresh,
		&zone.SOA.Retry, &zone.SOA.Expire, &zone.SOA.Minimum,
		&dnssecEnabled, &dnssecAlgo, &dnssecKSK, &dnssecZSK,
		&dnssecNSEC3Enabled, &dnssecNSEC3Iter, &dnssecSalt, &dnssecSigExp,
		&zone.CreatedAt, &zone.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("scan zone: %w", err)
	}

	if dnssecEnabled {
		zone.DNSSEC = &model.DNSSECConfig{
			Enabled:         true,
			Algorithm:       uint8(dnssecAlgo.Int64),
			KSKKeyTag:       uint16(dnssecKSK.Int64),
			ZSKKeyTag:       uint16(dnssecZSK.Int64),
			NSEC3Enabled:    dnssecNSEC3Enabled,
			NSEC3Iterations: uint16(dnssecNSEC3Iter.Int64),
			NSEC3Salt:       dnssecSalt.String,
		}
		if dnssecSigExp.Valid {
			zone.DNSSEC.SignatureExpiration = &dnssecSigExp.Time
		}
	}
	return zone, nil
}

func (p *PostgresBackend) loadRecordsPG(ctx context.Context, q pgQuerier, zoneName string) ([]model.Record, error) {
	query := `
		SELECT r.id, r.name, r.type, r.ttl, r.value, r.priority
		FROM records r JOIN zones z ON r.zone_id = z.id
		WHERE z.name = $1
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

func (p *PostgresBackend) insertZonePGTx(ctx context.Context, tx *sql.Tx, zone *model.Zone) (int64, error) {
	query := `
		INSERT INTO zones (
			name, version,
			soa_mname, soa_rname, soa_serial, soa_refresh, soa_retry, soa_expire, soa_minimum,
			dnssec_enabled, dnssec_algorithm, dnssec_ksk_key_tag, dnssec_zsk_key_tag,
			dnssec_nsec3_enabled, dnssec_nsec3_iterations, dnssec_nsec3_salt, dnssec_signature_expiration,
			created_at, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
		RETURNING id
	`

	dnssecEnabled := false
	var dnssecAlgo, dnssecKSK, dnssecZSK interface{}
	dnssecNSEC3 := false
	var dnssecNSEC3Iter interface{}
	var dnssecSalt, dnssecSigExp interface{}

	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = true
		dnssecAlgo = zone.DNSSEC.Algorithm
		dnssecKSK = zone.DNSSEC.KSKKeyTag
		dnssecZSK = zone.DNSSEC.ZSKKeyTag
		dnssecNSEC3 = zone.DNSSEC.NSEC3Enabled
		dnssecNSEC3Iter = zone.DNSSEC.NSEC3Iterations
		dnssecSalt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSigExp = zone.DNSSEC.SignatureExpiration
		}
	}

	var zoneID int64
	err := tx.QueryRowContext(ctx, query,
		zone.Name, zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgo, dnssecKSK, dnssecZSK,
		dnssecNSEC3, dnssecNSEC3Iter, dnssecSalt, dnssecSigExp,
		zone.CreatedAt, zone.UpdatedAt,
	).Scan(&zoneID)

	if err != nil {
		if isPostgresUniqueViolation(err) {
			return 0, model.ErrZoneAlreadyExists
		}
		return 0, fmt.Errorf("insert zone: %w", err)
	}
	return zoneID, nil
}

func (p *PostgresBackend) insertRecordsPGTx(ctx context.Context, tx *sql.Tx, zoneID int64, records []model.Record, allowedRecordIDs sqlRecordIDSet) error {
	if len(records) == 0 {
		return nil
	}

	autoIDQuery := `INSERT INTO records (zone_id, name, type, ttl, value, value_hash, priority) VALUES ($1, $2, $3, $4, $5, $6, $7)`
	autoIDStmt, err := tx.PrepareContext(ctx, autoIDQuery)
	if err != nil {
		return fmt.Errorf("prepare record insert: %w", err)
	}
	defer autoIDStmt.Close()

	explicitIDQuery := `INSERT INTO records (id, zone_id, name, type, ttl, value, value_hash, priority) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	explicitIDStmt, err := tx.PrepareContext(ctx, explicitIDQuery)
	if err != nil {
		return fmt.Errorf("prepare record insert with id: %w", err)
	}
	defer explicitIDStmt.Close()

	for _, rec := range records {
		hash := sha256.Sum256([]byte(rec.Value))
		valueHash := hex.EncodeToString(hash[:])
		var priority interface{}
		if rec.Priority != nil && *rec.Priority > 0 {
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

func isPostgresUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "duplicate key value violates unique constraint") ||
		strings.Contains(err.Error(), "23505")
}

// --- Transaction implementation ---

type pgTx struct {
	backend *PostgresBackend
	tx      *sql.Tx
}

func (t *pgTx) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	name = normalizeZoneName(name)
	zone, err := t.backend.scanZonePG(ctx, t.tx, name)
	if err != nil {
		return nil, err
	}
	records, err := t.backend.loadRecordsPG(ctx, t.tx, zone.Name)
	if err != nil {
		return nil, err
	}
	zone.Records = records
	return zone, nil
}

func (t *pgTx) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
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
		query += " LIMIT $1 OFFSET $2"
		args = append(args, opts.Limit, opts.Offset)
	}
	rows, err := t.tx.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query zones: %w", err)
	}
	defer rows.Close()

	zones := make([]*model.Zone, 0)
	for rows.Next() {
		zone, err := t.backend.scanZoneRowPG(rows)
		if err != nil {
			return nil, err
		}
		zones = append(zones, zone)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate zones: %w", err)
	}
	for _, zone := range zones {
		records, err := t.backend.loadRecordsPG(ctx, t.tx, zone.Name)
		if err != nil {
			return nil, err
		}
		zone.Records = records
	}
	return zones, nil
}

func (t *pgTx) ListZoneSummaries(ctx context.Context, opts ListOptions) ([]*ZoneSummary, error) {
	query := `
		SELECT name, version
		FROM zones ORDER BY name
	`
	args := []interface{}{}
	if opts.Limit > 0 {
		query += " LIMIT $1 OFFSET $2"
		args = append(args, opts.Limit, opts.Offset)
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

func (t *pgTx) CreateZone(ctx context.Context, zone *model.Zone) error {
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
	if err := validateZoneForWrite(zone); err != nil {
		return err
	}
	zoneID, err := t.backend.insertZonePGTx(ctx, t.tx, zone)
	if err != nil {
		return err
	}
	return t.backend.insertRecordsPGTx(ctx, t.tx, zoneID, zone.Records, nil)
}

func (t *pgTx) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	zone.Name = normalizeZoneName(zone.Name)
	if zone.Version == "" || expectedVersion == "" || zone.Version == expectedVersion {
		v, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate version: %w", err)
		}
		zone.Version = v
	}
	zone.UpdatedAt = time.Now()

	var createdAt time.Time
	var currentSerial uint32
	err := t.tx.QueryRowContext(ctx, "SELECT created_at, soa_serial FROM zones WHERE name = $1 FOR UPDATE", zone.Name).Scan(&createdAt, &currentSerial)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return model.ErrZoneNotFound
		}
		return fmt.Errorf("query zone: %w", err)
	}
	zone.CreatedAt = createdAt
	zone.SOA.Serial = updateSOASerial(currentSerial, zone.SOA.Serial)

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	dnssecEnabled := false
	var dnssecAlgo, dnssecKSK, dnssecZSK interface{}
	dnssecNSEC3 := false
	var dnssecNSEC3Iter interface{}
	var dnssecSalt, dnssecSigExp interface{}
	if zone.DNSSEC != nil && zone.DNSSEC.Enabled {
		dnssecEnabled = true
		dnssecAlgo = zone.DNSSEC.Algorithm
		dnssecKSK = zone.DNSSEC.KSKKeyTag
		dnssecZSK = zone.DNSSEC.ZSKKeyTag
		dnssecNSEC3 = zone.DNSSEC.NSEC3Enabled
		dnssecNSEC3Iter = zone.DNSSEC.NSEC3Iterations
		dnssecSalt = zone.DNSSEC.NSEC3Salt
		if zone.DNSSEC.SignatureExpiration != nil && !zone.DNSSEC.SignatureExpiration.IsZero() {
			dnssecSigExp = zone.DNSSEC.SignatureExpiration
		}
	}

	query := `
		UPDATE zones SET
			version = $1,
			soa_mname = $2, soa_rname = $3, soa_serial = $4, soa_refresh = $5, soa_retry = $6, soa_expire = $7, soa_minimum = $8,
			dnssec_enabled = $9, dnssec_algorithm = $10, dnssec_ksk_key_tag = $11, dnssec_zsk_key_tag = $12,
			dnssec_nsec3_enabled = $13, dnssec_nsec3_iterations = $14, dnssec_nsec3_salt = $15, dnssec_signature_expiration = $16,
			updated_at = $17
		WHERE name = $18
	`
	args := []interface{}{
		zone.Version,
		zone.SOA.MName, zone.SOA.RName, zone.SOA.Serial, zone.SOA.Refresh,
		zone.SOA.Retry, zone.SOA.Expire, zone.SOA.Minimum,
		dnssecEnabled, dnssecAlgo, dnssecKSK, dnssecZSK,
		dnssecNSEC3, dnssecNSEC3Iter, dnssecSalt, dnssecSigExp,
		zone.UpdatedAt, zone.Name,
	}
	if expectedVersion != "" {
		query += " AND version = $19"
		args = append(args, expectedVersion)
	}

	result, err := t.tx.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("update zone: %w", err)
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("rows affected: %w", err)
	}
	if rowsAffected == 0 {
		if expectedVersion != "" {
			return model.ErrConflict
		}
		return model.ErrZoneNotFound
	}

	var zoneID int64
	if err := t.tx.QueryRowContext(ctx, "SELECT id FROM zones WHERE name = $1", zone.Name).Scan(&zoneID); err != nil {
		return fmt.Errorf("get zone ID: %w", err)
	}
	recordIDs, err := loadSQLRecordIDSet(ctx, t.tx, "SELECT id FROM records WHERE zone_id = $1", zoneID)
	if err != nil {
		return fmt.Errorf("load record IDs: %w", err)
	}
	if _, err := t.tx.ExecContext(ctx, "DELETE FROM records WHERE zone_id = $1", zoneID); err != nil {
		return fmt.Errorf("delete records: %w", err)
	}
	return t.backend.insertRecordsPGTx(ctx, t.tx, zoneID, zone.Records, recordIDs)
}

func (t *pgTx) DeleteZone(ctx context.Context, name string) error {
	name = normalizeZoneName(name)
	result, err := t.tx.ExecContext(ctx, "DELETE FROM zones WHERE name = $1", name)
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

func (t *pgTx) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	name = normalizeZoneName(name)

	query := "DELETE FROM zones WHERE name = $1"
	args := []interface{}{name}
	if expectedVersion != "" {
		query += " AND version = $2"
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
	if err := t.tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM zones WHERE name = $1)", name).Scan(&exists); err != nil {
		return fmt.Errorf("check zone existence: %w", err)
	}
	if exists {
		return model.ErrConflict
	}
	return model.ErrZoneNotFound
}

func (t *pgTx) Close() error                       { return nil }
func (t *pgTx) Commit(ctx context.Context) error   { return t.tx.Commit() }
func (t *pgTx) Rollback(ctx context.Context) error { return t.tx.Rollback() }

func init() {
	RegisterBackend("postgres", func(cfg map[string]interface{}) (ZoneStore, error) {
		dsn, ok := cfg["dsn"].(string)
		if !ok {
			return nil, fmt.Errorf("PostgreSQL DSN is required")
		}
		return NewPostgresBackendWithPool(dsn, sqlPoolConfigFromMap(cfg))
	})
}
