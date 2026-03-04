-- Initial schema for arca-dns SQLite backend

CREATE TABLE zones (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL, -- Zone name in lowercase with trailing dot
    version TEXT NOT NULL,     -- Zone version (ULID-based)

    -- SOA fields
    soa_mname TEXT NOT NULL,
    soa_rname TEXT NOT NULL,
    soa_serial INTEGER NOT NULL,
    soa_refresh INTEGER NOT NULL,
    soa_retry INTEGER NOT NULL,
    soa_expire INTEGER NOT NULL,
    soa_minimum INTEGER NOT NULL,

    -- DNSSEC fields
    dnssec_enabled INTEGER DEFAULT 0,
    dnssec_algorithm INTEGER,
    dnssec_ksk_key_tag INTEGER,
    dnssec_zsk_key_tag INTEGER,
    dnssec_nsec3_enabled INTEGER DEFAULT 0,
    dnssec_nsec3_iterations INTEGER,
    dnssec_nsec3_salt TEXT,
    dnssec_signature_expiration TEXT, -- ISO 8601

    -- Timestamps (ISO 8601)
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX idx_zones_version ON zones(version);
CREATE INDEX idx_zones_updated ON zones(updated_at);

CREATE TABLE records (
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

CREATE INDEX idx_records_zone ON records(zone_id);
CREATE INDEX idx_records_name_type ON records(zone_id, name, type);
CREATE UNIQUE INDEX idx_records_unique ON records(zone_id, name, type, ttl, value_hash);
