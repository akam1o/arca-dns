-- Initial schema for arca-dns PostgreSQL backend

CREATE TABLE zones (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL, -- Zone name in lowercase with trailing dot
    version VARCHAR(64) NOT NULL,       -- Zone version (ULID-based)

    -- SOA fields
    soa_mname VARCHAR(255) NOT NULL,
    soa_rname VARCHAR(255) NOT NULL,
    soa_serial BIGINT NOT NULL,
    soa_refresh INTEGER NOT NULL,
    soa_retry INTEGER NOT NULL,
    soa_expire INTEGER NOT NULL,
    soa_minimum INTEGER NOT NULL,

    -- DNSSEC fields
    dnssec_enabled BOOLEAN DEFAULT FALSE,
    dnssec_algorithm SMALLINT,
    dnssec_ksk_key_tag INTEGER,
    dnssec_zsk_key_tag INTEGER,
    dnssec_nsec3_enabled BOOLEAN DEFAULT FALSE,
    dnssec_nsec3_iterations SMALLINT,
    dnssec_nsec3_salt VARCHAR(64),
    dnssec_signature_expiration TIMESTAMPTZ,

    -- Timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_zones_version ON zones(version);
CREATE INDEX idx_zones_updated ON zones(updated_at);

CREATE TABLE records (
    id SERIAL PRIMARY KEY,
    zone_id INTEGER NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(10) NOT NULL,
    ttl INTEGER NOT NULL,
    value TEXT NOT NULL,
    value_hash CHAR(64) NOT NULL,
    priority SMALLINT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (zone_id, name, type, ttl, value_hash)
);

CREATE INDEX idx_records_zone ON records(zone_id);
CREATE INDEX idx_records_name_type ON records(zone_id, name, type);

-- Function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_zones_updated_at
    BEFORE UPDATE ON zones
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();
