-- Initial schema for arca-dns MySQL backend
-- Zone version system: v{serial}-{hash8} format (VARCHAR(64) for future extensibility)

CREATE TABLE zones (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) UNIQUE NOT NULL COMMENT 'Zone name in lowercase with trailing dot (e.g., example.com.)',
    version VARCHAR(64) NOT NULL COMMENT 'Zone version in v{serial}-{hash8} format',

    -- SOA fields
    soa_mname VARCHAR(255) NOT NULL COMMENT 'SOA MNAME (primary nameserver)',
    soa_rname VARCHAR(255) NOT NULL COMMENT 'SOA RNAME (responsible email)',
    soa_serial INT UNSIGNED NOT NULL COMMENT 'SOA serial in YYYYMMDDnn format',
    soa_refresh INT UNSIGNED NOT NULL COMMENT 'SOA refresh interval (seconds)',
    soa_retry INT UNSIGNED NOT NULL COMMENT 'SOA retry interval (seconds)',
    soa_expire INT UNSIGNED NOT NULL COMMENT 'SOA expire time (seconds)',
    soa_minimum INT UNSIGNED NOT NULL COMMENT 'SOA minimum TTL (seconds)',

    -- DNSSEC fields (nullable - NULL when DNSSEC disabled)
    dnssec_enabled BOOLEAN DEFAULT FALSE COMMENT 'Whether DNSSEC is enabled for this zone',
    dnssec_algorithm TINYINT UNSIGNED COMMENT 'DNSSEC algorithm ID (e.g., 13 for ECDSA-P256)',
    dnssec_ksk_key_tag SMALLINT UNSIGNED COMMENT 'KSK key tag',
    dnssec_zsk_key_tag SMALLINT UNSIGNED COMMENT 'ZSK key tag',
    dnssec_nsec3_enabled BOOLEAN DEFAULT FALSE COMMENT 'Whether NSEC3 is enabled',
    dnssec_nsec3_iterations SMALLINT UNSIGNED COMMENT 'NSEC3 iteration count',
    dnssec_nsec3_salt VARCHAR(64) COMMENT 'NSEC3 salt (hex-encoded)',
    dnssec_signature_expiration TIMESTAMP NULL COMMENT 'When DNSSEC signatures expire (for re-signing)',

    -- Timestamps
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Zone creation timestamp',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT 'Zone last update timestamp',

    -- Indexes for query performance
    INDEX idx_version (version),
    INDEX idx_updated (updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin COMMENT='DNS zones';

CREATE TABLE records (
    id INT PRIMARY KEY AUTO_INCREMENT,
    zone_id INT NOT NULL COMMENT 'Foreign key to zones table',
    name VARCHAR(255) NOT NULL COMMENT 'Record name (owner name)',
    type VARCHAR(10) NOT NULL COMMENT 'Record type (A, AAAA, MX, etc.)',
    ttl INT UNSIGNED NOT NULL COMMENT 'TTL in seconds',
    value TEXT NOT NULL COMMENT 'Record value (RDATA)',
    value_hash CHAR(64) NOT NULL COMMENT 'SHA256 hash of value for deduplication',
    priority SMALLINT UNSIGNED COMMENT 'Priority field for MX/SRV records',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT 'Record creation timestamp',

    -- Foreign key with cascade delete (delete records when zone is deleted)
    FOREIGN KEY (zone_id) REFERENCES zones(id) ON DELETE CASCADE,

    -- Indexes for query performance
    INDEX idx_zone (zone_id),
    INDEX idx_name_type (zone_id, name, type),

    -- Prevent duplicate records (idempotent imports, handles long TXT records)
    UNIQUE KEY unique_record (zone_id, name, type, ttl, value_hash)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin COMMENT='DNS records';
