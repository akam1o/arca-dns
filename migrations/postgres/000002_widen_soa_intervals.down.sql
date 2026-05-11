-- Revert SOA interval columns to the original PostgreSQL integer type.

ALTER TABLE zones
    ALTER COLUMN soa_refresh TYPE INTEGER USING soa_refresh::integer,
    ALTER COLUMN soa_retry TYPE INTEGER USING soa_retry::integer,
    ALTER COLUMN soa_expire TYPE INTEGER USING soa_expire::integer,
    ALTER COLUMN soa_minimum TYPE INTEGER USING soa_minimum::integer;
