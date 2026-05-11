-- Widen SOA interval columns to support the model's uint32 range.

ALTER TABLE zones
    ALTER COLUMN soa_refresh TYPE BIGINT,
    ALTER COLUMN soa_retry TYPE BIGINT,
    ALTER COLUMN soa_expire TYPE BIGINT,
    ALTER COLUMN soa_minimum TYPE BIGINT;
