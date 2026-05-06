package backend

import (
	"database/sql"
	"time"
)

type SQLPoolConfig struct {
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
}

func defaultSQLPoolConfig() SQLPoolConfig {
	return SQLPoolConfig{
		MaxOpenConns:    25,
		MaxIdleConns:    5,
		ConnMaxLifetime: 5 * time.Minute,
	}
}

func normalizeSQLPoolConfig(cfg SQLPoolConfig) SQLPoolConfig {
	defaults := defaultSQLPoolConfig()
	if cfg.MaxOpenConns <= 0 {
		cfg.MaxOpenConns = defaults.MaxOpenConns
	}
	if cfg.MaxIdleConns <= 0 {
		cfg.MaxIdleConns = defaults.MaxIdleConns
	}
	if cfg.ConnMaxLifetime <= 0 {
		cfg.ConnMaxLifetime = defaults.ConnMaxLifetime
	}
	return cfg
}

func applySQLPoolConfig(db *sql.DB, cfg SQLPoolConfig) {
	cfg = normalizeSQLPoolConfig(cfg)
	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)
}

func sqlPoolConfigFromMap(cfg map[string]interface{}) SQLPoolConfig {
	var pool SQLPoolConfig

	if val, ok := intFromConfig(cfg["max_open_conns"]); ok {
		pool.MaxOpenConns = val
	}
	if val, ok := intFromConfig(cfg["max_idle_conns"]); ok {
		pool.MaxIdleConns = val
	}
	if val, ok := durationFromConfig(cfg["conn_max_lifetime"]); ok {
		pool.ConnMaxLifetime = val
	}

	return pool
}

func intFromConfig(value interface{}) (int, bool) {
	switch v := value.(type) {
	case int:
		return v, true
	case int8:
		return int(v), true
	case int16:
		return int(v), true
	case int32:
		return int(v), true
	case int64:
		return int(v), true
	case uint:
		return int(v), true
	case uint8:
		return int(v), true
	case uint16:
		return int(v), true
	case uint32:
		return int(v), true
	case uint64:
		return int(v), true
	case float64:
		if v == float64(int(v)) {
			return int(v), true
		}
	case float32:
		if v == float32(int(v)) {
			return int(v), true
		}
	}
	return 0, false
}

func durationFromConfig(value interface{}) (time.Duration, bool) {
	switch v := value.(type) {
	case time.Duration:
		return v, true
	case string:
		if v == "" {
			return 0, false
		}
		parsed, err := time.ParseDuration(v)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}
