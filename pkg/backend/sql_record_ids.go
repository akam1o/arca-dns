package backend

import (
	"context"
	"database/sql"
	"fmt"
	"strconv"
	"strings"
)

type sqlRecordIDSet map[int64]struct{}

type sqlRecordIDQuerier interface {
	QueryContext(ctx context.Context, query string, args ...interface{}) (*sql.Rows, error)
}

func formatSQLRecordID(id int64) string {
	return strconv.FormatInt(id, 10)
}

func parseSQLRecordID(id string) (int64, bool) {
	id = strings.TrimSpace(id)
	if id == "" {
		return 0, false
	}
	parsed, err := strconv.ParseInt(id, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, false
	}
	return parsed, true
}

func (ids sqlRecordIDSet) allows(id int64) bool {
	if ids == nil {
		return false
	}
	_, ok := ids[id]
	return ok
}

func loadSQLRecordIDSet(ctx context.Context, q sqlRecordIDQuerier, query string, args ...interface{}) (sqlRecordIDSet, error) {
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	ids := make(sqlRecordIDSet)
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan record id: %w", err)
		}
		ids[id] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
