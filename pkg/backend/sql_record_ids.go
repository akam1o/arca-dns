package backend

import (
	"strconv"
	"strings"
)

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
