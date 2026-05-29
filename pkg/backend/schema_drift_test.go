package backend

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSQLiteBackend_InitSchemaMatchesMigration(t *testing.T) {
	inlineDB := openSQLiteSchemaTestDB(t)
	migrationDB := openSQLiteSchemaTestDB(t)

	_, err := inlineDB.Exec(sqliteSchemaSQL)
	require.NoError(t, err)
	_, err = migrationDB.Exec(readMigrationSQL(t, "sqlite"))
	require.NoError(t, err)

	inlineSnapshot := sqliteSchemaSnapshot(t, inlineDB)
	migrationSnapshot := sqliteSchemaSnapshot(t, migrationDB)

	assert.Equal(t, migrationSnapshot, inlineSnapshot)
}

func TestPostgresBackend_InitSchemaMatchesMigrationShape(t *testing.T) {
	inlineShape := parseLogicalSQLSchema(t, postgresSchemaSQL)
	migrationShape := parseLogicalSQLSchema(t, readMigrationSQL(t, "postgres"))

	assert.Equal(t, migrationShape, inlineShape)
}

func TestBackendMigrationSchemasShareLogicalShape(t *testing.T) {
	sqliteShape := parseLogicalSQLSchema(t, readMigrationSQL(t, "sqlite"))
	postgresShape := parseLogicalSQLSchema(t, readMigrationSQL(t, "postgres"))
	mysqlShape := parseLogicalSQLSchema(t, readMigrationSQL(t, "mysql"))

	assert.Equal(t, sqliteShape, postgresShape)
	assert.Equal(t, sqliteShape, mysqlShape)
}

func openSQLiteSchemaTestDB(t *testing.T) *sql.DB {
	t.Helper()

	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, db.Close())
	})
	return db
}

func readMigrationSQL(t *testing.T, backend string) string {
	t.Helper()

	path := filepath.Join("..", "..", "migrations", backend, "000001_initial_schema.up.sql")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(data)
}

type sqliteSchema struct {
	Columns     []string
	Indexes     []string
	ForeignKeys []string
}

func sqliteSchemaSnapshot(t *testing.T, db *sql.DB) sqliteSchema {
	t.Helper()

	tables := []string{"zones", "records"}
	snapshot := sqliteSchema{}
	for _, table := range tables {
		snapshot.Columns = append(snapshot.Columns, sqliteColumns(t, db, table)...)
		snapshot.Indexes = append(snapshot.Indexes, sqliteIndexes(t, db, table)...)
		snapshot.ForeignKeys = append(snapshot.ForeignKeys, sqliteForeignKeys(t, db, table)...)
	}
	sort.Strings(snapshot.Columns)
	sort.Strings(snapshot.Indexes)
	sort.Strings(snapshot.ForeignKeys)
	return snapshot
}

func sqliteColumns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	rows, err := db.Query("PRAGMA table_info(" + table + ")")
	require.NoError(t, err)
	defer rows.Close()

	var columns []string
	for rows.Next() {
		var cid int
		var name, columnType string
		var notNull int
		var defaultValue sql.NullString
		var pk int
		require.NoError(t, rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &pk))
		columns = append(columns, fmt.Sprintf("%s.%s:type=%s:notnull=%t:default=%s:pk=%d",
			table,
			strings.ToLower(name),
			strings.ToUpper(columnType),
			notNull == 1,
			normalizeSQLDefault(defaultValue.String),
			pk,
		))
	}
	require.NoError(t, rows.Err())
	return columns
}

func sqliteIndexes(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	rows, err := db.Query("PRAGMA index_list(" + table + ")")
	require.NoError(t, err)
	defer rows.Close()

	var indexes []string
	for rows.Next() {
		var seq int
		var name string
		var unique int
		var origin string
		var partial int
		require.NoError(t, rows.Scan(&seq, &name, &unique, &origin, &partial))
		indexes = append(indexes, fmt.Sprintf("%s:unique=%t:origin=%s:columns=%s",
			table,
			unique == 1,
			strings.ToLower(origin),
			strings.Join(sqliteIndexColumns(t, db, name), ","),
		))
	}
	require.NoError(t, rows.Err())
	return indexes
}

func sqliteIndexColumns(t *testing.T, db *sql.DB, indexName string) []string {
	t.Helper()

	rows, err := db.Query("PRAGMA index_info(" + indexName + ")")
	require.NoError(t, err)
	defer rows.Close()

	type indexedColumn struct {
		seq  int
		name string
	}
	columns := make([]indexedColumn, 0)
	for rows.Next() {
		var seq, cid int
		var name string
		require.NoError(t, rows.Scan(&seq, &cid, &name))
		columns = append(columns, indexedColumn{seq: seq, name: strings.ToLower(name)})
	}
	require.NoError(t, rows.Err())

	sort.Slice(columns, func(i, j int) bool {
		return columns[i].seq < columns[j].seq
	})
	names := make([]string, 0, len(columns))
	for _, column := range columns {
		names = append(names, column.name)
	}
	return names
}

func sqliteForeignKeys(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()

	rows, err := db.Query("PRAGMA foreign_key_list(" + table + ")")
	require.NoError(t, err)
	defer rows.Close()

	var foreignKeys []string
	for rows.Next() {
		var id, seq int
		var refTable, from, to, onUpdate, onDelete, match string
		require.NoError(t, rows.Scan(&id, &seq, &refTable, &from, &to, &onUpdate, &onDelete, &match))
		foreignKeys = append(foreignKeys, fmt.Sprintf("%s.%s->%s.%s:on_update=%s:on_delete=%s:match=%s",
			table,
			strings.ToLower(from),
			strings.ToLower(refTable),
			strings.ToLower(to),
			strings.ToLower(onUpdate),
			strings.ToLower(onDelete),
			strings.ToLower(match),
		))
	}
	require.NoError(t, rows.Err())
	return foreignKeys
}

func normalizeSQLDefault(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.ReplaceAll(value, " ", "")
	return value
}

type logicalSQLSchema struct {
	Tables      map[string][]string
	Indexes     []string
	UniqueKeys  []string
	ForeignKeys []string
}

func parseLogicalSQLSchema(t *testing.T, rawSQL string) logicalSQLSchema {
	t.Helper()

	sqlText := stripLineComments(rawSQL)
	tables := extractCreateTables(t, sqlText)
	schema := logicalSQLSchema{
		Tables: make(map[string][]string, len(tables)),
	}

	for table, body := range tables {
		statements := splitTopLevelSQLList(body)
		for _, statement := range statements {
			parseTableStatement(table, statement, &schema)
		}
	}
	for _, match := range createIndexRegexp.FindAllStringSubmatch(sqlText, -1) {
		unique := strings.TrimSpace(match[1]) != ""
		indexName := strings.ToLower(match[2])
		table := strings.ToLower(match[3])
		columns := normalizeColumnList(match[4])
		if unique {
			schema.UniqueKeys = append(schema.UniqueKeys, fmt.Sprintf("%s:%s", table, strings.Join(columns, ",")))
			continue
		}
		schema.Indexes = append(schema.Indexes, fmt.Sprintf("%s:%s:%s", table, strings.Join(columns, ","), normalizeIndexName(indexName)))
	}

	normalizeLogicalSchema(&schema)
	return schema
}

var createIndexRegexp = regexp.MustCompile(`(?is)CREATE\s+(UNIQUE\s+)?INDEX(?:\s+IF\s+NOT\s+EXISTS)?\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+ON\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)

func stripLineComments(rawSQL string) string {
	lines := strings.Split(rawSQL, "\n")
	for i, line := range lines {
		if idx := strings.Index(line, "--"); idx >= 0 {
			line = line[:idx]
		}
		lines[i] = line
	}
	return strings.Join(lines, "\n")
}

func extractCreateTables(t *testing.T, sqlText string) map[string]string {
	t.Helper()

	tables := make(map[string]string)
	searchFrom := 0
	lowerSQL := strings.ToLower(sqlText)
	for {
		start := strings.Index(lowerSQL[searchFrom:], "create table")
		if start == -1 {
			break
		}
		start += searchFrom
		nameStart := start + len("create table")
		nameStart = skipSpace(sqlText, nameStart)
		if strings.HasPrefix(strings.ToLower(sqlText[nameStart:]), "if not exists") {
			nameStart += len("if not exists")
			nameStart = skipSpace(sqlText, nameStart)
		}
		nameEnd := scanIdentifier(sqlText, nameStart)
		require.Greater(t, nameEnd, nameStart, "missing table name near %q", sqlText[start:])
		table := strings.ToLower(sqlText[nameStart:nameEnd])

		openParen := strings.Index(sqlText[nameEnd:], "(")
		require.NotEqual(t, -1, openParen, "missing table body for %s", table)
		openParen += nameEnd
		closeParen := matchingParen(t, sqlText, openParen)
		tables[table] = sqlText[openParen+1 : closeParen]
		searchFrom = closeParen + 1
	}
	require.Contains(t, tables, "zones")
	require.Contains(t, tables, "records")
	return tables
}

func skipSpace(s string, offset int) int {
	for offset < len(s) && (s[offset] == ' ' || s[offset] == '\n' || s[offset] == '\r' || s[offset] == '\t') {
		offset++
	}
	return offset
}

func scanIdentifier(s string, offset int) int {
	for offset < len(s) {
		r := s[offset]
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			offset++
			continue
		}
		break
	}
	return offset
}

func matchingParen(t *testing.T, s string, openParen int) int {
	t.Helper()

	depth := 0
	inSingleQuote := false
	for i := openParen; i < len(s); i++ {
		switch s[i] {
		case '\'':
			if inSingleQuote && i+1 < len(s) && s[i+1] == '\'' {
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
		case '(':
			if !inSingleQuote {
				depth++
			}
		case ')':
			if !inSingleQuote {
				depth--
				if depth == 0 {
					return i
				}
			}
		}
	}
	t.Fatalf("missing closing parenthesis near %q", s[openParen:])
	return -1
}

func splitTopLevelSQLList(body string) []string {
	parts := make([]string, 0)
	start := 0
	depth := 0
	inSingleQuote := false
	for i := 0; i < len(body); i++ {
		switch body[i] {
		case '\'':
			if inSingleQuote && i+1 < len(body) && body[i+1] == '\'' {
				i++
				continue
			}
			inSingleQuote = !inSingleQuote
		case '(':
			if !inSingleQuote {
				depth++
			}
		case ')':
			if !inSingleQuote {
				depth--
			}
		case ',':
			if !inSingleQuote && depth == 0 {
				parts = append(parts, strings.TrimSpace(body[start:i]))
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(body[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func parseTableStatement(table string, statement string, schema *logicalSQLSchema) {
	normalized := normalizeSQLWhitespace(statement)
	lowerStatement := strings.ToLower(normalized)
	if lowerStatement == "" {
		return
	}

	switch {
	case strings.HasPrefix(lowerStatement, "foreign key"):
		parseForeignKey(table, normalized, schema)
	case strings.HasPrefix(lowerStatement, "unique"):
		parseUniqueKey(table, normalized, schema)
	case strings.HasPrefix(lowerStatement, "index") || strings.HasPrefix(lowerStatement, "key"):
		parseInlineIndex(table, normalized, schema)
	default:
		parseColumnStatement(table, normalized, schema)
	}
}

func parseColumnStatement(table string, statement string, schema *logicalSQLSchema) {
	parts := strings.Fields(statement)
	if len(parts) == 0 {
		return
	}
	column := strings.ToLower(strings.Trim(parts[0], "`\""))
	schema.Tables[table] = append(schema.Tables[table], column)

	lowerStatement := strings.ToLower(statement)
	if strings.Contains(lowerStatement, " unique ") {
		schema.UniqueKeys = append(schema.UniqueKeys, fmt.Sprintf("%s:%s", table, column))
	}
	if strings.Contains(lowerStatement, " references ") {
		parseColumnForeignKey(table, column, statement, schema)
	}
}

func parseForeignKey(table string, statement string, schema *logicalSQLSchema) {
	foreignKey := foreignKeyRegexp.FindStringSubmatch(statement)
	if len(foreignKey) == 0 {
		return
	}
	localColumns := normalizeColumnList(foreignKey[1])
	refTable := strings.ToLower(foreignKey[2])
	refColumns := normalizeColumnList(foreignKey[3])
	onDelete := "none"
	if strings.Contains(strings.ToLower(statement), "on delete cascade") {
		onDelete = "cascade"
	}
	schema.ForeignKeys = append(schema.ForeignKeys, fmt.Sprintf("%s:%s->%s:%s:on_delete=%s",
		table,
		strings.Join(localColumns, ","),
		refTable,
		strings.Join(refColumns, ","),
		onDelete,
	))
}

func parseColumnForeignKey(table string, column string, statement string, schema *logicalSQLSchema) {
	foreignKey := columnReferencesRegexp.FindStringSubmatch(statement)
	if len(foreignKey) == 0 {
		return
	}
	refTable := strings.ToLower(foreignKey[1])
	refColumns := normalizeColumnList(foreignKey[2])
	onDelete := "none"
	if strings.Contains(strings.ToLower(statement), "on delete cascade") {
		onDelete = "cascade"
	}
	schema.ForeignKeys = append(schema.ForeignKeys, fmt.Sprintf("%s:%s->%s:%s:on_delete=%s",
		table,
		column,
		refTable,
		strings.Join(refColumns, ","),
		onDelete,
	))
}

func parseUniqueKey(table string, statement string, schema *logicalSQLSchema) {
	openParen := strings.Index(statement, "(")
	closeParen := strings.LastIndex(statement, ")")
	if openParen == -1 || closeParen == -1 || closeParen <= openParen {
		return
	}
	columns := normalizeColumnList(statement[openParen+1 : closeParen])
	schema.UniqueKeys = append(schema.UniqueKeys, fmt.Sprintf("%s:%s", table, strings.Join(columns, ",")))
}

func parseInlineIndex(table string, statement string, schema *logicalSQLSchema) {
	index := inlineIndexRegexp.FindStringSubmatch(statement)
	if len(index) == 0 {
		return
	}
	indexName := normalizeIndexName(index[1])
	columns := normalizeColumnList(index[2])
	schema.Indexes = append(schema.Indexes, fmt.Sprintf("%s:%s:%s", table, strings.Join(columns, ","), indexName))
}

var (
	foreignKeyRegexp       = regexp.MustCompile(`(?is)FOREIGN\s+KEY\s*\(([^)]*)\)\s+REFERENCES\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)
	columnReferencesRegexp = regexp.MustCompile(`(?is)REFERENCES\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)
	inlineIndexRegexp      = regexp.MustCompile(`(?is)(?:INDEX|KEY)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)`)
)

func normalizeSQLWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func normalizeColumnList(value string) []string {
	columns := splitTopLevelSQLList(value)
	for i, column := range columns {
		column = strings.TrimSpace(column)
		column = strings.Trim(column, "`\"")
		columns[i] = strings.ToLower(column)
	}
	return columns
}

func normalizeIndexName(indexName string) string {
	indexName = strings.ToLower(indexName)
	replacer := strings.NewReplacer(
		"idx_zones_", "idx_",
		"idx_records_", "idx_",
		"unique_record", "idx_unique",
		"idx_records_unique", "idx_unique",
	)
	return replacer.Replace(indexName)
}

func normalizeLogicalSchema(schema *logicalSQLSchema) {
	for table, columns := range schema.Tables {
		sort.Strings(columns)
		schema.Tables[table] = columns
	}
	sort.Strings(schema.Indexes)
	sort.Strings(schema.UniqueKeys)
	sort.Strings(schema.ForeignKeys)
}
