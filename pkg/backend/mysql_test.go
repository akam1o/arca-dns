package backend

import (
	"fmt"
	"testing"

	gomysql "github.com/go-sql-driver/mysql"
	"github.com/stretchr/testify/assert"
)

func TestIsMySQLDeadlockRecognizesTransientErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "deadlock driver error",
			err:  &gomysql.MySQLError{Number: 1213, Message: "Deadlock found when trying to get lock"},
			want: true,
		},
		{
			name: "lock wait timeout driver error",
			err:  &gomysql.MySQLError{Number: 1205, Message: "Lock wait timeout exceeded"},
			want: true,
		},
		{
			name: "wrapped transient driver error",
			err:  fmt.Errorf("commit transaction: %w", &gomysql.MySQLError{Number: 1205, Message: "Lock wait timeout exceeded"}),
			want: true,
		},
		{
			name: "duplicate key is not retryable",
			err:  &gomysql.MySQLError{Number: 1062, Message: "Duplicate entry"},
			want: false,
		},
		{
			name: "legacy deadlock text",
			err:  fmt.Errorf("mysql failed: Error 1213"),
			want: true,
		},
		{
			name: "generic error",
			err:  fmt.Errorf("connection refused"),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isMySQLDeadlock(tc.err))
		})
	}
}
