package backend

import "testing"

func TestSQLPlaceholders(t *testing.T) {
	if got := sqlQuestionPlaceholders(0); got != "" {
		t.Fatalf("sqlQuestionPlaceholders(0) = %q, want empty string", got)
	}
	if got := sqlQuestionPlaceholders(3); got != "?,?,?" {
		t.Fatalf("sqlQuestionPlaceholders(3) = %q, want ?,?,?", got)
	}
	if got := sqlNumberedPlaceholders(3, 3); got != "$3,$4,$5" {
		t.Fatalf("sqlNumberedPlaceholders(3, 3) = %q, want $3,$4,$5", got)
	}
	if got := sqlNumberedPlaceholders(1, 0); got != "" {
		t.Fatalf("sqlNumberedPlaceholders(1, 0) = %q, want empty string", got)
	}
}
