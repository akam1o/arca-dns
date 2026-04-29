package model

import (
	"fmt"
	"time"

	"github.com/akam1o/arca-dns/pkg/util"
)

// NewZoneVersion generates a new controller-issued version identifier.
// Format: v{ULID} (example: "v01ARZ3NDEKTSV4RRFFQ69G5FAV").
func NewZoneVersion() (string, error) {
	id, err := util.NewULID(time.Now())
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("v%s", id), nil
}
