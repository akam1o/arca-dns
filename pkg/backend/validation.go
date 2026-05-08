package backend

import (
	"fmt"

	"github.com/akam1o/arca-dns/pkg/model"
)

func validateZoneForWrite(zone *model.Zone) error {
	if err := model.NormalizeZoneDerivedFields(zone); err != nil {
		return fmt.Errorf("normalize zone: %w", err)
	}
	if err := model.ValidateZone(zone); err != nil {
		return fmt.Errorf("validate zone: %w", err)
	}
	return nil
}
