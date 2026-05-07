package backend

import (
	"fmt"

	"github.com/akam1o/arca-dns/pkg/model"
)

func ensureZoneUpdateVersion(zone *model.Zone, currentVersion string) error {
	if zone.Version != "" && zone.Version != currentVersion {
		return nil
	}

	newVersion, err := model.NewZoneVersion()
	if err != nil {
		return fmt.Errorf("generate zone version: %w", err)
	}
	zone.Version = newVersion
	return nil
}
