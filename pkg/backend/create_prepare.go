package backend

import (
	"fmt"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
)

func prepareZoneForCreate(zone *model.Zone, normalize func(string) string) (*model.Zone, error) {
	writeZone := copyZone(zone)
	if writeZone == nil {
		return nil, validateZoneForWrite(writeZone)
	}

	writeZone.Name = normalize(writeZone.Name)
	if writeZone.SOA.Serial == 0 {
		writeZone.SOA.Serial = generateSerial(0)
	}
	if writeZone.Version == "" {
		version, err := model.NewZoneVersion()
		if err != nil {
			return nil, fmt.Errorf("generate zone version: %w", err)
		}
		writeZone.Version = version
	}

	now := time.Now()
	writeZone.CreatedAt = now
	writeZone.UpdatedAt = now

	if err := validateZoneForWrite(writeZone); err != nil {
		return nil, err
	}
	return writeZone, nil
}

func copyZoneInto(dst *model.Zone, src *model.Zone) {
	if dst == nil || src == nil {
		return
	}
	copied := copyZone(src)
	*dst = *copied
}
