package sync

import (
	"path/filepath"

	"github.com/akam1o/arca-dns/pkg/util"
)

// SafeZoneFilename converts a DNS zone name to a safe filename.
// This is a convenience wrapper around util.SafeZoneFilename.
func SafeZoneFilename(zoneName string) string {
	return util.SafeZoneFilename(zoneName)
}

// ZoneFilePath returns the full path to a zone file with safe filename.
func ZoneFilePath(zoneDir string, zoneName string) string {
	safeName := SafeZoneFilename(zoneName)
	return filepath.Join(zoneDir, safeName+".zone")
}

// ZoneBackupPattern returns the glob pattern for zone backup files.
func ZoneBackupPattern(zoneDir string, zoneName string) string {
	safeName := SafeZoneFilename(zoneName)
	return filepath.Join(zoneDir, safeName+".zone.backup.*")
}
