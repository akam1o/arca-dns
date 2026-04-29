package dnssec

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/akam1o/arca-dns/pkg/model"
)

// GenerateZoneKeys ensures (or rotates) both KSK and ZSK for a zone.
// If rotate is true, new keys are always generated and become active.
func (km *KeyManager) GenerateZoneKeys(zone string, rotate bool) (ksk *KeyPair, zsk *KeyPair, err error) {
	if !rotate {
		return km.EnsureZoneKeys(zone)
	}

	ksk, err = km.GenerateKSK(zone)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ksk: %w", err)
	}
	zsk, err = km.GenerateZSK(zone)
	if err != nil {
		return nil, nil, fmt.Errorf("generate zsk: %w", err)
	}
	return ksk, zsk, nil
}

// RemoveOldKeys deletes non-active key files for a zone.
// This is intended for post-rollover cleanup once DS has been updated at the parent.
// It keeps only the key files referenced by active.json.
func (km *KeyManager) RemoveOldKeys(zone string) (removedFiles int, err error) {
	zoneFQDN, err := NormalizeZoneFQDN(zone)
	if err != nil {
		return 0, err
	}

	zoneDir, err := km.getZoneDir(zoneFQDN)
	if err != nil {
		return 0, err
	}

	activePath := filepath.Join(zoneDir, "active.json")
	activeData, err := os.ReadFile(activePath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, model.ErrZoneNotFound
		}
		return 0, fmt.Errorf("read active.json: %w", err)
	}

	var active struct {
		Algorithm    uint8  `json:"algorithm"`
		ActiveKSKTag uint16 `json:"active_ksk_key_tag"`
		ActiveZSKTag uint16 `json:"active_zsk_key_tag"`
	}
	if err := json.Unmarshal(activeData, &active); err != nil {
		return 0, fmt.Errorf("parse active.json: %w", err)
	}

	keep := map[uint16]bool{}
	if active.ActiveKSKTag != 0 {
		keep[active.ActiveKSKTag] = true
	}
	if active.ActiveZSKTag != 0 {
		keep[active.ActiveZSKTag] = true
	}

	zoneName, err := ZoneNameForFile(zoneFQDN)
	if err != nil {
		return 0, err
	}
	prefix := fmt.Sprintf("K%s.+%03d+", zoneName, active.Algorithm)

	entries, err := os.ReadDir(zoneDir)
	if err != nil {
		return 0, fmt.Errorf("read zone key dir: %w", err)
	}

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		if !(strings.HasSuffix(name, ".key") || strings.HasSuffix(name, ".private.enc")) {
			continue
		}

		tag, ok := parseKeyTagFromFilename(prefix, name)
		if !ok {
			continue
		}
		if keep[tag] {
			continue
		}

		if err := os.Remove(filepath.Join(zoneDir, name)); err != nil {
			return removedFiles, fmt.Errorf("remove key file %q: %w", name, err)
		}
		removedFiles++
	}

	return removedFiles, nil
}

func parseKeyTagFromFilename(prefix string, filename string) (uint16, bool) {
	rest := strings.TrimPrefix(filename, prefix)
	// Expected: "12345.key" or "12345.private.enc"
	if len(rest) < 5 {
		return 0, false
	}
	tagStr := rest[:5]
	tagInt, err := strconv.Atoi(tagStr)
	if err != nil || tagInt < 0 || tagInt > 65535 {
		return 0, false
	}
	return uint16(tagInt), true
}
