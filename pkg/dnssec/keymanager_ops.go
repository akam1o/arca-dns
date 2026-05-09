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
// If rotate is true, new keys are always generated and become active together.
func (km *KeyManager) GenerateZoneKeys(zone string, rotate bool) (ksk *KeyPair, zsk *KeyPair, err error) {
	if !rotate {
		return km.EnsureZoneKeys(zone)
	}

	err = km.withZoneKeyLock(zone, true, func(zoneFQDN string) error {
		var err error
		ksk, err = km.generateKeyLocked(zoneFQDN, KeyRoleKSK, km.kskBits, dnskeyKSKFlags, false)
		if err != nil {
			return fmt.Errorf("generate ksk: %w", err)
		}
		zsk, err = km.generateKeyLocked(zoneFQDN, KeyRoleZSK, km.zskBits, dnskeyZSKFlags, false)
		if err != nil {
			return fmt.Errorf("generate zsk: %w", err)
		}
		if err := km.writeActiveKeys(ksk.ID.Zone, activeKeys{
			Algorithm:    km.algorithm,
			ActiveKSKTag: ksk.ID.KeyTag,
			ActiveZSKTag: zsk.ID.KeyTag,
		}); err != nil {
			return fmt.Errorf("activate rotated keys: %w", err)
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	return ksk, zsk, nil
}

// RemoveOldKeys deletes non-active key files for a zone.
// This is intended for post-rollover cleanup once DS has been updated at the parent.
// It keeps only the key files referenced by active.json.
func (km *KeyManager) RemoveOldKeys(zone string) (removedFiles int, err error) {
	err = km.withZoneKeyLock(zone, false, func(zoneFQDN string) error {
		zoneDir, err := km.getZoneDir(zoneFQDN)
		if err != nil {
			return err
		}

		activePath := filepath.Join(zoneDir, "active.json")
		activeData, err := os.ReadFile(activePath)
		if err != nil {
			if os.IsNotExist(err) {
				return model.ErrZoneNotFound
			}
			return fmt.Errorf("read active.json: %w", err)
		}

		var active struct {
			Algorithm    uint8  `json:"algorithm"`
			ActiveKSKTag uint16 `json:"active_ksk_key_tag"`
			ActiveZSKTag uint16 `json:"active_zsk_key_tag"`
		}
		if err := json.Unmarshal(activeData, &active); err != nil {
			return fmt.Errorf("parse active.json: %w", err)
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
			return err
		}
		prefix := fmt.Sprintf("K%s.+%03d+", zoneName, active.Algorithm)

		entries, err := os.ReadDir(zoneDir)
		if err != nil {
			return fmt.Errorf("read zone key dir: %w", err)
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
				return fmt.Errorf("remove key file %q: %w", name, err)
			}
			removedFiles++
		}

		return syncDir(zoneDir)
	})
	return removedFiles, err
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
