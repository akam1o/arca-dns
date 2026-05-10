# DNSSEC Key Management Guide

English | [日本語](dnssec.ja.md)

This document describes how to manage DNSSEC keys for arca-dns, including key generation, rotation, backup, and recovery procedures.

## Table of Contents

- [Overview](#overview)
- [Master Key Management](#master-key-management)
- [Zone Key Generation](#zone-key-generation)
- [Exporting DS Records](#exporting-ds-records)
- [Key Rotation](#key-rotation)
- [Backup and Recovery](#backup-and-recovery)
- [Security Considerations](#security-considerations)
- [Troubleshooting](#troubleshooting)

## Overview

arca-dns implements central DNSSEC signing at the controller, with the following architecture:

- **KSK (Key Signing Key)**: Signs the DNSKEY RRset
- **ZSK (Zone Signing Key)**: Signs all other RRsets in the zone
- **Algorithm**: ECDSA-P256-SHA256 (algorithm 13) by default, RSA-SHA256 (algorithm 8) also supported
- **Master Key**: AES-256 key used to encrypt private keys at rest

All private keys are encrypted using AES-256-GCM with authenticated metadata (AAD) to prevent tampering.

## Master Key Management

### Production Deployment

For production environments, provide the master key via environment variable:

```bash
# Generate a random 32-byte master key
python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())"
# Output: e.g., Q0TV7fRu9QMZKg810KOiokVTJrJDSVPqgaOBxHKNX5U=

# Set environment variable
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="Q0TV7fRu9QMZKg810KOiokVTJrJDSVPqgaOBxHKNX5U="
```

Store the master key securely:
- **Kubernetes**: Store in Secret, reference in pod spec
- **Systemd**: Use `EnvironmentFile=` with restricted permissions
- **Docker**: Pass via `-e` flag or Docker secrets
- **Vault/KMS**: Future enhancement (M7+)

### Development Environment

For development, the controller can auto-generate a master key on first startup:

```yaml
# config.yaml
dnssec:
  enabled: true
  key_directory: ./keys
```

The master key will be stored in `./keys/_masterkey` with 0600 permissions.

**⚠️ Warning**: Auto-generation is NOT recommended for production.

### Master Key Priority

The controller loads the master key in the following priority order:

1. **Environment variable**: `ARCA_DNS_DNSSEC_MASTER_KEY_B64`
2. **File**: `{key_directory}/_masterkey`
3. **Auto-generate**: Only if `AllowAutoGenerate` is true (dev mode)

## Zone Key Generation

### Automatic Generation

Keys are automatically generated when you create or update a zone via the API. The controller ensures both KSK and ZSK exist before signing.

### Manual Generation

To pre-generate keys for a zone:

```go
package main

import (
	"fmt"
	"os"
	"github.com/akam1o/arca-dns/pkg/dnssec"
)

func main() {
	// Load master key
	masterKeyB64, _ := os.ReadFile("/var/lib/arca-dns/keys/_masterkey")
	masterKey, _ := dnssec.ParseMasterKeyB64(string(masterKeyB64))

	// Create key manager
	km, _ := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: "/var/lib/arca-dns/keys",
		MasterKey:    masterKey,
		Algorithm:    13, // ECDSA-P256
	})

	// Generate keys for zone
	ksk, zsk, err := km.EnsureZoneKeys("example.com")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Generated KSK: key tag %d\n", ksk.ID.KeyTag)
	fmt.Printf("Generated ZSK: key tag %d\n", zsk.ID.KeyTag)
}
```

### Key Storage Format

Keys are stored in a zone-specific directory:

```
{key_directory}/
└── example.com/
    ├── active.json                        # Current active key tags
    ├── Kexample.com.+013+12345.key        # KSK public key (BIND format)
    ├── Kexample.com.+013+12345.private.enc # KSK private key (encrypted)
    ├── Kexample.com.+013+54321.key        # ZSK public key (BIND format)
    └── Kexample.com.+013+54321.private.enc # ZSK private key (encrypted)
```

**File Permissions**:
- Public keys (`.key`): 0644
- Private keys (`.private.enc`): 0600
- Directory: 0700
- Master key: 0600

## Exporting DS Records

After generating a KSK, you must submit the DS record to your parent zone for DNSSEC chain of trust.

### Export DS Record

```bash
# Export in BIND format (default)
arca-dns-controller dnssec export-ds example.com

# Export in JSON format
arca-dns-controller dnssec export-ds example.com --format json

# Use SHA-384 digest (default is SHA-256)
arca-dns-controller dnssec export-ds example.com --digest 4

# Use custom config file
arca-dns-controller dnssec export-ds example.com --config /etc/arca-dns/controller.yaml
```

### Example Output

**BIND format**:
```
example.com. 3600 IN DS 12345 13 2 A1B2C3D4E5F6...
```

**JSON format**:
```json
{
  "name": "example.com.",
  "ttl": 3600,
  "class": "IN",
  "type": "DS",
  "key_tag": 12345,
  "algorithm": 13,
  "digest_type": 2,
  "digest": "A1B2C3D4E5F6..."
}
```

### Submit to Parent Zone

1. Export the DS record as shown above
2. Submit the DS record to your registrar or parent zone operator
3. Wait for the parent zone to publish the DS record
4. Verify the DNSSEC chain: `dig +dnssec example.com SOA`

## Key Rotation

DNSSEC key rotation should be performed periodically for security best practices.

### KSK Rotation (Manual Procedure)

⚠️ **Important**: KSK rotation requires coordination with the parent zone.

**Timeline**: Allow 2× parent zone TTL between steps.

The current release does not support a fully automatic pre-publish or double-signature rollover. `generate-keys --rotate --activate-now` makes the new KSK/ZSK active immediately, so any scheduler run, zone update, record update, or on-demand re-sign before the parent publishes the new DS can break validation.

1. **Enter a controlled maintenance window** (before Day 0)
   - Disable the DNSSEC scheduler or stop controller instances that can re-sign zones.
   - Prevent zone and record writes for the zone being rotated.
   - Keep the existing signed artifact available; do not purge artifact storage during the DS publication window.

2. **Generate and activate a new key pair** (Day 0)
   ```bash
   # --activate-now confirms that the new KSK/ZSK should become active immediately.
   arca-dns-controller dnssec generate-keys --zone example.com. --rotate --activate-now
   ```
   This updates `active.json`; it does not by itself replace a cached signed zone artifact.

3. **Export new DS record**
   ```bash
   arca-dns-controller dnssec export-ds --zone example.com. > new-ds.txt
   ```

4. **Submit new DS to parent zone** (Day 0)
   - Submit to registrar
   - Keep old DS record active (both old and new DS records should coexist)

5. **Wait for parent zone propagation** (Day 0 + parent TTL)
   - Verify with: `dig +dnssec example.com DS`
   - Do not resume scheduler or allow zone/record writes until the new DS is visible from public resolvers.

6. **Trigger re-signing with the active keys** (after the new DS is visible)
   ```bash
   BASE="https://controller/api/v1"
   API_KEY="your-api-key"

   zone_json="$(curl -s "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}")"
   etag="$(curl -sI "${BASE}/zones/example.com." -H "X-API-Key: ${API_KEY}" | awk -F': ' 'tolower($1)=="etag"{print $2}' | tr -d '\r')"

   printf '%s' "${zone_json}" | jq '{name: .name, soa: .soa}' |
     curl -X PUT "${BASE}/zones/example.com." \
       -H "X-API-Key: ${API_KEY}" \
       -H "Content-Type: application/json" \
       -H "If-Match: ${etag}" \
       --data-binary @-
   ```
   `PUT /zones/:name` preserves records; it is used here only to bump the zone version and re-sign with the already rotated keys.
   After verifying the new signed zone, resume the scheduler and normal zone/record writes.

7. **Remove old DS from parent zone** (Day 0 + 3× parent TTL)
   - Request removal from registrar
   - After old signatures have expired, remove inactive key files:
     ```bash
     arca-dns-controller dnssec remove-old-keys --zone example.com.
     ```

### ZSK Rotation (Simplified)

ZSK rotation does not require parent zone coordination, but the current CLI rotates KSK and ZSK together when `--rotate --activate-now` is used. Treat it as a combined rollover and follow the KSK procedure above whenever the KSK changes.

**Timeline**: Allow 2× zone maximum TTL between steps.

1. **Generate and activate new keys**
   ```bash
   arca-dns-controller dnssec generate-keys --zone example.com. --rotate --activate-now
   ```

2. **Trigger re-signing**
   - Use the same `PUT /zones/:name` re-signing step from the KSK procedure.

3. **Wait for old signatures to expire** (Day 0 + 2× max TTL)

4. **Remove inactive key files**
   ```bash
   arca-dns-controller dnssec remove-old-keys --zone example.com.
   ```

**Note**: Automated key rotation and double-signature rollover are not implemented in the current release.

## Backup and Recovery

### Backup Procedures

**Critical files to backup**:
1. Master key: `{key_directory}/_masterkey`
2. All zone key files: `{key_directory}/*/*.key` and `{key_directory}/*/*.private.enc`
3. Active key tracking: `{key_directory}/*/active.json`

**Backup script example**:
```bash
#!/bin/bash
KEY_DIR="/var/lib/arca-dns/keys"
BACKUP_DIR="/backup/arca-dns-keys-$(date +%Y%m%d-%H%M%S)"

mkdir -p "$BACKUP_DIR"
cp -r "$KEY_DIR" "$BACKUP_DIR/"
chmod 700 "$BACKUP_DIR"

# Encrypt backup (recommended)
tar czf - "$BACKUP_DIR" | \
  openssl enc -aes-256-cbc -salt -pbkdf2 -out "$BACKUP_DIR.tar.gz.enc"

# Securely delete unencrypted backup
rm -rf "$BACKUP_DIR"
```

**Backup frequency**:
- Master key: Immediately after generation, then monthly
- Zone keys: After each key generation or rotation
- Full backup: Daily

### Recovery Procedures

**Scenario 1: Lost key files, but have backup**

1. Stop the controller
2. Restore key files from backup
3. Verify file permissions (0600 for private keys, 0700 for directories)
4. Start the controller
5. Verify DNSSEC signatures: `dig +dnssec example.com SOA`

**Scenario 2: Lost master key, but have backup**

1. Stop the controller
2. Restore `_masterkey` file with correct permissions (0600)
3. Set environment variable if using that method
4. Start the controller

**Scenario 3: Complete key loss**

If you lose both the master key and all backups:

1. Generate new master key
2. Generate new KSK and ZSK for all zones
3. Export new DS records for all zones
4. Submit new DS records to parent zones
5. **⚠️ DNSSEC will be broken until parent zones publish new DS records**

## Security Considerations

### Encryption

- Private keys are encrypted using **AES-256-GCM**
- Authenticated metadata (AAD) prevents tampering with zone/algorithm/key_tag/role fields
- Nonce length is validated to prevent panic attacks
- All writes are atomic (tmp + rename) to prevent corruption

### Key Storage

- Master key: Keep secure, never commit to version control
- Private keys: Encrypted at rest, restricted file permissions
- Public keys: Can be safely shared, included in DNS responses

### Access Control

- Limit access to key directory (chmod 700)
- Master key should only be readable by controller process
- Use separate master keys for dev/staging/production

### Monitoring

Monitor these events:
- Master key load failures
- Key decryption failures
- Missing key files
- Permission errors on key directory

## Troubleshooting

### "Master key not found"

**Cause**: No master key in environment variable or file, and auto-generation is disabled.

**Solution**:
```bash
# Option 1: Set environment variable
export ARCA_DNS_DNSSEC_MASTER_KEY_B64="<your-key-here>"

# Option 2: Create master key file
python3 -c "import os, base64; print(base64.b64encode(os.urandom(32)).decode())" \
  > /var/lib/arca-dns/keys/_masterkey
chmod 600 /var/lib/arca-dns/keys/_masterkey
```

### "Decryption failed"

**Cause**: Wrong master key, or corrupted key file.

**Solution**:
1. Verify master key is correct
2. Check file integrity
3. Restore from backup if corrupted

### "Invalid nonce length"

**Cause**: Corrupted encrypted key file.

**Solution**:
1. Restore from backup
2. If no backup, regenerate keys and update parent zone DS records

### Permission Errors

**Cause**: Incorrect file permissions.

**Solution**:
```bash
# Fix permissions
chmod 700 /var/lib/arca-dns/keys
chmod 700 /var/lib/arca-dns/keys/*
chmod 644 /var/lib/arca-dns/keys/*/*.key
chmod 600 /var/lib/arca-dns/keys/*/*.private.enc
chmod 600 /var/lib/arca-dns/keys/_masterkey
```

### DNSSEC Validation Failures

**Symptoms**: `dig +dnssec` shows SERVFAIL or BOGUS status.

**Debug steps**:
1. Check if DS record is published in parent zone: `dig example.com DS`
2. Verify DNSKEY records: `dig example.com DNSKEY +dnssec`
3. Check RRSIG records: `dig example.com SOA +dnssec`
4. Validate chain: `delv example.com SOA`

## Additional Resources

- [RFC 4033](https://tools.ietf.org/html/rfc4033) - DNS Security Introduction
- [RFC 4034](https://tools.ietf.org/html/rfc4034) - Resource Records for DNSSEC
- [RFC 4035](https://tools.ietf.org/html/rfc4035) - Protocol Modifications for DNSSEC
- [RFC 5155](https://tools.ietf.org/html/rfc5155) - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
- [RFC 6781](https://tools.ietf.org/html/rfc6781) - DNSSEC Operational Practices

---

**Version**: M4.1
**Last Updated**: 2025-12-28
