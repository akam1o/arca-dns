package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/dnssec"
	"github.com/miekg/dns"
	"github.com/spf13/cobra"
)

// NewDNSSECCmd creates the dnssec command with subcommands.
func NewDNSSECCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnssec",
		Short: "DNSSEC key management commands",
		Long:  "Commands for managing DNSSEC keys, exporting DS records, and key operations",
	}

	cmd.AddCommand(newExportDSCmd())
	cmd.AddCommand(newGenerateKeysCmd())
	cmd.AddCommand(newRemoveOldKeysCmd())

	return cmd
}

func newExportDSCmd() *cobra.Command {
	var (
		configFile   string
		zoneFlag     string
		digestType   uint8
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "export-ds [ZONE]",
		Short: "Export DS record for a zone's KSK",
		Long: `Export the DS (Delegation Signer) record for a zone's Key Signing Key (KSK).
The DS record should be submitted to the parent zone for DNSSEC chain of trust.

The zone name can be specified with or without a trailing dot.`,
		Args: cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zoneName := zoneFlag
			if zoneName == "" && len(args) == 1 {
				zoneName = args[0]
			}
			if zoneName == "" {
				return fmt.Errorf("zone is required (pass ZONE arg or --zone)")
			}
			return runExportDS(configFile, zoneName, digestType, outputFormat)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().StringVar(&zoneFlag, "zone", "", "Zone name (alternative to positional argument)")
	cmd.Flags().Uint8VarP(&digestType, "digest", "d", 2, "Digest type (2=SHA-256, 4=SHA-384)")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "bind", "Output format (bind, json)")

	return cmd
}

func runExportDS(configFile string, zoneName string, digestType uint8, outputFormat string) error {
	cfg, err := config.LoadControllerConfig(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !cfg.DNSSEC.Enabled {
		return fmt.Errorf("DNSSEC is not enabled in configuration")
	}

	masterKey, src, err := dnssec.LoadMasterKey(dnssec.MasterKeyOptions{
		KeyDirectory:      cfg.DNSSEC.KeyDirectory,
		AllowAutoGenerate: false, // Production mode: don't auto-generate
	})
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}
	if src == dnssec.MasterKeySourceEnv {
		fmt.Fprintf(os.Stderr, "Using master key from environment variable\n")
	} else if src == dnssec.MasterKeySourceFile {
		fmt.Fprintf(os.Stderr, "Using master key from file\n")
	}

	km, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: cfg.DNSSEC.KeyDirectory,
		MasterKey:    masterKey,
		Algorithm:    cfg.DNSSEC.Algorithm,
		KSKBits:      cfg.DNSSEC.KSKKeySize,
		ZSKBits:      cfg.DNSSEC.ZSKKeySize,
	})
	if err != nil {
		return fmt.Errorf("create key manager: %w", err)
	}

	ds, err := km.ExportDS(zoneName, digestType)
	if err != nil {
		return fmt.Errorf("export DS record: %w", err)
	}

	if err := outputDS(os.Stdout, ds, outputFormat); err != nil {
		return fmt.Errorf("output DS record: %w", err)
	}

	fmt.Fprintf(os.Stderr, "\nDS record exported successfully\n")
	fmt.Fprintf(os.Stderr, "Zone: %s\n", ds.Hdr.Name)
	fmt.Fprintf(os.Stderr, "Key Tag: %d\n", ds.KeyTag)
	fmt.Fprintf(os.Stderr, "Algorithm: %d (%s)\n", ds.Algorithm, dnssec.AlgorithmName(ds.Algorithm))
	fmt.Fprintf(os.Stderr, "Digest Type: %d\n", ds.DigestType)

	return nil
}

func newGenerateKeysCmd() *cobra.Command {
	var (
		configFile string
		zoneFlag   string
		rotate     bool
	)

	cmd := &cobra.Command{
		Use:   "generate-keys [ZONE]",
		Short: "Generate KSK/ZSK for a zone",
		Long:  "Generate DNSSEC keys for a zone. If keys already exist, it is a no-op unless --rotate is set.",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zoneName := zoneFlag
			if zoneName == "" && len(args) == 1 {
				zoneName = args[0]
			}
			if zoneName == "" {
				return fmt.Errorf("zone is required (pass ZONE arg or --zone)")
			}
			return runGenerateKeys(configFile, zoneName, rotate)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().StringVar(&zoneFlag, "zone", "", "Zone name (alternative to positional argument)")
	cmd.Flags().BoolVar(&rotate, "rotate", false, "Always generate new keys and activate them")

	return cmd
}

func runGenerateKeys(configFile string, zoneName string, rotate bool) error {
	cfg, err := config.LoadControllerConfig(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !cfg.DNSSEC.Enabled {
		return fmt.Errorf("DNSSEC is not enabled in configuration")
	}

	masterKey, _, err := dnssec.LoadMasterKey(dnssec.MasterKeyOptions{
		KeyDirectory:      cfg.DNSSEC.KeyDirectory,
		AllowAutoGenerate: cfg.DNSSEC.MasterKeyAutoGenerate,
	})
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	km, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: cfg.DNSSEC.KeyDirectory,
		MasterKey:    masterKey,
		Algorithm:    cfg.DNSSEC.Algorithm,
		KSKBits:      cfg.DNSSEC.KSKKeySize,
		ZSKBits:      cfg.DNSSEC.ZSKKeySize,
	})
	if err != nil {
		return fmt.Errorf("create key manager: %w", err)
	}

	ksk, zsk, err := km.GenerateZoneKeys(zoneName, rotate)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Keys ready\n")
	fmt.Fprintf(os.Stderr, "Zone: %s\n", ksk.ID.Zone)
	fmt.Fprintf(os.Stderr, "Algorithm: %d (%s)\n", ksk.ID.Algorithm, dnssec.AlgorithmName(ksk.ID.Algorithm))
	fmt.Fprintf(os.Stderr, "KSK KeyTag: %d\n", ksk.ID.KeyTag)
	fmt.Fprintf(os.Stderr, "ZSK KeyTag: %d\n", zsk.ID.KeyTag)

	return nil
}

func newRemoveOldKeysCmd() *cobra.Command {
	var (
		configFile string
		zoneFlag   string
	)

	cmd := &cobra.Command{
		Use:   "remove-old-keys [ZONE]",
		Short: "Remove inactive DNSSEC key files for a zone",
		Long:  "Remove DNSSEC key files that are no longer active according to active.json (post-rollover cleanup).",
		Args:  cobra.RangeArgs(0, 1),
		RunE: func(cmd *cobra.Command, args []string) error {
			zoneName := zoneFlag
			if zoneName == "" && len(args) == 1 {
				zoneName = args[0]
			}
			if zoneName == "" {
				return fmt.Errorf("zone is required (pass ZONE arg or --zone)")
			}
			return runRemoveOldKeys(configFile, zoneName)
		},
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().StringVar(&zoneFlag, "zone", "", "Zone name (alternative to positional argument)")

	return cmd
}

func runRemoveOldKeys(configFile string, zoneName string) error {
	cfg, err := config.LoadControllerConfig(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	if !cfg.DNSSEC.Enabled {
		return fmt.Errorf("DNSSEC is not enabled in configuration")
	}

	masterKey, _, err := dnssec.LoadMasterKey(dnssec.MasterKeyOptions{
		KeyDirectory:      cfg.DNSSEC.KeyDirectory,
		AllowAutoGenerate: false,
	})
	if err != nil {
		return fmt.Errorf("load master key: %w", err)
	}

	km, err := dnssec.NewKeyManager(dnssec.KeyManagerOptions{
		KeyDirectory: cfg.DNSSEC.KeyDirectory,
		MasterKey:    masterKey,
		Algorithm:    cfg.DNSSEC.Algorithm,
		KSKBits:      cfg.DNSSEC.KSKKeySize,
		ZSKBits:      cfg.DNSSEC.ZSKKeySize,
	})
	if err != nil {
		return fmt.Errorf("create key manager: %w", err)
	}

	removed, err := km.RemoveOldKeys(zoneName)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Removed %d inactive key file(s)\n", removed)
	return nil
}

// outputDS outputs the DS record in the specified format.
func outputDS(w io.Writer, ds *dns.DS, format string) error {
	switch format {
	case "bind":
		fmt.Fprintf(w, "%s\n", ds.String())
		return nil
	case "json":
		fmt.Fprintf(w, "{\n")
		fmt.Fprintf(w, "  \"name\": \"%s\",\n", ds.Hdr.Name)
		fmt.Fprintf(w, "  \"ttl\": %d,\n", ds.Hdr.Ttl)
		fmt.Fprintf(w, "  \"class\": \"IN\",\n")
		fmt.Fprintf(w, "  \"type\": \"DS\",\n")
		fmt.Fprintf(w, "  \"key_tag\": %d,\n", ds.KeyTag)
		fmt.Fprintf(w, "  \"algorithm\": %d,\n", ds.Algorithm)
		fmt.Fprintf(w, "  \"digest_type\": %d,\n", ds.DigestType)
		fmt.Fprintf(w, "  \"digest\": \"%s\"\n", ds.Digest)
		fmt.Fprintf(w, "}\n")
		return nil
	default:
		return fmt.Errorf("unsupported output format: %s (supported: bind, json)", format)
	}
}
