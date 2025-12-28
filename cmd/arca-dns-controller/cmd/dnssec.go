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

var (
	configFile   string
	digestType   uint8
	outputFormat string
)

// NewDNSSECCmd creates the dnssec command with subcommands.
func NewDNSSECCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dnssec",
		Short: "DNSSEC key management commands",
		Long:  "Commands for managing DNSSEC keys, exporting DS records, and key operations",
	}

	// Add subcommands
	cmd.AddCommand(newExportDSCmd())

	return cmd
}

// newExportDSCmd creates the export-ds subcommand.
func newExportDSCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export-ds ZONE",
		Short: "Export DS record for a zone's KSK",
		Long: `Export the DS (Delegation Signer) record for a zone's Key Signing Key (KSK).
The DS record should be submitted to the parent zone for DNSSEC chain of trust.

The zone name can be specified with or without a trailing dot.
Example: arca-dns-controller dnssec export-ds example.com`,
		Args: cobra.ExactArgs(1),
		RunE: runExportDS,
	}

	cmd.Flags().StringVarP(&configFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().Uint8VarP(&digestType, "digest", "d", 2, "Digest type (2=SHA-256, 4=SHA-384)")
	cmd.Flags().StringVarP(&outputFormat, "format", "f", "bind", "Output format (bind, json)")

	return cmd
}

// runExportDS executes the export-ds command.
func runExportDS(cmd *cobra.Command, args []string) error {
	zoneName := args[0]

	// Load configuration
	cfg, err := config.LoadControllerConfig(configFile)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Validate DNSSEC is enabled
	if !cfg.DNSSEC.Enabled {
		return fmt.Errorf("DNSSEC is not enabled in configuration")
	}

	// Load master key
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

	// Create key manager
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

	// Export DS record
	ds, err := km.ExportDS(zoneName, digestType)
	if err != nil {
		return fmt.Errorf("export DS record: %w", err)
	}

	// Output DS record
	if err := outputDS(os.Stdout, ds, outputFormat); err != nil {
		return fmt.Errorf("output DS record: %w", err)
	}

	// Print metadata to stderr
	fmt.Fprintf(os.Stderr, "\nDS record exported successfully\n")
	fmt.Fprintf(os.Stderr, "Zone: %s\n", ds.Hdr.Name)
	fmt.Fprintf(os.Stderr, "Key Tag: %d\n", ds.KeyTag)
	fmt.Fprintf(os.Stderr, "Algorithm: %d (%s)\n", ds.Algorithm, dnssec.AlgorithmName(ds.Algorithm))
	fmt.Fprintf(os.Stderr, "Digest Type: %d\n", ds.DigestType)

	return nil
}

// outputDS outputs the DS record in the specified format.
func outputDS(w io.Writer, ds *dns.DS, format string) error {
	switch format {
	case "bind":
		// Output in BIND zone file format
		fmt.Fprintf(w, "%s\n", ds.String())
		return nil

	case "json":
		// Output in JSON format
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
