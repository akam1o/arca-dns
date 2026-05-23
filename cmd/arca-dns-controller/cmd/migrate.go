package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/akam1o/arca-dns/pkg/backend"
	"github.com/akam1o/arca-dns/pkg/config"
	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/akam1o/arca-dns/pkg/util"
	"github.com/spf13/cobra"
)

var (
	migrateConfigFile  string
	migrateBackendType string
	migrateBackendDSN  string
	migrateBackendPath string
	migrateOutputDir   string
	migrateInputDir    string
	migrateFromBackend string
	migrateToBackend   string
	migrateFromDSN     string
	migrateFromPath    string
	migrateToDSN       string
	migrateToPath      string
	migrateDryRun      bool
	migrateOverwrite   bool
)

const (
	defaultMigrateBackend    = "sqlite"
	supportedMigrateBackends = "sqlite, postgres, mysql, git, etcd"
	maxMigrationFileSize     = config.DefaultControllerClientMaxResponseBytes
)

var errOverwriteConditionalDeleteUnsupported = errors.New("backend does not support atomic conditional delete")

// NewMigrateCmd creates the migrate command with subcommands.
func NewMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Data migration commands between backends",
		Long:  "Commands for exporting, importing, and copying DNS zone data between different backend storage systems",
	}

	// Add subcommands
	cmd.AddCommand(newExportCmd())
	cmd.AddCommand(newImportCmd())
	cmd.AddCommand(newCopyCmd())

	return cmd
}

// newExportCmd creates the export subcommand.
func newExportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export zones from backend to JSON files",
		Long: `Export all zones from a backend to JSON files in a directory.
Each zone is saved as a separate JSON file named <zone-name>.json.

Example:
  arca-dns-controller migrate export --output=./zones/
  arca-dns-controller migrate export --backend=postgres --dsn="postgres://user:pass@localhost:5432/dns?sslmode=disable" --output=./backup/`,
		RunE: runExport,
	}

	cmd.Flags().StringVarP(&migrateConfigFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().StringVar(&migrateBackendType, "backend", "", "Backend type (sqlite [default], postgres, mysql, git, etcd)")
	cmd.Flags().StringVar(&migrateBackendDSN, "dsn", "", "Backend DSN (for SQLite, PostgreSQL, MySQL)")
	cmd.Flags().StringVar(&migrateBackendPath, "path", "", "Backend path (for Git)")
	cmd.Flags().StringVarP(&migrateOutputDir, "output", "o", "./zones", "Output directory for JSON files")
	cmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Preview export without writing files")

	return cmd
}

// newImportCmd creates the import subcommand.
func newImportCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import zones from JSON files to backend",
		Long: `Import zones from JSON files into a backend.
Zone versions are recomputed during import to ensure consistency.

Example:
  arca-dns-controller migrate import --input=./zones/
  arca-dns-controller migrate import --backend=git --path=/var/dns/repo --input=./backup/`,
		RunE: runImport,
	}

	cmd.Flags().StringVarP(&migrateConfigFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().StringVar(&migrateBackendType, "backend", "", "Backend type (sqlite [default], postgres, mysql, git, etcd)")
	cmd.Flags().StringVar(&migrateBackendDSN, "dsn", "", "Backend DSN (for SQLite, PostgreSQL, MySQL)")
	cmd.Flags().StringVar(&migrateBackendPath, "path", "", "Backend path (for Git)")
	cmd.Flags().StringVarP(&migrateInputDir, "input", "i", "./zones", "Input directory with JSON files")
	cmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Validate files without importing")
	cmd.Flags().BoolVar(&migrateOverwrite, "overwrite", false, "Overwrite existing zones")

	return cmd
}

// newCopyCmd creates the copy subcommand.
func newCopyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "copy",
		Short: "Copy zones directly from one backend to another",
		Long: `Copy zones directly between backends without intermediate JSON files.
Zone versions are recomputed during the copy operation.

Example:
  arca-dns-controller migrate copy --from-backend=sqlite --from-dsn="file:arca-dns.db" --to-backend=mysql --to-dsn="root:pass@/dns"
  arca-dns-controller migrate copy --from-backend=git --from-path=/tmp/repo --to-backend=etcd`,
		RunE: runCopy,
	}

	cmd.Flags().StringVarP(&migrateConfigFile, "config", "c", "", "Path to configuration file")
	cmd.Flags().StringVar(&migrateFromBackend, "from-backend", "", "Source backend type (sqlite, postgres, mysql, git, etcd)")
	cmd.Flags().StringVar(&migrateToBackend, "to-backend", "", "Destination backend type (sqlite, postgres, mysql, git, etcd)")
	cmd.Flags().StringVar(&migrateFromDSN, "from-dsn", "", "Source DSN (for SQLite, PostgreSQL, MySQL)")
	cmd.Flags().StringVar(&migrateFromPath, "from-path", "", "Source path (for Git)")
	cmd.Flags().StringVar(&migrateToDSN, "to-dsn", "", "Destination DSN (for SQLite, PostgreSQL, MySQL)")
	cmd.Flags().StringVar(&migrateToPath, "to-path", "", "Destination path (for Git)")
	cmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Preview copy without writing")
	cmd.Flags().BoolVar(&migrateOverwrite, "overwrite", false, "Overwrite existing zones")

	cobra.CheckErr(cmd.MarkFlagRequired("from-backend"))
	cobra.CheckErr(cmd.MarkFlagRequired("to-backend"))

	return cmd
}

// runExport executes the export command.
func runExport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load configuration if provided
	cfg, err := loadMigrationConfig(migrateConfigFile)
	if err != nil {
		return err
	}

	// Create backend
	store, err := createBackend(migrateBackendType, cfg)
	if err != nil {
		return fmt.Errorf("create backend: %w", err)
	}
	defer store.Close()

	_, err = exportFromStore(ctx, store, migrateOutputDir, migrateDryRun)
	return err
}

// runImport executes the import command.
func runImport(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load configuration if provided
	cfg, err := loadMigrationConfig(migrateConfigFile)
	if err != nil {
		return err
	}

	// Create backend
	store, err := createBackend(migrateBackendType, cfg)
	if err != nil {
		return fmt.Errorf("create backend: %w", err)
	}
	defer store.Close()

	_, err = importToStore(ctx, store, migrateInputDir, migrateDryRun, migrateOverwrite)
	return err
}

// runCopy executes the copy command.
func runCopy(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load configuration if provided
	cfg, err := loadMigrationConfig(migrateConfigFile)
	if err != nil {
		return err
	}

	// Create source backend with from-* flags
	sourceStore, err := createBackendForCopy(migrateFromBackend, migrateFromDSN, migrateFromPath, cfg)
	if err != nil {
		return fmt.Errorf("create source backend: %w", err)
	}
	defer sourceStore.Close()

	// List all zones from source
	zones, err := sourceStore.ListZones(ctx, backend.ListOptions{})
	if err != nil {
		return fmt.Errorf("list zones from source: %w", err)
	}

	fmt.Printf("Found %d zones to copy from %s to %s\n", len(zones), migrateFromBackend, migrateToBackend)

	// Handle dry-run before creating destination backend to avoid side effects
	if migrateDryRun {
		fmt.Println("\n[DRY RUN] Would copy:")
		for _, zone := range zones {
			fmt.Printf("  - %s (old version: %s, new version: generated during copy)\n", zone.Name, zone.Version)
		}
		return nil
	}

	// Create destination backend only after dry-run check
	destStore, err := createBackendForCopy(migrateToBackend, migrateToDSN, migrateToPath, cfg)
	if err != nil {
		return fmt.Errorf("create destination backend: %w", err)
	}
	defer destStore.Close()

	// Copy zones
	copied := 0
	skipped := 0
	for _, zone := range zones {
		oldVersion := zone.Version

		// Clear version - it will be recomputed during CreateZone/UpdateZone
		zone.Version = ""

		if err := destStore.CreateZone(ctx, zone); err != nil {
			// If zone exists, handle based on overwrite flag
			if errors.Is(err, model.ErrZoneAlreadyExists) {
				if migrateOverwrite {
					if err := overwriteZone(ctx, destStore, zone); err != nil {
						return fmt.Errorf("overwrite zone %s in destination: %w", zone.Name, err)
					}
					fmt.Printf("Overwrote: %s (old version: %s, new version: %s)\n", zone.Name, oldVersion, zone.Version)
				} else {
					fmt.Printf("Skipped (exists): %s\n", zone.Name)
					skipped++
					continue
				}
			} else {
				return fmt.Errorf("create zone %s in destination: %w", zone.Name, err)
			}
		} else {
			fmt.Printf("Copied: %s (old version: %s, new version: %s)\n", zone.Name, oldVersion, zone.Version)
		}
		copied++
	}

	if skipped > 0 {
		fmt.Printf("\nCopy complete: %d zones copied, %d skipped (use --overwrite to replace existing zones)\n", copied, skipped)
	} else {
		fmt.Printf("\nCopy complete: %d zones copied from %s to %s\n", copied, migrateFromBackend, migrateToBackend)
	}
	return nil
}

func loadMigrationConfig(path string) (*config.ControllerConfig, error) {
	if path == "" {
		return config.DefaultControllerConfig(), nil
	}
	cfg, err := config.LoadControllerBackendConfig(path)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}

func exportFromStore(ctx context.Context, store backend.ZoneStore, outputDir string, dryRun bool) (int, error) {
	// List all zones
	zones, err := store.ListZones(ctx, backend.ListOptions{})
	if err != nil {
		return 0, fmt.Errorf("list zones: %w", err)
	}

	fmt.Printf("Found %d zones to export\n", len(zones))

	if dryRun {
		fmt.Println("\n[DRY RUN] Would export:")
		for _, zone := range zones {
			fmt.Printf("  - %s (version: %s)\n", zone.Name, zone.Version)
		}
		return 0, nil
	}

	// Create output directory
	if err := ensureMigrationDirectory(outputDir, "output directory"); err != nil {
		return 0, fmt.Errorf("create output directory: %w", err)
	}

	// Export each zone
	exported := 0
	for _, zone := range zones {
		filename := filepath.Join(outputDir, sanitizeFilename(zone.Name)+".json")

		data, err := json.MarshalIndent(zone, "", "  ")
		if err != nil {
			return 0, fmt.Errorf("marshal zone %s: %w", zone.Name, err)
		}

		if err := writeMigrationFileAtomicSynced(filename, data, 0644); err != nil {
			return 0, fmt.Errorf("write zone %s: %w", zone.Name, err)
		}

		exported++
		fmt.Printf("Exported: %s -> %s\n", zone.Name, filename)
	}

	fmt.Printf("\nExport complete: %d zones exported to %s\n", exported, outputDir)
	return exported, nil
}

func writeMigrationFileAtomicSynced(path string, data []byte, perm os.FileMode) error {
	dirPath := filepath.Dir(path)
	if err := validateExistingMigrationDirectory(dirPath, "output directory"); err != nil {
		return fmt.Errorf("stat output directory: %w", err)
	}

	tmp, err := os.CreateTemp(dirPath, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	tmpPath := tmp.Name()
	cleanupTmp := true
	defer func() {
		if cleanupTmp {
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if n, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	} else if n != len(data) {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", io.ErrShortWrite)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename temp file: %w", err)
	}
	cleanupTmp = false

	if err := syncMigrationDir(dirPath); err != nil {
		return fmt.Errorf("sync output directory: %w", err)
	}

	return nil
}

func ensureMigrationDirectory(path string, label string) error {
	existed := true
	if err := validateExistingMigrationDirectory(path, label); err != nil {
		if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", label, err)
		}
		existed = false
	}

	if err := os.MkdirAll(path, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", label, err)
	}
	if err := validateExistingMigrationDirectory(path, label); err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if !existed {
		if err := syncMigrationDir(filepath.Dir(path)); err != nil {
			return fmt.Errorf("sync %s parent: %w", label, err)
		}
	}

	return nil
}

func validateExistingMigrationDirectory(path string, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s must not be a symlink: %s", label, path)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s must be a directory: %s", label, path)
	}
	return nil
}

func syncMigrationDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		if errors.Is(syncErr, syscall.EINVAL) || errors.Is(syncErr, syscall.ENOTSUP) {
			syncErr = nil
		}
	}
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func importToStore(ctx context.Context, store backend.ZoneStore, inputDir string, dryRun bool, overwrite bool) (int, error) {
	if err := validateExistingMigrationDirectory(inputDir, "input directory"); err != nil {
		return 0, fmt.Errorf("stat input directory: %w", err)
	}

	// Read zone files
	files, err := filepath.Glob(filepath.Join(inputDir, "*.json"))
	if err != nil {
		return 0, fmt.Errorf("glob zone files: %w", err)
	}

	if len(files) == 0 {
		return 0, fmt.Errorf("no zone files found in %s", inputDir)
	}

	fmt.Printf("Found %d zone files to import\n", len(files))

	// Parse and validate zones
	zones := make([]*model.Zone, 0, len(files))
	for _, file := range files {
		data, err := readRegularMigrationFile(file)
		if err != nil {
			return 0, fmt.Errorf("read file %s: %w", file, err)
		}

		var zone model.Zone
		if err := json.Unmarshal(data, &zone); err != nil {
			return 0, fmt.Errorf("parse file %s: %w", file, err)
		}
		if err := model.ValidateZone(&zone); err != nil {
			return 0, fmt.Errorf("validate file %s: %w", file, err)
		}

		zones = append(zones, &zone)
	}

	if dryRun {
		fmt.Println("\n[DRY RUN] Would import:")
		for _, zone := range zones {
			fmt.Printf("  - %s (old version: %s, new version: generated during import)\n", zone.Name, zone.Version)
		}
		return 0, nil
	}

	// Import zones
	imported := 0
	skipped := 0
	for _, zone := range zones {
		// Clear version - it will be recomputed during CreateZone/UpdateZone
		oldVersion := zone.Version
		zone.Version = ""

		if err := store.CreateZone(ctx, zone); err != nil {
			// If zone exists, handle based on overwrite flag
			if errors.Is(err, model.ErrZoneAlreadyExists) {
				if overwrite {
					if err := overwriteZone(ctx, store, zone); err != nil {
						return 0, fmt.Errorf("overwrite zone %s: %w", zone.Name, err)
					}
					fmt.Printf("Overwrote: %s (old version: %s, new version: %s)\n", zone.Name, oldVersion, zone.Version)
				} else {
					fmt.Printf("Skipped (exists): %s\n", zone.Name)
					skipped++
					continue
				}
			} else {
				return 0, fmt.Errorf("create zone %s: %w", zone.Name, err)
			}
		} else {
			fmt.Printf("Imported: %s (old version: %s, new version: %s)\n", zone.Name, oldVersion, zone.Version)
		}
		imported++
	}

	if skipped > 0 {
		fmt.Printf("\nImport complete: %d zones imported, %d skipped (use --overwrite to replace existing zones)\n", imported, skipped)
	} else {
		fmt.Printf("\nImport complete: %d zones imported\n", imported)
	}
	return imported, nil
}

func readRegularMigrationFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("migration file must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("migration file must be a regular file: %s", path)
	}
	if info.Size() > maxMigrationFileSize {
		return nil, fmt.Errorf("migration file exceeds maximum size of %d bytes: %s", maxMigrationFileSize, path)
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, fmt.Errorf("migration file changed while opening: %s", path)
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("migration file must be a regular file: %s", path)
	}
	if openedInfo.Size() > maxMigrationFileSize {
		return nil, fmt.Errorf("migration file exceeds maximum size of %d bytes: %s", maxMigrationFileSize, path)
	}

	data, err := io.ReadAll(io.LimitReader(file, maxMigrationFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxMigrationFileSize {
		return nil, fmt.Errorf("migration file exceeds maximum size of %d bytes: %s", maxMigrationFileSize, path)
	}
	return data, nil
}

func overwriteZone(ctx context.Context, store backend.ZoneStore, zone *model.Zone) error {
	if txStore, ok := store.(backend.TransactionalStore); ok {
		return overwriteZoneInTransaction(ctx, txStore, zone)
	}

	return overwriteZoneWithRestore(ctx, store, zone)
}

func overwriteZoneInTransaction(ctx context.Context, store backend.TransactionalStore, zone *model.Zone) error {
	tx, err := store.BeginTx(ctx)
	if err != nil {
		return fmt.Errorf("begin overwrite transaction: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(context.WithoutCancel(ctx))
		}
	}()

	current, err := tx.GetZone(ctx, zone.Name)
	if err != nil {
		return fmt.Errorf("get existing zone: %w", err)
	}

	if err := deleteZoneForOverwrite(ctx, tx, zone.Name, current.Version); err != nil {
		return fmt.Errorf("delete existing zone: %w", err)
	}
	if err := tx.CreateZone(ctx, zone); err != nil {
		return fmt.Errorf("create replacement zone: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit overwrite transaction: %w", err)
	}
	committed = true
	return nil
}

func overwriteZoneWithRestore(ctx context.Context, store backend.ZoneStore, zone *model.Zone) error {
	current, err := store.GetZone(ctx, zone.Name)
	if err != nil {
		return fmt.Errorf("get existing zone: %w", err)
	}

	if err := deleteZoneForOverwrite(ctx, store, zone.Name, current.Version); err != nil {
		return fmt.Errorf("delete existing zone: %w", err)
	}
	if err := store.CreateZone(ctx, zone); err != nil {
		if restoreErr := restoreZoneAfterOverwriteFailure(ctx, store, current, zone); restoreErr != nil {
			return errors.Join(
				fmt.Errorf("create replacement zone: %w", err),
				restoreErr,
			)
		}
		return fmt.Errorf("create replacement zone: %w", err)
	}
	return nil
}

func restoreZoneAfterOverwriteFailure(ctx context.Context, store backend.ZoneStore, current *model.Zone, attemptedReplacement *model.Zone) error {
	restoreCtx := context.WithoutCancel(ctx)

	visible, err := store.GetZone(restoreCtx, current.Name)
	switch {
	case err == nil:
		if visible.Version == current.Version {
			return nil
		}
		if !sameReplacementZone(visible, attemptedReplacement) {
			return fmt.Errorf("restore previous zone: visible zone changed after failed replacement: %w", model.ErrConflict)
		}
		if err := deleteZoneForOverwrite(restoreCtx, store, current.Name, visible.Version); err != nil {
			return fmt.Errorf("restore previous zone: delete failed replacement zone: %w", err)
		}
	case errors.Is(err, model.ErrZoneNotFound):
	default:
		return fmt.Errorf("restore previous zone: get visible zone: %w", err)
	}

	if err := store.CreateZone(restoreCtx, current); err != nil {
		return fmt.Errorf("restore previous zone: create previous zone: %w", err)
	}
	return nil
}

func sameReplacementZone(visible *model.Zone, attempted *model.Zone) bool {
	if visible == nil || attempted == nil {
		return false
	}
	if attempted.Version == "" || visible.Version != attempted.Version {
		return false
	}
	if model.NormalizeZoneName(visible.Name) != model.NormalizeZoneName(attempted.Name) {
		return false
	}
	if visible.SOA != attempted.SOA {
		return false
	}
	if !sameDNSSECConfig(visible.DNSSEC, attempted.DNSSEC) {
		return false
	}
	if len(visible.Records) != len(attempted.Records) {
		return false
	}
	for i := range visible.Records {
		if !sameRecord(visible.Records[i], attempted.Records[i]) {
			return false
		}
	}
	return true
}

func sameRecord(a model.Record, b model.Record) bool {
	if a.ID != b.ID || a.Name != b.Name || a.Type != b.Type || a.TTL != b.TTL || a.Value != b.Value {
		return false
	}
	if a.Priority == nil || b.Priority == nil {
		return a.Priority == nil && b.Priority == nil
	}
	return *a.Priority == *b.Priority
}

func sameDNSSECConfig(a *model.DNSSECConfig, b *model.DNSSECConfig) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	if a.Enabled != b.Enabled ||
		a.Algorithm != b.Algorithm ||
		a.KSKKeyTag != b.KSKKeyTag ||
		a.ZSKKeyTag != b.ZSKKeyTag ||
		a.NSEC3Enabled != b.NSEC3Enabled ||
		a.NSEC3Iterations != b.NSEC3Iterations ||
		a.NSEC3Salt != b.NSEC3Salt {
		return false
	}
	if a.SignatureExpiration == nil || b.SignatureExpiration == nil {
		return a.SignatureExpiration == nil && b.SignatureExpiration == nil
	}
	return a.SignatureExpiration.Equal(*b.SignatureExpiration)
}

func deleteZoneForOverwrite(ctx context.Context, store backend.ZoneStore, name string, expectedVersion string) error {
	if conditionalStore, ok := store.(backend.ConditionalDeleteStore); ok {
		return conditionalStore.DeleteZoneWithVersion(ctx, name, expectedVersion)
	}
	return errOverwriteConditionalDeleteUnsupported
}

// createBackendForCopy creates a backend with explicit DSN/path parameters.
// This is used by the copy command to configure source and destination independently.
func createBackendForCopy(backendType, dsn, path string, cfg *config.ControllerConfig) (backend.ZoneStore, error) {
	configMap := make(map[string]interface{})

	switch backendType {
	case "sqlite":
		if dsn == "" && cfg != nil && cfg.Backend.Type == "sqlite" {
			dsn = cfg.Backend.SQLite.DSN
		}
		if dsn != "" {
			configMap["dsn"] = dsn
		}
		return backend.NewBackend("sqlite", configMap)

	case "postgres":
		if dsn == "" && cfg != nil && cfg.Backend.Type == "postgres" {
			dsn = cfg.Backend.Postgres.DSN
		}
		if dsn == "" {
			return nil, fmt.Errorf("PostgreSQL backend requires --from-dsn/--to-dsn flag or dsn in config")
		}
		configMap["dsn"] = dsn
		if cfg != nil && cfg.Backend.Type == "postgres" {
			if cfg.Backend.Postgres.MaxOpenConns > 0 {
				configMap["max_open_conns"] = cfg.Backend.Postgres.MaxOpenConns
			}
			if cfg.Backend.Postgres.MaxIdleConns > 0 {
				configMap["max_idle_conns"] = cfg.Backend.Postgres.MaxIdleConns
			}
			if cfg.Backend.Postgres.ConnMaxLifetime > 0 {
				configMap["conn_max_lifetime"] = cfg.Backend.Postgres.ConnMaxLifetime
			}
		}
		return backend.NewBackend("postgres", configMap)

	case "mysql":
		if dsn == "" && cfg != nil && cfg.Backend.Type == "mysql" {
			dsn = cfg.Backend.MySQL.DSN
		}
		if dsn == "" {
			return nil, fmt.Errorf("MySQL backend requires --from-dsn/--to-dsn flag or dsn in config")
		}
		configMap["dsn"] = dsn
		if cfg != nil && cfg.Backend.Type == "mysql" {
			if cfg.Backend.MySQL.MaxOpenConns > 0 {
				configMap["max_open_conns"] = cfg.Backend.MySQL.MaxOpenConns
			}
			if cfg.Backend.MySQL.MaxIdleConns > 0 {
				configMap["max_idle_conns"] = cfg.Backend.MySQL.MaxIdleConns
			}
			if cfg.Backend.MySQL.ConnMaxLifetime > 0 {
				configMap["conn_max_lifetime"] = cfg.Backend.MySQL.ConnMaxLifetime
			}
		}
		return backend.NewBackend("mysql", configMap)

	case "git":
		if path == "" && cfg != nil && cfg.Backend.Type == "git" {
			path = cfg.Backend.Git.RepositoryPath
		}
		if path == "" {
			return nil, fmt.Errorf("Git backend requires --from-path/--to-path flag or repository_path in config")
		}
		configMap["repository_path"] = path
		if cfg != nil && cfg.Backend.Type == "git" {
			if cfg.Backend.Git.Branch != "" {
				configMap["branch"] = cfg.Backend.Git.Branch
			}
			if cfg.Backend.Git.Author != "" {
				configMap["author_name"] = cfg.Backend.Git.Author
			}
			if cfg.Backend.Git.Email != "" {
				configMap["author_email"] = cfg.Backend.Git.Email
			}
			configMap["auto_sync"] = false
		}
		return backend.NewBackend("git", configMap)

	case "etcd":
		endpoints := []string{"localhost:2379"}
		if cfg != nil && cfg.Backend.Type == "etcd" && len(cfg.Backend.Etcd.Endpoints) > 0 {
			endpoints = cfg.Backend.Etcd.Endpoints
		}
		configMap["endpoints"] = endpoints
		if cfg != nil && cfg.Backend.Type == "etcd" {
			if cfg.Backend.Etcd.Prefix != "" {
				configMap["prefix"] = cfg.Backend.Etcd.Prefix
			}
			if cfg.Backend.Etcd.Username != "" {
				configMap["username"] = cfg.Backend.Etcd.Username
			}
			if cfg.Backend.Etcd.Password != "" {
				configMap["password"] = cfg.Backend.Etcd.Password
			}
			if cfg.Backend.Etcd.DialTimeout > 0 {
				configMap["dial_timeout"] = cfg.Backend.Etcd.DialTimeout
			}
			if cfg.Backend.Etcd.RequestTimeout > 0 {
				configMap["request_timeout"] = cfg.Backend.Etcd.RequestTimeout
			}
		}
		return backend.NewBackend("etcd", configMap)

	default:
		return nil, fmt.Errorf("unsupported backend type: %s (supported: %s)", backendType, supportedMigrateBackends)
	}
}

// createBackend creates a backend instance based on type and configuration.
func createBackend(backendType string, cfg *config.ControllerConfig) (backend.ZoneStore, error) {
	// Build config map from flags and config file
	configMap := make(map[string]interface{})
	backendType = effectiveMigrateBackendType(backendType, cfg)

	switch backendType {
	case "sqlite":
		dsn := migrateBackendDSN
		if dsn == "" && cfg != nil && cfg.Backend.Type == "sqlite" {
			dsn = cfg.Backend.SQLite.DSN
		}
		if dsn != "" {
			configMap["dsn"] = dsn
		}
		return backend.NewBackend("sqlite", configMap)

	case "postgres":
		dsn := migrateBackendDSN
		if dsn == "" && cfg != nil && cfg.Backend.Type == "postgres" {
			dsn = cfg.Backend.Postgres.DSN
		}
		if dsn == "" {
			return nil, fmt.Errorf("PostgreSQL backend requires --dsn flag or dsn in config")
		}
		configMap["dsn"] = dsn
		if cfg != nil && cfg.Backend.Type == "postgres" {
			if cfg.Backend.Postgres.MaxOpenConns > 0 {
				configMap["max_open_conns"] = cfg.Backend.Postgres.MaxOpenConns
			}
			if cfg.Backend.Postgres.MaxIdleConns > 0 {
				configMap["max_idle_conns"] = cfg.Backend.Postgres.MaxIdleConns
			}
			if cfg.Backend.Postgres.ConnMaxLifetime > 0 {
				configMap["conn_max_lifetime"] = cfg.Backend.Postgres.ConnMaxLifetime
			}
		}
		return backend.NewBackend("postgres", configMap)

	case "mysql":
		dsn := migrateBackendDSN
		if dsn == "" && cfg != nil && cfg.Backend.Type == "mysql" {
			dsn = cfg.Backend.MySQL.DSN
		}
		if dsn == "" {
			return nil, fmt.Errorf("MySQL backend requires --dsn flag or dsn in config")
		}
		configMap["dsn"] = dsn
		if cfg != nil && cfg.Backend.Type == "mysql" {
			if cfg.Backend.MySQL.MaxOpenConns > 0 {
				configMap["max_open_conns"] = cfg.Backend.MySQL.MaxOpenConns
			}
			if cfg.Backend.MySQL.MaxIdleConns > 0 {
				configMap["max_idle_conns"] = cfg.Backend.MySQL.MaxIdleConns
			}
			if cfg.Backend.MySQL.ConnMaxLifetime > 0 {
				configMap["conn_max_lifetime"] = cfg.Backend.MySQL.ConnMaxLifetime
			}
		}
		return backend.NewBackend("mysql", configMap)

	case "git":
		path := migrateBackendPath
		if path == "" && cfg != nil && cfg.Backend.Type == "git" {
			path = cfg.Backend.Git.RepositoryPath
		}
		if path == "" {
			return nil, fmt.Errorf("Git backend requires --path flag or repository_path in config")
		}
		configMap["repository_path"] = path

		// Optional Git config
		if cfg != nil && cfg.Backend.Type == "git" {
			if cfg.Backend.Git.Branch != "" {
				configMap["branch"] = cfg.Backend.Git.Branch
			}
			if cfg.Backend.Git.Author != "" {
				configMap["author_name"] = cfg.Backend.Git.Author
			}
			if cfg.Backend.Git.Email != "" {
				configMap["author_email"] = cfg.Backend.Git.Email
			}
			// For migration, we don't want auto push/pull
			configMap["auto_sync"] = false
		}
		return backend.NewBackend("git", configMap)

	case "etcd":
		endpoints := []string{"localhost:2379"} // Default
		if cfg != nil && cfg.Backend.Type == "etcd" {
			if len(cfg.Backend.Etcd.Endpoints) > 0 {
				endpoints = cfg.Backend.Etcd.Endpoints
			}
		}
		configMap["endpoints"] = endpoints

		// Optional etcd config
		if cfg != nil && cfg.Backend.Type == "etcd" {
			if cfg.Backend.Etcd.Prefix != "" {
				configMap["prefix"] = cfg.Backend.Etcd.Prefix
			}
			if cfg.Backend.Etcd.Username != "" {
				configMap["username"] = cfg.Backend.Etcd.Username
			}
			if cfg.Backend.Etcd.Password != "" {
				configMap["password"] = cfg.Backend.Etcd.Password
			}
			if cfg.Backend.Etcd.DialTimeout > 0 {
				configMap["dial_timeout"] = cfg.Backend.Etcd.DialTimeout
			}
			if cfg.Backend.Etcd.RequestTimeout > 0 {
				configMap["request_timeout"] = cfg.Backend.Etcd.RequestTimeout
			}
		}
		return backend.NewBackend("etcd", configMap)

	default:
		return nil, fmt.Errorf("unsupported backend type: %s (supported: %s)", backendType, supportedMigrateBackends)
	}
}

func effectiveMigrateBackendType(backendType string, cfg *config.ControllerConfig) string {
	if backendType != "" {
		return backendType
	}
	if cfg != nil && cfg.Backend.Type != "" {
		return cfg.Backend.Type
	}
	return defaultMigrateBackend
}

// sanitizeFilename converts a zone name to a safe filename.
func sanitizeFilename(zoneName string) string {
	name := util.SafeZoneFilename(zoneName)
	name = strings.ReplaceAll(name, ".", "_")
	return name
}
