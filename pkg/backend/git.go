package backend

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/akam1o/arca-dns/pkg/model"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/gofrs/flock"
)

func init() {
	RegisterBackend("git", func(cfg map[string]interface{}) (ZoneStore, error) {
		repoPath, ok := cfg["repository_path"].(string)
		if !ok || repoPath == "" {
			return nil, fmt.Errorf("git backend requires repository_path")
		}

		branch, _ := cfg["branch"].(string)
		if branch == "" {
			branch = "main"
		}

		// Support both old names (author_name/author_email) and new names (author/email)
		// Priority: new name (author) > old name (author_name) > default
		authorName, _ := cfg["author"].(string)
		if authorName == "" {
			authorName, _ = cfg["author_name"].(string)
		}
		if authorName == "" {
			authorName = "arca-dns-controller"
		}

		authorEmail, _ := cfg["email"].(string)
		if authorEmail == "" {
			authorEmail, _ = cfg["author_email"].(string)
		}
		if authorEmail == "" {
			authorEmail = "noreply@arca-dns"
		}

		// Support both old name (auto_sync) and new name (auto_push)
		// Priority: new name (auto_push) > old name (auto_sync) > default (false)
		var autoSync bool
		if val, ok := cfg["auto_push"]; ok {
			autoSync, _ = val.(bool)
		} else if val, ok := cfg["auto_sync"]; ok {
			autoSync, _ = val.(bool)
		}
		// Default: false (local-only)

		return NewGitBackend(repoPath, branch, authorName, authorEmail, autoSync)
	})
}

// GitBackend implements ZoneStore and RevisionStore using a Git repository
type GitBackend struct {
	repoPath    string
	branch      string
	authorName  string
	authorEmail string
	autoSync    bool // If true, pull before operations and push after commits

	repo      *git.Repository
	worktree  *git.Worktree
	fileLock  *flock.Flock
	zoneMutex sync.Map // map[string]*sync.Mutex (per-zone locking)
	mu        sync.RWMutex
}

// NewGitBackend creates a new Git backend
// If the repository doesn't exist, it will be initialized
func NewGitBackend(repoPath, branch, authorName, authorEmail string, autoSync bool) (*GitBackend, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repository path: %w", err)
	}

	// Initialize or open repository
	repo, err := openOrInitRepo(absPath, branch)
	if err != nil {
		return nil, fmt.Errorf("failed to open/init repository: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("failed to get worktree: %w", err)
	}

	// Create zones directory if it doesn't exist
	zonesDir := filepath.Join(absPath, "zones")
	if err := os.MkdirAll(zonesDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create zones directory: %w", err)
	}

	// Initialize file lock
	lockPath := filepath.Join(absPath, ".lock")
	fileLock := flock.New(lockPath)

	return &GitBackend{
		repoPath:    absPath,
		branch:      branch,
		authorName:  authorName,
		authorEmail: authorEmail,
		autoSync:    autoSync,
		repo:        repo,
		worktree:    worktree,
		fileLock:    fileLock,
	}, nil
}

// openOrInitRepo opens an existing repository or initializes a new one
func openOrInitRepo(path, branch string) (*git.Repository, error) {
	// Try to open existing repository
	repo, err := git.PlainOpen(path)
	if err == nil {
		// Repository exists, checkout branch
		w, err := repo.Worktree()
		if err != nil {
			return nil, err
		}

		// Check if branch exists
		branchRef := plumbing.NewBranchReferenceName(branch)
		_, err = repo.Reference(branchRef, true)
		if err == plumbing.ErrReferenceNotFound {
			// Branch doesn't exist, create it
			_, headErr := repo.Head()
			if headErr == nil {
				// Create branch from current HEAD
				err = w.Checkout(&git.CheckoutOptions{
					Branch: branchRef,
					Create: true,
				})
				if err != nil {
					return nil, fmt.Errorf("failed to create branch %s: %w", branch, err)
				}
			}
			// If HEAD doesn't exist, the repository is empty; the branch will be created on first commit.
		} else if err != nil {
			return nil, err
		} else {
			// Branch exists, checkout
			err = w.Checkout(&git.CheckoutOptions{
				Branch: branchRef,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to checkout branch %s: %w", branch, err)
			}
		}

		return repo, nil
	}

	// Repository doesn't exist, initialize new one
	if err := os.MkdirAll(path, 0755); err != nil {
		return nil, fmt.Errorf("failed to create repository directory: %w", err)
	}

	fs := osfs.New(path)
	storage := filesystem.NewStorage(fs, cache.NewObjectLRUDefault())

	repo, err = git.Init(storage, fs)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repository: %w", err)
	}

	return repo, nil
}

// acquireLock acquires both file lock and per-zone mutex
func (g *GitBackend) acquireLock(ctx context.Context, zoneName string) (*sync.Mutex, error) {
	// Acquire file lock (cross-process)
	locked := false
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
			var err error
			locked, err = g.fileLock.TryLock()
			if err != nil {
				return nil, fmt.Errorf("failed to acquire file lock: %w", err)
			}
			if locked {
				goto haveLock
			}
		}
	}

haveLock:
	// Acquire per-zone mutex (in-process)
	muInterface, _ := g.zoneMutex.LoadOrStore(zoneName, &sync.Mutex{})
	zoneMu := muInterface.(*sync.Mutex)
	zoneMu.Lock()

	return zoneMu, nil
}

// releaseLock releases both per-zone mutex and file lock
func (g *GitBackend) releaseLock(zoneMu *sync.Mutex) {
	if zoneMu != nil {
		zoneMu.Unlock()
	}
	_ = g.fileLock.Unlock()
}

// zoneFilePath returns the path to the zone JSON file
// Returns error if the zone name would escape the zones directory
func (g *GitBackend) zoneFilePath(zoneName string) (string, error) {
	normalized := model.NormalizeZoneName(zoneName)

	// Additional security: prevent path traversal
	// Reject absolute paths, "..", and path separators in zone name
	if filepath.IsAbs(normalized) {
		return "", fmt.Errorf("zone name cannot be absolute path")
	}
	if strings.Contains(normalized, "..") {
		return "", fmt.Errorf("zone name cannot contain '..'")
	}
	if strings.ContainsAny(normalized, string(filepath.Separator)) {
		return "", fmt.Errorf("zone name cannot contain path separators")
	}

	relPath := filepath.Join("zones", normalized+".json")

	// Verify the resolved path is within zones directory
	absPath := filepath.Join(g.repoPath, relPath)
	zonesDir := filepath.Join(g.repoPath, "zones")
	if !strings.HasPrefix(absPath, zonesDir+string(filepath.Separator)) && absPath != zonesDir {
		return "", fmt.Errorf("zone path would escape zones directory")
	}

	return relPath, nil
}

// pullIfNeeded performs a fast-forward-only pull if autoSync is enabled
func (g *GitBackend) pullIfNeeded(ctx context.Context) error {
	if !g.autoSync {
		return nil
	}

	err := g.worktree.PullContext(ctx, &git.PullOptions{
		RemoteName: "origin",
		Force:      false, // Fast-forward only
	})

	if err == git.NoErrAlreadyUpToDate {
		return nil
	}

	if err != nil {
		if strings.Contains(err.Error(), "non-fast-forward") {
			return fmt.Errorf("git pull failed: non-fast-forward update rejected (manual merge required)")
		}
		return fmt.Errorf("git pull failed: %w", err)
	}

	return nil
}

// commitZone commits changes to the zone file
func (g *GitBackend) commitZone(ctx context.Context, zoneName, operation, summary string, zone *model.Zone) error {
	filePath, err := g.zoneFilePath(zoneName)
	if err != nil {
		return fmt.Errorf("invalid zone path: %w", err)
	}

	// Add file to staging
	_, err = g.worktree.Add(filePath)
	if err != nil {
		return fmt.Errorf("failed to add file to git: %w", err)
	}

	// Create commit message
	message := fmt.Sprintf("[%s] %s: %s\n\nVersion: %s", operation, zoneName, summary, zone.Version)

	// Commit
	_, err = g.worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  g.authorName,
			Email: g.authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	// Push if autoSync is enabled
	if g.autoSync {
		err = g.repo.PushContext(ctx, &git.PushOptions{
			RemoteName: "origin",
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("git push failed: %w", err)
		}
	}

	return nil
}

// removeAndCommit removes a zone file and commits the deletion
func (g *GitBackend) removeAndCommit(ctx context.Context, zoneName, summary string) error {
	filePath, err := g.zoneFilePath(zoneName)
	if err != nil {
		return fmt.Errorf("invalid zone path: %w", err)
	}

	// Remove file from git
	_, err = g.worktree.Remove(filePath)
	if err != nil {
		return fmt.Errorf("failed to remove file from git: %w", err)
	}

	// Create commit message
	message := fmt.Sprintf("[delete] %s: %s", zoneName, summary)

	// Commit
	_, err = g.worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  g.authorName,
			Email: g.authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit deletion: %w", err)
	}

	// Push if autoSync is enabled
	if g.autoSync {
		err = g.repo.PushContext(ctx, &git.PushOptions{
			RemoteName: "origin",
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("git push failed: %w", err)
		}
	}

	return nil
}

// readZone reads and parses a zone JSON file
func (g *GitBackend) readZone(zoneName string) (*model.Zone, error) {
	relPath, err := g.zoneFilePath(zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	filePath := filepath.Join(g.repoPath, relPath)

	data, err := os.ReadFile(filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, model.ErrZoneNotFound
		}
		return nil, fmt.Errorf("failed to read zone file: %w", err)
	}

	var zone model.Zone
	if err := json.Unmarshal(data, &zone); err != nil {
		return nil, fmt.Errorf("failed to parse zone JSON: %w", err)
	}

	return &zone, nil
}

// writeZone writes a zone to JSON file atomically
func (g *GitBackend) writeZone(zoneName string, zone *model.Zone) error {
	relPath, err := g.zoneFilePath(zoneName)
	if err != nil {
		return fmt.Errorf("invalid zone path: %w", err)
	}

	filePath := filepath.Join(g.repoPath, relPath)

	// Ensure directory exists
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Marshal to JSON
	data, err := json.MarshalIndent(zone, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal zone to JSON: %w", err)
	}

	// Atomic write: write to .tmp, fsync, rename
	tmpPath := filePath + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}

	_, err = f.Write(data)
	if err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to write temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("failed to sync temp file: %w", err)
	}

	f.Close()

	if err := os.Rename(tmpPath, filePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename temp file: %w", err)
	}

	return nil
}

// GetZone retrieves a zone by name
func (g *GitBackend) GetZone(ctx context.Context, name string) (*model.Zone, error) {
	normalized := model.NormalizeZoneName(name)

	g.mu.RLock()
	defer g.mu.RUnlock()

	return g.readZone(normalized)
}

// ListZones returns all zones with pagination
func (g *GitBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()

	zonesDir := filepath.Join(g.repoPath, "zones")
	entries, err := os.ReadDir(zonesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return make([]*model.Zone, 0), nil
		}
		return nil, fmt.Errorf("failed to read zones directory: %w", err)
	}

	zones := make([]*model.Zone, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		zoneName := strings.TrimSuffix(entry.Name(), ".json")
		zone, err := g.readZone(zoneName)
		if err != nil {
			// Skip corrupted files
			continue
		}

		zones = append(zones, zone)
	}

	// Sort by name for consistent ordering
	sort.Slice(zones, func(i, j int) bool {
		return zones[i].Name < zones[j].Name
	})

	// Apply pagination
	start := opts.Offset
	if start > len(zones) {
		return make([]*model.Zone, 0), nil
	}

	// Limit==0 means return all (no limit)
	if opts.Limit <= 0 {
		return zones[start:], nil
	}

	end := start + opts.Limit
	if end > len(zones) {
		end = len(zones)
	}

	return zones[start:end], nil
}

// CreateZone creates a new zone
func (g *GitBackend) CreateZone(ctx context.Context, zone *model.Zone) error {
	normalized := model.NormalizeZoneName(zone.Name)
	zone.Name = normalized

	// Auto-generate serial if not set
	if zone.SOA.Serial == 0 {
		zone.SOA.Serial = generateSerial(0)
	}

	// Set timestamps
	now := time.Now()
	zone.CreatedAt = now
	zone.UpdatedAt = now

	// Compute version
	version, err := ComputeZoneVersion(zone)
	if err != nil {
		return fmt.Errorf("failed to compute zone version: %w", err)
	}
	zone.Version = version

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	// Pull if autoSync is enabled
	if err := g.pullIfNeeded(ctx); err != nil {
		return err
	}

	// Check if zone already exists
	_, err = g.readZone(normalized)
	if err == nil {
		return model.ErrZoneAlreadyExists
	}
	if err != model.ErrZoneNotFound {
		return err
	}

	// Write zone file
	if err := g.writeZone(normalized, zone); err != nil {
		return err
	}

	// Commit
	summary := fmt.Sprintf("created zone with %d records", len(zone.Records))
	return g.commitZone(ctx, normalized, "create", summary, zone)
}

// UpdateZone updates an existing zone with optimistic locking
func (g *GitBackend) UpdateZone(ctx context.Context, zone *model.Zone, expectedVersion string) error {
	normalized := model.NormalizeZoneName(zone.Name)
	zone.Name = normalized

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	// Pull if autoSync is enabled
	if err := g.pullIfNeeded(ctx); err != nil {
		return err
	}

	// Read current zone
	currentZone, err := g.readZone(normalized)
	if err != nil {
		if err == model.ErrZoneNotFound {
			return model.ErrZoneNotFound
		}
		return err
	}

	// Check version (optimistic locking) only if expectedVersion is provided
	if expectedVersion != "" && currentZone.Version != expectedVersion {
		return model.ErrConflict
	}

	// Preserve CreatedAt from current zone
	zone.CreatedAt = currentZone.CreatedAt

	// Auto-increment serial
	zone.SOA.Serial = generateSerial(currentZone.SOA.Serial)

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// Compute new version
	newVersion, err := ComputeZoneVersion(zone)
	if err != nil {
		return fmt.Errorf("failed to compute zone version: %w", err)
	}
	zone.Version = newVersion

	// Write updated zone file
	if err := g.writeZone(normalized, zone); err != nil {
		return err
	}

	// Commit
	summary := fmt.Sprintf("updated zone (%d records)", len(zone.Records))
	return g.commitZone(ctx, normalized, "update", summary, zone)
}

// DeleteZone deletes a zone
func (g *GitBackend) DeleteZone(ctx context.Context, name string) error {
	normalized := model.NormalizeZoneName(name)

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	// Pull if autoSync is enabled
	if err := g.pullIfNeeded(ctx); err != nil {
		return err
	}

	// Check if zone exists
	_, err = g.readZone(normalized)
	if err != nil {
		if err == model.ErrZoneNotFound {
			return model.ErrZoneNotFound
		}
		return err
	}

	// Delete file
	relPath, err := g.zoneFilePath(normalized)
	if err != nil {
		return fmt.Errorf("invalid zone path: %w", err)
	}

	filePath := filepath.Join(g.repoPath, relPath)
	if err := os.Remove(filePath); err != nil {
		return fmt.Errorf("failed to delete zone file: %w", err)
	}

	// Commit deletion
	summary := "deleted zone"
	return g.removeAndCommit(ctx, normalized, summary)
}

// Close closes the backend
func (g *GitBackend) Close() error {
	// Release file lock if held
	_ = g.fileLock.Unlock()
	return nil
}

// GetRevision retrieves a specific zone version from commit history
func (g *GitBackend) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	normalized := model.NormalizeZoneName(zoneName)

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Get commit history for the zone file
	filePath, err := g.zoneFilePath(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	commits, err := g.repo.Log(&git.LogOptions{
		FileName: &filePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit history: %w", err)
	}

	// Search for commit with matching Version trailer
	var targetCommit *object.Commit
	stopSentinel := fmt.Errorf("found")
	err = commits.ForEach(func(c *object.Commit) error {
		if strings.Contains(c.Message, fmt.Sprintf("Version: %s", version)) {
			targetCommit = c
			return stopSentinel // Stop iteration
		}
		return nil
	})

	// Handle iteration errors (excluding our stop sentinel)
	if err != nil && err != stopSentinel {
		return nil, fmt.Errorf("failed to iterate commit history: %w", err)
	}

	if targetCommit == nil {
		return nil, model.ErrVersionNotFound
	}

	// Get file contents at that commit
	tree, err := targetCommit.Tree()
	if err != nil {
		return nil, fmt.Errorf("failed to get commit tree: %w", err)
	}

	file, err := tree.File(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to get file from tree: %w", err)
	}

	contents, err := file.Contents()
	if err != nil {
		return nil, fmt.Errorf("failed to read file contents: %w", err)
	}

	var zone model.Zone
	if err := json.Unmarshal([]byte(contents), &zone); err != nil {
		return nil, fmt.Errorf("failed to parse zone JSON: %w", err)
	}

	return &zone, nil
}

// ListRevisions returns version history for a zone
func (g *GitBackend) ListRevisions(ctx context.Context, zoneName string, opts ListOptions) ([]*model.ZoneVersion, error) {
	normalized := model.NormalizeZoneName(zoneName)

	g.mu.RLock()
	defer g.mu.RUnlock()

	// Get commit history for the zone file
	filePath, err := g.zoneFilePath(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	commits, err := g.repo.Log(&git.LogOptions{
		FileName: &filePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit history: %w", err)
	}

	versions := make([]*model.ZoneVersion, 0)
	err = commits.ForEach(func(c *object.Commit) error {
		// Extract version from commit message
		lines := strings.Split(c.Message, "\n")
		var version string
		for _, line := range lines {
			if strings.HasPrefix(line, "Version: ") {
				version = strings.TrimPrefix(line, "Version: ")
				break
			}
		}

		if version == "" {
			return nil // Skip commits without version trailer
		}

		// Get zone data at this commit
		tree, err := c.Tree()
		if err != nil {
			return nil // Skip on error
		}

		file, err := tree.File(filePath)
		if err != nil {
			return nil // Skip on error
		}

		contents, err := file.Contents()
		if err != nil {
			return nil // Skip on error
		}

		var zone model.Zone
		if err := json.Unmarshal([]byte(contents), &zone); err != nil {
			return nil // Skip on error
		}

		versions = append(versions, &model.ZoneVersion{
			Version:   version,
			Timestamp: c.Author.When,
			Serial:    zone.SOA.Serial,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	// Apply pagination
	start := opts.Offset
	if start > len(versions) {
		return make([]*model.ZoneVersion, 0), nil
	}

	// Limit==0 means return all (no limit)
	if opts.Limit <= 0 {
		return versions[start:], nil
	}

	end := start + opts.Limit
	if end > len(versions) {
		end = len(versions)
	}

	return versions[start:end], nil
}

// GetCurrentVersion returns the current version of a zone
func (g *GitBackend) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	zone, err := g.GetZone(ctx, zoneName)
	if err != nil {
		return "", err
	}
	return zone.Version, nil
}
