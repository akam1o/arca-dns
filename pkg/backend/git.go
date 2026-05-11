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
	"github.com/akam1o/arca-dns/pkg/util"
	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	gitconfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/format/index"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
	"github.com/gofrs/flock"
)

const maxLegacyZoneFilenameLength = 255

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

		remoteURL, _ := cfg["remote_url"].(string)

		autoPush, autoPushSet := boolFromConfig(cfg["auto_push"])
		autoPull, autoPullSet := boolFromConfig(cfg["auto_pull"])
		if autoSync, ok := boolFromConfig(cfg["auto_sync"]); ok {
			if !autoPushSet {
				autoPush = autoSync
			}
			if !autoPullSet {
				autoPull = autoSync
			}
		} else if autoPushSet && !autoPullSet {
			autoPull = autoPush
		}

		pullInterval, _ := durationFromConfig(cfg["pull_interval"])

		return NewGitBackendWithOptions(repoPath, GitBackendOptions{
			Branch:       branch,
			AuthorName:   authorName,
			AuthorEmail:  authorEmail,
			RemoteURL:    remoteURL,
			AutoPush:     autoPush,
			AutoPull:     autoPull,
			PullInterval: pullInterval,
		})
	})
}

// GitBackendOptions configures a Git-backed zone store.
type GitBackendOptions struct {
	Branch       string
	AuthorName   string
	AuthorEmail  string
	RemoteURL    string
	AutoPush     bool
	AutoPull     bool
	PullInterval time.Duration
}

// GitBackend implements ZoneStore and RevisionStore using a Git repository
type GitBackend struct {
	repoPath    string
	branch      string
	authorName  string
	authorEmail string
	remoteURL   string

	autoPush     bool
	autoPull     bool
	pullInterval time.Duration
	lastPull     time.Time

	repo      *git.Repository
	worktree  *git.Worktree
	repoLock  chan struct{}
	fileLock  *flock.Flock
	zoneMutex sync.Map // map[string]*sync.Mutex (per-zone locking)
}

type gitRollbackFile struct {
	relPath      string
	absPath      string
	fileData     []byte
	fileMode     os.FileMode
	fileExists   bool
	indexTracked bool
}

type gitRollbackPoint struct {
	files    []gitRollbackFile
	headHash plumbing.Hash
	headRef  *plumbing.Reference
	hasHead  bool
}

// NewGitBackend creates a new Git backend
// If the repository doesn't exist, it will be initialized
func NewGitBackend(repoPath, branch, authorName, authorEmail string, autoSync bool) (*GitBackend, error) {
	return NewGitBackendWithOptions(repoPath, GitBackendOptions{
		Branch:      branch,
		AuthorName:  authorName,
		AuthorEmail: authorEmail,
		AutoPush:    autoSync,
		AutoPull:    autoSync,
	})
}

// NewGitBackendWithOptions creates a new Git backend with explicit options.
func NewGitBackendWithOptions(repoPath string, options GitBackendOptions) (*GitBackend, error) {
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve repository path: %w", err)
	}

	if options.Branch == "" {
		options.Branch = "main"
	}
	if options.AuthorName == "" {
		options.AuthorName = "arca-dns-controller"
	}
	if options.AuthorEmail == "" {
		options.AuthorEmail = "noreply@arca-dns"
	}

	// Initialize or open repository
	repo, err := openOrInitRepo(absPath, options.Branch)
	if err != nil {
		return nil, fmt.Errorf("failed to open/init repository: %w", err)
	}

	if options.RemoteURL != "" {
		if err := ensureRemote(repo, "origin", options.RemoteURL); err != nil {
			return nil, err
		}
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
		repoPath:     absPath,
		branch:       options.Branch,
		authorName:   options.AuthorName,
		authorEmail:  options.AuthorEmail,
		remoteURL:    options.RemoteURL,
		autoPush:     options.AutoPush,
		autoPull:     options.AutoPull,
		pullInterval: options.PullInterval,
		repo:         repo,
		worktree:     worktree,
		repoLock:     make(chan struct{}, 1),
		fileLock:     fileLock,
	}, nil
}

// HealthCheck verifies that the local Git repository is usable without loading
// zone contents or contacting the remote.
func (g *GitBackend) HealthCheck(ctx context.Context) error {
	if err := g.acquireFileLock(ctx); err != nil {
		return err
	}
	defer g.releaseFileLock()

	if _, err := os.Stat(g.repoPath); err != nil {
		return fmt.Errorf("git repository path unavailable: %w", err)
	}
	if _, err := g.repo.Head(); err != nil && err != plumbing.ErrReferenceNotFound {
		return fmt.Errorf("git repository head unavailable: %w", err)
	}

	zonesDir := filepath.Join(g.repoPath, "zones")
	if _, err := os.Stat(zonesDir); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("git zones directory unavailable: %w", err)
	}
	return nil
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
			} else if headErr == plumbing.ErrReferenceNotFound {
				// Empty repositories do not have a commit to checkout from yet.
				// Point HEAD at the configured branch so the first commit lands there.
				if err := repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branchRef)); err != nil {
					return nil, fmt.Errorf("failed to set HEAD to branch %s: %w", branch, err)
				}
			} else {
				return nil, headErr
			}
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

	repo, err = git.InitWithOptions(storage, fs, git.InitOptions{
		DefaultBranch: plumbing.NewBranchReferenceName(branch),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initialize repository: %w", err)
	}

	return repo, nil
}

func ensureRemote(repo *git.Repository, name, remoteURL string) error {
	cfg, err := repo.Config()
	if err != nil {
		return fmt.Errorf("failed to read git config: %w", err)
	}
	if cfg.Remotes == nil {
		cfg.Remotes = make(map[string]*gitconfig.RemoteConfig)
	}
	cfg.Remotes[name] = &gitconfig.RemoteConfig{
		Name: name,
		URLs: []string{remoteURL},
	}
	if err := repo.SetConfig(cfg); err != nil {
		return fmt.Errorf("failed to configure git remote %s: %w", name, err)
	}
	return nil
}

func boolFromConfig(value interface{}) (bool, bool) {
	v, ok := value.(bool)
	return v, ok
}

func (g *GitBackend) acquireRepoLock(ctx context.Context) error {
	select {
	case g.repoLock <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (g *GitBackend) releaseRepoLock() {
	<-g.repoLock
}

// acquireFileLock acquires the in-process repository lock and cross-process file lock.
func (g *GitBackend) acquireFileLock(ctx context.Context) error {
	if err := g.acquireRepoLock(ctx); err != nil {
		return err
	}

	locked := false
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			g.releaseRepoLock()
			return ctx.Err()
		case <-ticker.C:
			var err error
			locked, err = g.fileLock.TryLock()
			if err != nil {
				g.releaseRepoLock()
				return fmt.Errorf("failed to acquire file lock: %w", err)
			}
			if locked {
				return nil
			}
		}
	}
}

func (g *GitBackend) releaseFileLock() {
	_ = g.fileLock.Unlock()
	g.releaseRepoLock()
}

// acquireLock acquires both file lock and per-zone mutex.
func (g *GitBackend) acquireLock(ctx context.Context, zoneName string) (*sync.Mutex, error) {
	if err := g.acquireFileLock(ctx); err != nil {
		return nil, err
	}

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
	g.releaseFileLock()
}

// zoneFilePath returns the path to the zone JSON file
// Returns error if the zone name would escape the zones directory
func (g *GitBackend) zoneFilePath(zoneName string) (string, error) {
	normalized, err := normalizeZoneNameForPath(zoneName)
	if err != nil {
		return "", err
	}

	return g.zoneRelPath(util.SafeZoneFilename(normalized) + ".json")
}

func (g *GitBackend) legacyZoneFilePath(zoneName string) (string, error) {
	normalized, err := normalizeZoneNameForPath(zoneName)
	if err != nil {
		return "", err
	}

	return g.zoneRelPath(normalized + ".json")
}

func (g *GitBackend) zoneFilePathCandidates(zoneName string) ([]string, error) {
	safePath, err := g.zoneFilePath(zoneName)
	if err != nil {
		return nil, err
	}

	legacyPath, err := g.legacyZoneFilePath(zoneName)
	if err != nil {
		return nil, err
	}
	if len(filepath.Base(legacyPath)) > maxLegacyZoneFilenameLength {
		return []string{safePath}, nil
	}
	if legacyPath == safePath {
		return []string{safePath}, nil
	}
	return []string{safePath, legacyPath}, nil
}

func (g *GitBackend) existingZoneFilePath(zoneName string) (string, error) {
	paths, err := g.zoneFilePathCandidates(zoneName)
	if err != nil {
		return "", err
	}

	for _, relPath := range paths {
		if _, err := os.Stat(filepath.Join(g.repoPath, relPath)); err == nil {
			return relPath, nil
		} else if !os.IsNotExist(err) {
			return "", fmt.Errorf("failed to stat zone file: %w", err)
		}
	}

	return paths[0], nil
}

func normalizeZoneNameForPath(zoneName string) (string, error) {
	normalized := model.NormalizeZoneName(zoneName)

	// Additional security: prevent path traversal
	// Reject absolute paths, "..", and path separators in zone name
	if filepath.IsAbs(normalized) {
		return "", fmt.Errorf("zone name cannot be absolute path")
	}
	if strings.Contains(normalized, "..") {
		return "", fmt.Errorf("zone name cannot contain '..'")
	}
	if strings.ContainsAny(normalized, `/\`) {
		return "", fmt.Errorf("zone name cannot contain path separators")
	}

	return normalized, nil
}

func (g *GitBackend) zoneRelPath(filename string) (string, error) {
	relPath := filepath.Join("zones", filename)

	// Verify the resolved path is within zones directory
	absPath := filepath.Join(g.repoPath, relPath)
	zonesDir := filepath.Join(g.repoPath, "zones")
	if !strings.HasPrefix(absPath, zonesDir+string(filepath.Separator)) && absPath != zonesDir {
		return "", fmt.Errorf("zone path would escape zones directory")
	}

	return relPath, nil
}

// pullIfNeeded performs a fast-forward-only pull if auto-pull is enabled
func (g *GitBackend) pullIfNeeded(ctx context.Context) error {
	if !g.autoPull {
		return nil
	}
	if g.pullInterval > 0 && !g.lastPull.IsZero() && time.Since(g.lastPull) < g.pullInterval {
		return nil
	}

	err := g.worktree.PullContext(ctx, &git.PullOptions{
		RemoteName:    "origin",
		ReferenceName: plumbing.NewBranchReferenceName(g.branch),
		Force:         false, // Fast-forward only
	})

	if err == git.NoErrAlreadyUpToDate {
		g.lastPull = time.Now()
		return nil
	}

	if err != nil {
		if strings.Contains(err.Error(), "non-fast-forward") {
			return fmt.Errorf("git pull failed: non-fast-forward update rejected (manual merge required)")
		}
		return fmt.Errorf("git pull failed: %w", err)
	}

	g.lastPull = time.Now()
	return nil
}

func (g *GitBackend) snapshotZoneFile(zoneName string) (*gitRollbackPoint, error) {
	relPath, err := g.existingZoneFilePath(zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	return g.snapshotZoneFilePaths([]string{relPath})
}

func (g *GitBackend) snapshotExistingZoneFiles(zoneName string) (*gitRollbackPoint, error) {
	paths, err := g.zoneFilePathCandidates(zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	existingPaths := make([]string, 0, len(paths))
	for _, relPath := range paths {
		_, err := os.Stat(filepath.Join(g.repoPath, relPath))
		if err == nil {
			existingPaths = append(existingPaths, relPath)
			continue
		}
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat zone file: %w", err)
		}
	}
	if len(existingPaths) == 0 {
		return nil, model.ErrZoneNotFound
	}

	return g.snapshotZoneFilePaths(existingPaths)
}

func (g *GitBackend) snapshotZoneFilePaths(relPaths []string) (*gitRollbackPoint, error) {
	point := &gitRollbackPoint{
		files: make([]gitRollbackFile, 0, len(relPaths)),
	}

	idx, err := g.repo.Storer.Index()
	if err != nil {
		return nil, fmt.Errorf("failed to read git index: %w", err)
	}

	for _, relPath := range relPaths {
		file := gitRollbackFile{
			relPath: relPath,
			absPath: filepath.Join(g.repoPath, relPath),
		}

		info, err := os.Stat(file.absPath)
		if err == nil {
			file.fileExists = true
			file.fileMode = info.Mode()
			file.fileData, err = os.ReadFile(file.absPath)
			if err != nil {
				return nil, fmt.Errorf("failed to snapshot zone file: %w", err)
			}
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to stat zone file: %w", err)
		}

		if _, err := idx.Entry(relPath); err == nil {
			file.indexTracked = true
		} else if err != index.ErrEntryNotFound {
			return nil, fmt.Errorf("failed to inspect git index: %w", err)
		}

		point.files = append(point.files, file)
	}

	head, err := g.repo.Head()
	if err == nil {
		point.hasHead = true
		point.headHash = head.Hash()
		headRef, err := g.repo.Reference(plumbing.HEAD, false)
		if err != nil {
			return nil, fmt.Errorf("failed to snapshot git head reference: %w", err)
		}
		point.headRef = headRef
		return point, nil
	}
	if err != plumbing.ErrReferenceNotFound {
		return nil, fmt.Errorf("failed to snapshot git head: %w", err)
	}

	return point, nil
}

func (g *GitBackend) restoreZoneFile(point *gitRollbackPoint) error {
	for _, file := range point.files {
		if file.fileExists {
			if err := os.MkdirAll(filepath.Dir(file.absPath), 0755); err != nil {
				return fmt.Errorf("failed to recreate zone directory: %w", err)
			}
			if err := os.WriteFile(file.absPath, file.fileData, file.fileMode.Perm()); err != nil {
				return fmt.Errorf("failed to restore zone file: %w", err)
			}
			continue
		}

		if err := os.Remove(file.absPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to remove rolled back zone file: %w", err)
		}
	}
	return nil
}

func (g *GitBackend) restoreHead(point *gitRollbackPoint) error {
	if !point.hasHead {
		branchRef := plumbing.NewBranchReferenceName(g.branch)
		if err := g.repo.Storer.RemoveReference(branchRef); err != nil && err != plumbing.ErrReferenceNotFound {
			return fmt.Errorf("failed to remove rolled back branch reference: %w", err)
		}
		if err := g.repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branchRef)); err != nil {
			return fmt.Errorf("failed to restore git head reference: %w", err)
		}
		return nil
	}

	if point.headRef != nil && point.headRef.Type() == plumbing.SymbolicReference {
		branchRef := point.headRef.Target()
		if err := g.repo.Storer.SetReference(plumbing.NewHashReference(branchRef, point.headHash)); err != nil {
			return fmt.Errorf("failed to restore git branch reference: %w", err)
		}
		if err := g.repo.Storer.SetReference(plumbing.NewSymbolicReference(plumbing.HEAD, branchRef)); err != nil {
			return fmt.Errorf("failed to restore git head reference: %w", err)
		}
		return nil
	}

	if err := g.repo.Storer.SetReference(plumbing.NewHashReference(plumbing.HEAD, point.headHash)); err != nil {
		return fmt.Errorf("failed to restore git head reference: %w", err)
	}
	return nil
}

func (g *GitBackend) restoreIndex(point *gitRollbackPoint) error {
	for _, file := range point.files {
		if !file.indexTracked || !file.fileExists {
			if err := g.removeFromIndex(file.relPath); err != nil {
				return err
			}
			continue
		}

		if _, err := g.worktree.Add(file.relPath); err != nil {
			return fmt.Errorf("failed to restore zone in git index: %w", err)
		}
	}

	return nil
}

func (g *GitBackend) removeFromIndex(relPath string) error {
	idx, err := g.repo.Storer.Index()
	if err != nil {
		return fmt.Errorf("failed to read git index: %w", err)
	}
	if _, err := idx.Remove(relPath); err != nil && err != index.ErrEntryNotFound {
		return fmt.Errorf("failed to remove zone from git index: %w", err)
	}
	if err := g.repo.Storer.SetIndex(idx); err != nil {
		return fmt.Errorf("failed to write git index: %w", err)
	}
	return nil
}

func (g *GitBackend) rollbackZoneMutation(point *gitRollbackPoint) error {
	if err := g.restoreHead(point); err != nil {
		return err
	}
	if err := g.restoreZoneFile(point); err != nil {
		return err
	}
	return g.restoreIndex(point)
}

func (g *GitBackend) wrapWithRollback(point *gitRollbackPoint, err error) error {
	if point == nil {
		return err
	}
	if rollbackErr := g.rollbackZoneMutation(point); rollbackErr != nil {
		return fmt.Errorf("%w (rollback failed: %v)", err, rollbackErr)
	}
	return err
}

// commitZone commits changes to the zone file
func (g *GitBackend) commitZone(ctx context.Context, zoneName, operation, summary string, zone *model.Zone, rollback *gitRollbackPoint) error {
	message := fmt.Sprintf("[%s] %s: %s\n\nVersion: %s", operation, zoneName, summary, zone.Version)
	return g.commitZoneWithMessage(ctx, zoneName, message, rollback)
}

func (g *GitBackend) commitZoneMetadata(ctx context.Context, zoneName, operation, summary string, rollback *gitRollbackPoint) error {
	message := fmt.Sprintf("[%s] %s: %s", operation, zoneName, summary)
	return g.commitZoneWithMessage(ctx, zoneName, message, rollback)
}

func (g *GitBackend) commitZoneWithMessage(ctx context.Context, zoneName, message string, rollback *gitRollbackPoint) error {
	filePath, err := g.existingZoneFilePath(zoneName)
	if err != nil {
		return fmt.Errorf("invalid zone path: %w", err)
	}

	// Add file to staging
	_, err = g.worktree.Add(filePath)
	if err != nil {
		return g.wrapWithRollback(rollback, fmt.Errorf("failed to add file to git: %w", err))
	}

	// Commit
	_, err = g.worktree.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  g.authorName,
			Email: g.authorEmail,
			When:  time.Now(),
		},
	})
	if err != nil {
		return g.wrapWithRollback(rollback, fmt.Errorf("failed to commit: %w", err))
	}

	// Push if auto-push is enabled
	if g.autoPush {
		err = g.repo.PushContext(ctx, &git.PushOptions{
			RemoteName: "origin",
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("git push failed after local commit was retained: %w", err)
		}
	}

	return nil
}

// removeAndCommit removes a zone file and commits the deletion
func (g *GitBackend) removeAndCommit(ctx context.Context, zoneName, summary string) error {
	rollback, err := g.snapshotExistingZoneFiles(zoneName)
	if err != nil {
		return err
	}

	trackedRemovals := 0
	for _, file := range rollback.files {
		if file.indexTracked {
			if _, err := g.worktree.Remove(file.relPath); err != nil {
				return g.wrapWithRollback(rollback, fmt.Errorf("failed to remove file from git: %w", err))
			}
			trackedRemovals++
			continue
		}

		if err := os.Remove(file.absPath); err != nil && !os.IsNotExist(err) {
			return g.wrapWithRollback(rollback, fmt.Errorf("failed to remove untracked zone file: %w", err))
		}
	}

	if trackedRemovals == 0 {
		return nil
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
		return g.wrapWithRollback(rollback, fmt.Errorf("failed to commit deletion: %w", err))
	}

	// Push if auto-push is enabled
	if g.autoPush {
		err = g.repo.PushContext(ctx, &git.PushOptions{
			RemoteName: "origin",
		})
		if err != nil && err != git.NoErrAlreadyUpToDate {
			return fmt.Errorf("git push failed after local commit was retained: %w", err)
		}
	}

	return nil
}

// readZone reads and parses a zone JSON file
func (g *GitBackend) readZone(zoneName string) (*model.Zone, error) {
	paths, err := g.zoneFilePathCandidates(zoneName)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	for _, relPath := range paths {
		zone, err := g.readZoneFile(relPath)
		if err == nil {
			return zone, nil
		}
		if err == model.ErrZoneNotFound {
			continue
		}
		return nil, err
	}

	return nil, model.ErrZoneNotFound
}

func (g *GitBackend) readZoneFile(relPath string) (*model.Zone, error) {
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
	relPath, err := g.existingZoneFilePath(zoneName)
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

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return nil, err
	}
	defer g.releaseLock(zoneMu)

	if err := g.pullIfNeeded(ctx); err != nil {
		return nil, err
	}

	return g.readZone(normalized)
}

// ListZones returns all zones with pagination
func (g *GitBackend) ListZones(ctx context.Context, opts ListOptions) ([]*model.Zone, error) {
	if err := g.acquireFileLock(ctx); err != nil {
		return nil, err
	}
	defer g.releaseFileLock()

	if err := g.pullIfNeeded(ctx); err != nil {
		return nil, err
	}

	zonesDir := filepath.Join(g.repoPath, "zones")
	entries, err := os.ReadDir(zonesDir)
	if err != nil {
		if os.IsNotExist(err) {
			return make([]*model.Zone, 0), nil
		}
		return nil, fmt.Errorf("failed to read zones directory: %w", err)
	}

	zonesByName := make(map[string]*model.Zone)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}

		zoneName := strings.TrimSuffix(entry.Name(), ".json")
		relPath := filepath.Join("zones", entry.Name())
		zone, err := g.readZoneFile(relPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read zone %q from git backend: %w", zoneName, err)
		}

		key := zone.Name
		if key == "" {
			key = zoneName
		}
		if _, exists := zonesByName[key]; exists {
			safePath, err := g.zoneFilePath(zone.Name)
			if err == nil && relPath == safePath {
				zonesByName[key] = zone
			}
			continue
		}
		zonesByName[key] = zone
	}

	zones := make([]*model.Zone, 0, len(zonesByName))
	for _, zone := range zonesByName {
		zones = append(zones, zone)
	}

	// Sort by name for consistent ordering
	sort.Slice(zones, func(i, j int) bool {
		return zones[i].Name < zones[j].Name
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
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
	writeZone, err := prepareZoneForCreate(zone, model.NormalizeZoneName)
	if err != nil {
		return err
	}
	normalized := writeZone.Name

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	// Pull if auto-pull is enabled
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

	rollback, err := g.snapshotZoneFile(normalized)
	if err != nil {
		return err
	}

	// Write zone file
	if err := g.writeZone(normalized, writeZone); err != nil {
		return err
	}

	// Commit
	summary := fmt.Sprintf("created zone with %d records", len(writeZone.Records))
	if err := g.commitZone(ctx, normalized, "create", summary, writeZone, rollback); err != nil {
		return err
	}
	copyZoneInto(zone, writeZone)
	return nil
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

	// Pull if auto-pull is enabled
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

	// Advance from the stored serial. A caller may provide a precomputed
	// greater serial when another component already used it for a prepared artifact.
	zone.SOA.Serial = updateSOASerial(currentZone.SOA.Serial, zone.SOA.Serial)

	// Update timestamp
	zone.UpdatedAt = time.Now()

	// Ensure version changes on update (normally issued by controller).
	if zone.Version == "" || zone.Version == currentZone.Version {
		newVersion, err := model.NewZoneVersion()
		if err != nil {
			return fmt.Errorf("generate zone version: %w", err)
		}
		zone.Version = newVersion
	}

	if err := validateZoneForWrite(zone); err != nil {
		return err
	}

	rollback, err := g.snapshotZoneFile(normalized)
	if err != nil {
		return err
	}

	// Write updated zone file
	if err := g.writeZone(normalized, zone); err != nil {
		return err
	}

	// Commit
	summary := fmt.Sprintf("updated zone (%d records)", len(zone.Records))
	return g.commitZone(ctx, normalized, "update", summary, zone, rollback)
}

// UpdateDNSSECMetadata updates DNSSEC metadata without changing zone version or SOA serial.
func (g *GitBackend) UpdateDNSSECMetadata(ctx context.Context, zoneName string, dnssec *model.DNSSECConfig) error {
	normalized := model.NormalizeZoneName(zoneName)

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	if err := g.pullIfNeeded(ctx); err != nil {
		return err
	}

	zone, err := g.readZone(normalized)
	if err != nil {
		if err == model.ErrZoneNotFound {
			return model.ErrZoneNotFound
		}
		return err
	}

	zone.DNSSEC = cloneDNSSECConfig(dnssec)
	zone.UpdatedAt = time.Now()

	rollback, err := g.snapshotZoneFile(normalized)
	if err != nil {
		return err
	}

	if err := g.writeZone(normalized, zone); err != nil {
		return err
	}

	return g.commitZoneMetadata(ctx, normalized, "dnssec", "updated DNSSEC metadata", rollback)
}

// DeleteZone deletes a zone
func (g *GitBackend) DeleteZone(ctx context.Context, name string) error {
	normalized := model.NormalizeZoneName(name)

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	// Pull if auto-pull is enabled
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

	// Commit deletion
	summary := "deleted zone"
	return g.removeAndCommit(ctx, normalized, summary)
}

// DeleteZoneWithVersion deletes a zone only when its current version matches.
func (g *GitBackend) DeleteZoneWithVersion(ctx context.Context, name string, expectedVersion string) error {
	normalized := model.NormalizeZoneName(name)

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return err
	}
	defer g.releaseLock(zoneMu)

	if err := g.pullIfNeeded(ctx); err != nil {
		return err
	}

	zone, err := g.readZone(normalized)
	if err != nil {
		if err == model.ErrZoneNotFound {
			return model.ErrZoneNotFound
		}
		return err
	}
	if expectedVersion != "" && zone.Version != expectedVersion {
		return model.ErrConflict
	}

	return g.removeAndCommit(ctx, normalized, "deleted zone")
}

// Close closes the backend
func (g *GitBackend) Close() error {
	if err := g.acquireRepoLock(context.Background()); err != nil {
		return err
	}
	defer g.releaseRepoLock()

	// Release file lock if held
	_ = g.fileLock.Unlock()
	return nil
}

// Info returns backend metadata.
func (g *GitBackend) Info() BackendInfo {
	return BackendInfo{
		Type: "git",
		Capabilities: []string{
			CapabilityZoneStore,
			CapabilityHealthStore,
			CapabilityDNSSECMetadataStore,
			CapabilityConditionalDeleteStore,
			CapabilityRevisionStore,
		},
		Consistency: "eventual",
		Description: "Git-backed storage with revision history and auditability",
	}
}

// GetRevision retrieves a specific zone version from commit history
func (g *GitBackend) GetRevision(ctx context.Context, zoneName, version string) (*model.Zone, error) {
	normalized := model.NormalizeZoneName(zoneName)

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return nil, err
	}
	defer g.releaseLock(zoneMu)

	if err := g.pullIfNeeded(ctx); err != nil {
		return nil, err
	}

	filePaths, err := g.zoneFilePathCandidates(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	for _, filePath := range filePaths {
		zone, err := g.getRevisionFromPath(filePath, version)
		if err == nil {
			return zone, nil
		}
		if err == model.ErrVersionNotFound {
			continue
		}
		return nil, err
	}

	return nil, model.ErrVersionNotFound
}

func (g *GitBackend) getRevisionFromPath(filePath, version string) (*model.Zone, error) {
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
		if commitVersion := extractVersionTrailer(c.Message); commitVersion == version {
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

	zoneMu, err := g.acquireLock(ctx, normalized)
	if err != nil {
		return nil, err
	}
	defer g.releaseLock(zoneMu)

	if err := g.pullIfNeeded(ctx); err != nil {
		return nil, err
	}

	filePaths, err := g.zoneFilePathCandidates(normalized)
	if err != nil {
		return nil, fmt.Errorf("invalid zone path: %w", err)
	}

	versions := make([]*model.ZoneVersion, 0)
	seenVersions := make(map[string]struct{})
	for _, filePath := range filePaths {
		pathVersions, err := g.listRevisionsForPath(filePath)
		if err != nil {
			return nil, err
		}
		for _, version := range pathVersions {
			if _, exists := seenVersions[version.Version]; exists {
				continue
			}
			seenVersions[version.Version] = struct{}{}
			versions = append(versions, version)
		}
	}

	sort.Slice(versions, func(i, j int) bool {
		if versions[i].Timestamp.Equal(versions[j].Timestamp) {
			return versions[i].Version > versions[j].Version
		}
		return versions[i].Timestamp.After(versions[j].Timestamp)
	})

	// Apply pagination
	start := opts.Offset
	if start < 0 {
		start = 0
	}
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

func (g *GitBackend) listRevisionsForPath(filePath string) ([]*model.ZoneVersion, error) {
	commits, err := g.repo.Log(&git.LogOptions{
		FileName: &filePath,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get commit history: %w", err)
	}

	versions := make([]*model.ZoneVersion, 0)
	err = commits.ForEach(func(c *object.Commit) error {
		version := extractVersionTrailer(c.Message)
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

		hashHex, err := ComputeZoneHash(&zone)
		if err != nil {
			hashHex = ""
		}
		hash8 := ""
		if len(hashHex) >= 8 {
			hash8 = hashHex[:8]
		}

		versions = append(versions, &model.ZoneVersion{
			Version:   version,
			Timestamp: c.Author.When,
			Serial:    zone.SOA.Serial,
			Hash:      hashHex,
			Hash8:     hash8,
		})

		return nil
	})

	if err != nil {
		return nil, err
	}

	return versions, nil
}

func extractVersionTrailer(message string) string {
	lines := strings.Split(message, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "Version: ") {
			return strings.TrimPrefix(line, "Version: ")
		}
	}
	return ""
}

// GetCurrentVersion returns the current version of a zone
func (g *GitBackend) GetCurrentVersion(ctx context.Context, zoneName string) (string, error) {
	zone, err := g.GetZone(ctx, zoneName)
	if err != nil {
		return "", err
	}
	return zone.Version, nil
}
