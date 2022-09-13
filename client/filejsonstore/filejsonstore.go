package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	"github.com/theupdateframework/go-tuf/client"
	"github.com/theupdateframework/go-tuf/internal/fsutil"
	"github.com/theupdateframework/go-tuf/util"
)

const (
	// user:  rwx
	// group: r-x
	// other: ---
	dirCreateMode = os.FileMode(0750)
	// user:  rw-
	// group: r--
	// other: ---
	fileCreateMode = os.FileMode(0640)
)

// FileJSONStore represents a local metadata cache relying on raw JSON files
// as retrieved from the remote repository.
type FileJSONStore struct {
	mtx     sync.RWMutex
	baseDir string
}

var _ client.LocalStore = (*FileJSONStore)(nil)

// NewFileJSONStore returns a new metadata cache, implemented using raw JSON
// files, stored in a directory provided by the client.
// If the provided directory does not exist on disk, it will be created.
// The provided metadata cache is safe for concurrent access.
func NewFileJSONStore(baseDir string) (*FileJSONStore, error) {
	f := &FileJSONStore{
		baseDir: baseDir,
	}

	// Does the directory exist?
	fi, err := os.Stat(baseDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// Create the directory
			if err = os.MkdirAll(baseDir, dirCreateMode); err != nil {
				return nil, fmt.Errorf("error creating directory for metadata cache: %w", err)
			}
		} else {
			return nil, fmt.Errorf("error getting FileInfo for %s: %w", baseDir, err)
		}
	} else {
		// Verify that it is a directory
		if !fi.IsDir() {
			return nil, fmt.Errorf("can not open %s, not a directory", baseDir)
		}
		// Verify file mode is not too permissive.
		if err = fsutil.EnsureMaxPermissions(fi, dirCreateMode); err != nil {
			return nil, err
		}
	}

	return f, nil
}

// GetMeta returns the currently cached set of metadata files.
func (f *FileJSONStore) GetMeta() (map[string]json.RawMessage, error) {
	f.mtx.RLock()
	defer f.mtx.RUnlock()

	names, err := os.ReadDir(f.baseDir)
	if err != nil {
		return nil, fmt.Errorf("error reading directory %s: %w", f.baseDir, err)
	}

	meta := map[string]json.RawMessage{}
	for _, name := range names {
		ok, err := fsutil.IsMetaFile(name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}

		// Verify permissions
		info, err := name.Info()
		if err != nil {
			return nil, fmt.Errorf("error retrieving FileInfo for %s: %w", name.Name(), err)
		}
		if err = fsutil.EnsureMaxPermissions(info, fileCreateMode); err != nil {
			return nil, err
		}

		p := filepath.Join(f.baseDir, name.Name())
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("error reading file %s: %w", name.Name(), err)
		}
		meta[name.Name()] = b
	}

	return meta, nil
}

// SetMeta stores a metadata file in the cache. If the metadata file exist,
// it will be overwritten.
func (f *FileJSONStore) SetMeta(name string, meta json.RawMessage) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	if filepath.Ext(name) != ".json" {
		return fmt.Errorf("file %s is not a JSON file", name)
	}

	p := filepath.Join(f.baseDir, name)
	err := util.AtomicallyWriteFile(p, meta, fileCreateMode)
	return err
}

// DeleteMeta deletes a metadata file from the cache.
// If the file does not exist, an *os.PathError is returned.
func (f *FileJSONStore) DeleteMeta(name string) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	if filepath.Ext(name) != ".json" {
		return fmt.Errorf("file %s is not a JSON file", name)
	}

	p := filepath.Join(f.baseDir, name)
	err := os.Remove(p)
	if err == nil {
		return nil
	}

	return fmt.Errorf("error deleting file %s: %w", name, err)
}

// Close closes the metadata cache. This is a no-op.
func (f *FileJSONStore) Close() error {
	return nil
}
