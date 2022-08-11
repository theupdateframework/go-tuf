package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/theupdateframework/go-tuf/internal/fsutil"
	"github.com/theupdateframework/go-tuf/util"
)

// ErrNotJSON is returned when a metadata operation is attempted
// against a file that does not seem to be a JSON file
// (e.g. does not end in .json, case sensitive).
var ErrNotJSON = errors.New("file is not in JSON format")

// ErrToPermissive is returned when the metadata directory, or a metadata
// file has too permissive file mode bits set
var ErrTooPermissive = errors.New("permissions are too permissive")

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

// NewFileJSONStore returns a new metadata cache, implemented using raw JSON
// files, stored in a directory provided by the client.
// If the provided directory does not exist on disk, it will be created.
// The provided metadata cache is safe for concurrent access.
func NewFileJSONStore(baseDir string) (*FileJSONStore, error) {
	var f = FileJSONStore{
		baseDir: baseDir,
	}
	var err error

	// Does the directory exist?
	fi, err := os.Stat(baseDir)
	if err != nil {
		pe, ok := err.(*os.PathError)
		if ok && errors.Is(pe.Err, os.ErrNotExist) {
			// Create the directory
			if err = os.MkdirAll(baseDir, dirCreateMode); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		// Verify that it is a directory
		if !fi.IsDir() {
			return nil, fmt.Errorf("can not open %s, not a directory",
				baseDir)
		}
		// Verify file mode is not too permissive.
		if err = fsutil.EnsurePermission(fi, dirCreateMode); err != nil {
			return nil, ErrTooPermissive
		}
	}

	return &f, nil
}

// GetMeta returns the currently cached set of metadata files.
func (f *FileJSONStore) GetMeta() (map[string]json.RawMessage, error) {
	f.mtx.RLock()
	defer f.mtx.RUnlock()

	names, err := os.ReadDir(f.baseDir)
	if err != nil {
		return nil, err
	}

	meta := map[string]json.RawMessage{}
	for _, name := range names {
		p := filepath.FromSlash(filepath.Join(f.baseDir, name.Name()))
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
			return nil, err
		}
		if err = fsutil.EnsurePermission(info, fileCreateMode); err != nil {
			return nil, ErrTooPermissive
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
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
		return ErrNotJSON
	}

	p := filepath.FromSlash(filepath.Join(f.baseDir, name))
	err := util.AtomicallyWriteFile(p, meta, fileCreateMode)
	return err
}

// DeleteMeta deletes a metadata file from the cache.
// If the file does not exist, an *os.PathError is returned.
func (f *FileJSONStore) DeleteMeta(name string) error {
	f.mtx.Lock()
	defer f.mtx.Unlock()

	if filepath.Ext(name) != ".json" {
		return ErrNotJSON
	}

	p := filepath.FromSlash(filepath.Join(f.baseDir, name))
	err := os.Remove(p)
	return err
}

// Close closes the metadata cache. This is a no-op.
func (f *FileJSONStore) Close() error {
	return nil
}
