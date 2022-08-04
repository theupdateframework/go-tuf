package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/theupdateframework/go-tuf/util"
)

// ErrNotJSON is returned when a metadata operation is attempted to be
// performed against a file that does not seem to be a JSON file
// (e.g. does not end in .json, case sensitive).
var ErrNotJSON = errors.New("file is not in JSON format")

// FileJSONStore represents a local metadata cache relying on raw JSON files
// as retrieved from the remote repository.
type FileJSONStore struct {
	baseDir string
}

// NewFileJSONStore returns a new metadata cache, implemented using raw JSON
// files, stored in a directory provided by the client.
// If the provided directory does not exist on disk, it will be created.
// The provided metadata cache is not safe for concurrent access, if
// concurrent access safety is requires, wrap local store in a
// ConcurrentLocalStore.
func NewFileJSONStore(baseDir string) (*FileJSONStore, error) {
	return newImpl(baseDir, true)
}

func newImpl(baseDir string, recurse bool) (*FileJSONStore, error) {
	var f = FileJSONStore{
		baseDir: baseDir,
	}
	var err error

	// Does the directory exist?
	fi, err := os.Stat(baseDir)
	if err != nil {
		pe, ok := err.(*os.PathError)
		if ok && errors.Is(pe.Err, os.ErrNotExist) && recurse {
			// Create the directory
			// user:  rwx
			// group: r-x
			// other: ---
			err = os.MkdirAll(baseDir, 0750)
			if err == nil {
				return newImpl(baseDir, false)
			}
		}
		return nil, err
	}

	if !fi.IsDir() {
		return nil, fmt.Errorf("can not open %s, not a directory",
			baseDir)
	}

	return &f, nil
}

// GetMeta returns the currently cached set of metadata files.
func (f *FileJSONStore) GetMeta() (map[string]json.RawMessage, error) {
	names, err := os.ReadDir(f.baseDir)

	if err != nil {
		return nil, err
	}

	meta := map[string]json.RawMessage{}
	for _, name := range names {
		p := filepath.FromSlash(filepath.Join(f.baseDir, name.Name()))
		if ok, err := util.IsMetaFile(name); !ok {
			continue
		} else if err != nil {
			return nil, err
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
	if filepath.Ext(name) != ".json" {
		return ErrNotJSON
	}

	p := filepath.FromSlash(filepath.Join(f.baseDir, name))
	// user:  rw-
	// group: r--
	// other: ---
	err := util.AtomicallyWriteFile(p, meta, 0640)
	return err
}

// DeleteMeta deletes a metadata file from the cache.
// If the file does not exist, an *os.PathError is returned.
func (f *FileJSONStore) DeleteMeta(name string) error {
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
