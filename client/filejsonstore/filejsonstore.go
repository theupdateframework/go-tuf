package filejsonstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/theupdateframework/go-tuf/util"
)

var ErrNotJSON = errors.New("file is not in JSON format")

type FileJSONStore struct {
	baseDir string
}

func New(baseDir string) (*FileJSONStore, error) {
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
			err = os.Mkdir(baseDir, 0750)
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

func (f *FileJSONStore) DeleteMeta(name string) error {
	p := filepath.FromSlash(filepath.Join(f.baseDir, name))
	err := os.Remove(p)
	return err
}

func (f *FileJSONStore) Close() error {
	return nil
}
