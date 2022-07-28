package filejsonstore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

type FileJSONStore struct {
	f       *os.File
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

	if f.f, err = os.Open(baseDir); err != nil {
		pe, ok := err.(*os.PathError)
		fmt.Println(ok)
		fmt.Println(pe.Err)
		if ok && errors.Is(pe.Err, os.ErrNotExist) && recurse {
			// Create the directory
			err = os.Mkdir(baseDir, 0750)
			if err == nil {
				return newImpl(baseDir, false)
			}
			return nil, err
		} else {
			return nil, err
		}
	}

	if stat, err := f.f.Stat(); err != nil {
		f.f.Close()
		return nil, fmt.Errorf("failed to stat file %s: %w",
			baseDir, err)
	} else {
		if !stat.IsDir() {
			f.f.Close()
			return nil, fmt.Errorf("can not open %s, not a directory",
				baseDir)
		}
	}

	return &f, nil
}

func (f *FileJSONStore) GetMeta() (map[string]json.RawMessage, error) {
	names, err := f.f.Readdirnames(0)

	if err != nil {
		return nil, err
	}

	meta := map[string]json.RawMessage{}
	for _, name := range names {
		p := filepath.FromSlash(filepath.Join(f.baseDir, name))
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		meta[name] = b
	}

	return meta, nil
}

func (f *FileJSONStore) SetMeta(name string, meta json.RawMessage) error {
	p := filepath.FromSlash(filepath.Join(f.baseDir, name))
	return os.WriteFile(p, meta, 0640)
}

func (f *FileJSONStore) DeleteMeta(name string) error {
	p := filepath.FromSlash(filepath.Join(f.baseDir, name))
	return os.Remove(p)
}

func (f *FileJSONStore) Close() error {
	if f == nil {
		return nil
	}
	if f.f != nil {
		return f.f.Close()
	}
	return nil
}
