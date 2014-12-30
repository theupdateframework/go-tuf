package tuf

import (
	"bytes"
	"encoding/json"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
)

func MemoryStore(meta map[string]json.RawMessage, files map[string][]byte) LocalStore {
	return &memoryStore{
		meta:  meta,
		files: files,
		keys:  make(map[string][]*keys.Key),
	}
}

type memoryStore struct {
	meta  map[string]json.RawMessage
	files map[string][]byte
	keys  map[string][]*keys.Key
}

func (m *memoryStore) GetMeta() (map[string]json.RawMessage, error) {
	return m.meta, nil
}

func (m *memoryStore) SetMeta(name string, meta json.RawMessage) error {
	m.meta[name] = meta
	return nil
}

type bytesReadCloser struct {
	*bytes.Reader
}

func (b bytesReadCloser) Close() error {
	return nil
}

func (m *memoryStore) GetStagedTarget(path string) (io.ReadCloser, error) {
	data, ok := m.files[path]
	if !ok {
		return nil, ErrFileNotFound{path}
	}
	return bytesReadCloser{bytes.NewReader(data)}, nil
}

func (m *memoryStore) Commit(meta map[string]json.RawMessage, targets data.Files) error {
	return nil
}

func (m *memoryStore) GetKeys(role string) ([]*keys.Key, error) {
	return m.keys[role], nil
}

func (m *memoryStore) SaveKey(role string, key *keys.Key) error {
	if _, ok := m.keys[role]; !ok {
		m.keys[role] = make([]*keys.Key, 0)
	}
	m.keys[role] = append(m.keys[role], key)
	return nil
}

func (m *memoryStore) Clean() error {
	return nil
}

func FileSystemStore(dir string) LocalStore {
	return &fileSystemStore{dir}
}

type fileSystemStore struct {
	dir string
}

func (f *fileSystemStore) repoDir() string {
	return filepath.Join(f.dir, "repository")
}

func (f *fileSystemStore) repoTargetsDir() string {
	return filepath.Join(f.repoDir(), "targets")
}

func (f *fileSystemStore) stagedDir() string {
	return filepath.Join(f.dir, "staged")
}

func (f *fileSystemStore) GetMeta() (map[string]json.RawMessage, error) {
	meta := make(map[string]json.RawMessage)
	var err error
	notExists := func(path string) bool {
		_, err := os.Stat(path)
		return os.IsNotExist(err)
	}
	for _, name := range topLevelManifests {
		path := filepath.Join(f.stagedDir(), name)
		if notExists(path) {
			path = filepath.Join(f.repoDir(), name)
			if notExists(path) {
				continue
			}
		}
		meta[name], err = ioutil.ReadFile(path)
		if err != nil {
			return nil, err
		}
	}
	return meta, nil
}

func (f *fileSystemStore) SetMeta(name string, meta json.RawMessage) error {
	if err := f.createDirs(); err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(f.stagedDir(), name), meta, 0644); err != nil {
		return err
	}
	return nil
}

func (f *fileSystemStore) createDirs() error {
	for _, dir := range []string{"keys", "repository", "staged/targets"} {
		if err := os.MkdirAll(filepath.Join(f.dir, dir), 0755); err != nil {
			return err
		}
	}
	return nil
}

func (f *fileSystemStore) GetStagedTarget(path string) (io.ReadCloser, error) {
	file, err := os.Open(filepath.Join(f.stagedDir(), "targets", path))
	if err != nil {
		return nil, err
	}
	return file, nil
}

func (f *fileSystemStore) Commit(meta map[string]json.RawMessage, targets data.Files) error {
	copyToRepo := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		rel, err := filepath.Rel(f.stagedDir(), path)
		if err != nil {
			return err
		}
		dst := filepath.Join(f.repoDir(), rel)
		if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
			return err
		}
		staged, err := os.Open(path)
		if err != nil {
			return err
		}
		defer staged.Close()
		file, err := os.Create(dst)
		if err != nil {
			return err
		}
		defer file.Close()
		if _, err = io.Copy(file, staged); err != nil {
			return err
		}
		return nil
	}
	needsRemoval := func(path string) bool {
		_, ok := targets[path]
		return !ok
	}
	removeFile := func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(f.repoTargetsDir(), path)
		if err != nil {
			return err
		}
		if !info.IsDir() && needsRemoval(rel) {
			if err := os.Remove(path); err != nil {
				// TODO: log / handle error
			}
			// TODO: remove empty directory
		}
		return nil
	}
	if err := filepath.Walk(f.stagedDir(), copyToRepo); err != nil {
		return err
	}
	if err := filepath.Walk(f.repoTargetsDir(), removeFile); err != nil {
		return err
	}
	return f.Clean()
}

func (f *fileSystemStore) GetKeys(role string) ([]*keys.Key, error) {
	files, err := ioutil.ReadDir(filepath.Join(f.dir, "keys"))
	if err != nil {
		return nil, err
	}
	signingKeys := make([]*keys.Key, 0, len(files))
	for _, file := range files {
		if !strings.HasPrefix(file.Name(), role) {
			continue
		}
		s, err := os.Open(filepath.Join(f.dir, "keys", file.Name()))
		if err != nil {
			return nil, err
		}
		key := &keys.Key{}
		if err := json.NewDecoder(s).Decode(key); err != nil {
			return nil, err
		}
		signingKeys = append(signingKeys, key)
	}
	return signingKeys, nil
}

func (f *fileSystemStore) SaveKey(role string, key *keys.Key) error {
	if err := f.createDirs(); err != nil {
		return err
	}
	data, err := json.Marshal(key)
	if err != nil {
		return err
	}
	if err := ioutil.WriteFile(filepath.Join(f.dir, "keys", role+"-"+key.ID+".json"), data, 0600); err != nil {
		return err
	}
	return nil
}

func (f *fileSystemStore) Clean() error {
	if err := os.RemoveAll(f.stagedDir()); err != nil {
		return err
	}
	return os.Mkdir(f.stagedDir(), 0755)
}
