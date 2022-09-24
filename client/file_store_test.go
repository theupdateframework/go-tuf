package client

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const targetsDir = "targets"

func TestCreates(t *testing.T) {
	tmpDir := t.TempDir()
	defer os.RemoveAll(tmpDir)
	dir := filepath.Join(tmpDir, "repository")
	os.Mkdir(dir, os.ModePerm)
	os.Mkdir(filepath.Join(dir, "targets"), os.ModePerm)
	os.Create(filepath.Join(dir, "targets-that-isfile"))

	tests := []struct {
		name    string
		fsys    fs.FS
		td      string
		wantErr string
	}{{
		name:    "nil, error",
		wantErr: "nil fs.FS",
	}, {
		name:    "missing targets directory",
		fsys:    os.DirFS(dir),
		td:      "targets-not-there",
		wantErr: "failed to open targets directory targets-not-there",
	}, {
		name:    "targets directory is not a file",
		fsys:    os.DirFS(dir),
		td:      "targets-that-isfile",
		wantErr: "targets directory not a directory targets-that-isfile",
	}, {
		name: "works, explicit targets",
		fsys: os.DirFS(dir),
		td:   "targets",
	}, {
		name: "works, explicit targets",
		fsys: os.DirFS(dir),
		td:   "targets",
	}}

	for _, tc := range tests {
		_, err := NewFileRemoteStore(tc.fsys, tc.td)
		if tc.wantErr != "" && err == nil {
			t.Errorf("%q wanted error %s, got none", tc.name, tc.wantErr)
		} else if tc.wantErr == "" && err != nil {
			t.Errorf("%q did not want error, got: %v", tc.name, err)
		} else if err != nil && !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("%q wanted error %s but got: %s", tc.name, tc.wantErr, err)
		}
	}
}

func TestBasicOps(t *testing.T) {
	metas := map[string][]byte{
		"root.json":     []byte("root"),
		"snapshot.json": []byte("snapshot"),
		"timestamp":     []byte("timestamp"),
	}

	fsys, dir, err := newTestFileStoreFS()
	if err != nil {
		t.Fatalf("Failed to create test FileStore")
	}
	defer os.RemoveAll(dir)

	// Add targets and metas and check them.
	for k, v := range targetFiles {
		if err := fsys.addTarget(k, v); err != nil {
			t.Errorf("failed to add target %s: %v", k, err)
		}
		rc, size, err := fsys.GetTarget(k)
		if err != nil {
			t.Errorf("failed to GetTarget %s: %v", k, err)
		}
		if size != int64(len(v)) {
			t.Errorf("unexpected size returned for GetTarget: %s want %d got %d", k, len(v), size)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Errorf("failed to ReadAll returned ReacCloser %s: %v", k, err)
		}
		if !bytes.Equal(v, got) {
			t.Errorf("Read unexpected bytes, want: %s got: %s", string(k), string(got))
		}
	}
	for k, v := range metas {
		if err := fsys.addMeta(k, v); err != nil {
			t.Errorf("failed to add meta %s %v", k, err)
		}
		rc, size, err := fsys.GetMeta(k)
		if err != nil {
			t.Errorf("failed to GetMeta %s: %v", k, err)
		}
		if size != int64(len(v)) {
			t.Errorf("unexpected size returned for GetMeta: %s want %d got %d", k, len(v), size)
		}
		got, err := io.ReadAll(rc)
		if err != nil {
			t.Errorf("failed to ReadAll returned ReacCloser %s: %v", k, err)
		}
		if !bytes.Equal(v, got) {
			t.Errorf("Read unexpected bytes, want: %s got: %s", string(k), string(got))
		}
	}
}

// Test helper methods
func (f *FileRemoteStore) addMeta(name string, data []byte) error {
	return os.WriteFile(filepath.Join(f.testDir, name), data, os.ModePerm)
}

func (f *FileRemoteStore) addTarget(name string, data []byte) error {
	fname := filepath.Join(f.testDir, targetsDir, name)
	err := os.WriteFile(fname, data, os.ModePerm)
	return err
}

func (f *FileRemoteStore) deleteMeta(name string) error {
	return os.Remove(filepath.Join(f.testDir, name))
}

func (f *FileRemoteStore) deleteTarget(name string) error {
	return os.Remove(filepath.Join(f.testDir, targetsDir, name))
}

func newTestFileStoreFS() (*FileRemoteStore, string, error) {
	tmpDir := os.TempDir()
	tufDir := filepath.Join(tmpDir, "tuf-file-store-test")
	// Clean it in case there is cruft left around
	os.RemoveAll(tufDir)
	os.Mkdir(tufDir, os.ModePerm)
	os.Mkdir(filepath.Join(tufDir, targetsDir), os.ModePerm)
	fs, err := NewFileRemoteStore(os.DirFS(tufDir), targetsDir)
	fs.testDir = tufDir
	return fs, tufDir, err
}