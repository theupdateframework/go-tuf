package client

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const targetsDir = "targets"

func TestCreates(t *testing.T) {
	runningWindows := false
	if runtime.GOOS == "windows" {
		runningWindows = true
	}
	tmpDir := t.TempDir()
	defer os.RemoveAll(tmpDir)
	dir := filepath.Join(tmpDir, "repository")
	os.Mkdir(dir, os.ModePerm)
	os.Mkdir(filepath.Join(dir, "targets"), os.ModePerm)
	if !runningWindows {
		targetDirThatIsFile := filepath.Join(dir, "targets-that-isfile")
		f, err := os.Create(targetDirThatIsFile)
		if err != nil {
			t.Fatalf("failed to create file: %s: %v", targetDirThatIsFile, err)
		}
		defer f.Close()
	}
	t.Cleanup(func() { rmrf(dir, t.Logf) })
	t.Cleanup(func() { rmrf(tmpDir, t.Logf) })

	tests := []struct {
		name              string
		fsys              fs.FS
		td                string
		wantErr           string
		doNotRunOnWindows bool
	}{{
		name:    "nil, error",
		wantErr: "nil fs.FS",
	}, {
		name:    "missing targets directory",
		fsys:    os.DirFS(dir),
		td:      "targets-not-there",
		wantErr: "failed to open targets directory targets-not-there",
	}, {
		name:              "targets directory is not a file",
		fsys:              os.DirFS(dir),
		td:                "targets-that-isfile",
		wantErr:           "targets directory not a directory targets-that-isfile",
		doNotRunOnWindows: true,
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
		if tc.doNotRunOnWindows {
			t.Skip("Can't figure out how to make this work on windows")
		}
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
	t.Cleanup(func() { rmrf(dir, t.Logf) })
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

// goes through a dir and removes everything. This is to work around:
// https://github.com/golang/go/issues/51442
func rmrf(dir string, logger func(string, ...interface{})) {
	if dir == "" {
		logger("cowardly refusing to remove a not fully specified fir")
		return
	}
	logger("Removing %s", dir)
	d, err := os.Open(dir)
	if err != nil {
		logger("Failed to open %s: %v", dir, err)
		return
	}
	defer d.Close()
	// -1 means give me everything, we don't have that many entries, so
	// fine here.
	names, err := d.Readdirnames(-1)
	if err != nil {
		logger("Failed to ReaddirNames %s: %v", dir, err)
		return
	}
	for _, name := range names {
		toRemove := filepath.Join(dir, name)
		err = os.RemoveAll(toRemove)
		if err != nil {
			logger("Failed to RemoveAll %s: %v", toRemove, err)
			// Do not want to fail here, just keep doing the best we can
		}
	}
}
