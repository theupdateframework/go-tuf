package client

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/util"
	"github.com/theupdateframework/go-tuf/verify"
)

func TestGetTargetMeta(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer func() { assert.Nil(t, closer()) }()
	_, err := c.Update()
	assert.Nil(t, err)

	f, err := c.getTargetFileMeta("f.txt")
	assert.Nil(t, err)
	hash := sha256.Sum256([]byte("Contents: f.txt"))
	assert.Equal(t, data.HexBytes(hash[:]), f.Hashes["sha256"])

	f, err = c.getTargetFileMeta("targets.txt")
	assert.Nil(t, err)
	hash = sha256.Sum256([]byte("Contents: targets.txt"))
	assert.Equal(t, data.HexBytes(hash[:]), f.Hashes["sha256"])
}

func TestMaxDelegations(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer func() { assert.Nil(t, closer()) }()
	_, err := c.Update()
	assert.Nil(t, err)
	c.MaxDelegations = 2
	_, err = c.getTargetFileMeta("c.txt")
	assert.Equal(t, ErrMaxDelegations{Target: "c.txt", MaxDelegations: 2, SnapshotVersion: 2}, err)
}

func TestMetaNotFound(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer func() { assert.Nil(t, closer()) }()
	_, err := c.Update()
	assert.Nil(t, err)
	_, err = c.getTargetFileMeta("unknown.txt")
	assert.Equal(t, ErrUnknownTarget{Name: "unknown.txt", SnapshotVersion: 2}, err)
}

type fakeRemote struct {
	getMeta   func(name string) (stream io.ReadCloser, size int64, err error)
	getTarget func(path string) (stream io.ReadCloser, size int64, err error)
}

func (f fakeRemote) GetMeta(name string) (stream io.ReadCloser, size int64, err error) {
	return f.getMeta(name)
}

func (f fakeRemote) GetTarget(name string) (stream io.ReadCloser, size int64, err error) {
	return f.getTarget(name)
}

func TestTargetsNotFound(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer func() { assert.Nil(t, closer()) }()
	_, err := c.Update()
	assert.Nil(t, err)

	previousRemote := c.remote
	newRemote := fakeRemote{
		getMeta: func(path string) (stream io.ReadCloser, size int64, err error) {
			if path == "1.c.json" {
				return nil, 0, ErrNotFound{}
			}
			return previousRemote.GetMeta(path)
		},
		getTarget: previousRemote.GetTarget,
	}
	c.remote = newRemote

	_, err = c.getTargetFileMeta("c.txt")
	assert.Equal(t, ErrMissingRemoteMetadata{Name: "c.json"}, err)
}

func TestUnverifiedTargets(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer closer()
	_, err := c.Update()
	assert.Nil(t, err)

	previousRemote := c.remote
	newRemote := fakeRemote{
		getMeta: func(path string) (stream io.ReadCloser, size int64, err error) {
			if path == "1.c.json" {
				// returns a snapshot that does not match
				return previousRemote.GetMeta("1.d.json")
			}
			return previousRemote.GetMeta(path)
		},
		getTarget: previousRemote.GetTarget,
	}
	c.remote = newRemote

	_, err = c.getTargetFileMeta("c.txt")
	assert.Equal(t, ErrDecodeFailed{File: "c.json", Err: verify.ErrRoleThreshold{Expected: 1, Actual: 0}}, err)
}

func TestPersistedMeta(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer closer()
	_, err := c.Update()
	assert.Nil(t, err)

	_, err = c.local.GetMeta()
	assert.Nil(t, err)

	type expectedTargets struct {
		name    string
		version int64
	}
	var persistedTests = []struct {
		file          string
		targets       []expectedTargets
		downloadError error
		targetError   error
		fileContent   string
	}{
		{
			file: "unknown",
			targets: []expectedTargets{
				{
					name:    "targets.json",
					version: 2,
				},
			},
			downloadError: ErrUnknownTarget{Name: "unknown", SnapshotVersion: 2},
			targetError:   ErrNotFound{File: "unknown"},
			fileContent:   "",
		},
		{
			file: "b.txt",
			targets: []expectedTargets{
				{
					name:    "targets.json",
					version: 2,
				},
				{
					name:    "a.json",
					version: 1,
				},
				{
					name:    "b.json",
					version: 1,
				},
			},
			downloadError: nil,
			targetError:   nil,
			fileContent:   "Contents: b.txt",
		},
		{
			file: "f.txt",
			targets: []expectedTargets{
				{
					name:    "targets.json",
					version: 2,
				},
				{
					name:    "a.json",
					version: 1,
				},
				{
					name:    "b.json",
					version: 1,
				},
				{
					name:    "c.json",
					version: 1,
				},
				{
					name:    "d.json",
					version: 1,
				},
				{
					name:    "e.json",
					version: 1,
				},
				{
					name:    "f.json",
					version: 1,
				},
			},
			downloadError: nil,
			targetError:   nil,
			fileContent:   "Contents: f.txt",
		},
	}

	for _, tt := range persistedTests {
		t.Run("search "+tt.file, func(t *testing.T) {
			var dest testDestination
			err = c.Download(tt.file, &dest)
			assert.Equal(t, tt.downloadError, err)
			assert.Equal(t, tt.fileContent, dest.String())

			target, err := c.Target(tt.file)
			assert.Equal(t, tt.targetError, err)
			if tt.targetError == nil {
				meta, err := util.GenerateTargetFileMeta(strings.NewReader(tt.fileContent), target.HashAlgorithms()...)
				assert.Nil(t, err)
				assert.Nil(t, util.TargetFileMetaEqual(target, meta))
			}

			p, err := c.local.GetMeta()
			assert.Nil(t, err)
			persisted := copyStore(p)
			persistedLocal := copyStore(c.localMeta)
			// trim non targets metas
			for _, notTargets := range []string{"root.json", "snapshot.json", "timestamp.json"} {
				delete(persisted, notTargets)
				delete(persistedLocal, notTargets)
			}
			for _, targets := range tt.targets {
				// Test local store
				storedVersion, err := versionOfStoredTargets(targets.name, persisted)
				assert.Equal(t, targets.version, storedVersion)
				assert.Nil(t, err)
				delete(persisted, targets.name)

				// Test localMeta
				storedVersion, err = versionOfStoredTargets(targets.name, persistedLocal)
				assert.Equal(t, targets.version, storedVersion)
				assert.Nil(t, err)
				delete(persistedLocal, targets.name)
			}
			assert.Empty(t, persisted)
			assert.Empty(t, persistedLocal)
		})
	}
}

func versionOfStoredTargets(name string, store map[string]json.RawMessage) (int64, error) {
	rawTargets, ok := store[name]
	if !ok {
		return 0, nil
	}
	s := &data.Signed{}
	if err := json.Unmarshal(rawTargets, s); err != nil {
		return 0, err
	}
	targets := &data.Targets{}
	if err := json.Unmarshal(s.Signed, targets); err != nil {
		return 0, err
	}
	return targets.Version, nil
}

func initTestDelegationClient(t *testing.T, dirPrefix string) (*Client, func() error) {
	serverDir := dirPrefix + "/server"
	initialStateDir := dirPrefix + "/client/metadata/current"
	l, err := net.Listen("tcp", "127.0.0.1:0")
	assert.Nil(t, err)
	addr := l.Addr().String()
	go http.Serve(l, http.FileServer(http.Dir(serverDir)))

	opts := &HTTPRemoteOptions{
		MetadataPath: "metadata",
		TargetsPath:  "targets",
	}
	remote, err := HTTPRemoteStore(fmt.Sprintf("http://%s/", addr), opts, nil)
	assert.Nil(t, err)

	c := NewClient(MemoryLocalStore(), remote)
	rawFile, err := os.ReadFile(initialStateDir + "/" + "root.json")
	assert.Nil(t, err)
	assert.Nil(t, c.Init(rawFile))
	files, err := os.ReadDir(initialStateDir)
	assert.Nil(t, err)

	// load local files
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		// ignoring consistent snapshot when loading initial state
		if len(strings.Split(name, ".")) == 1 && strings.HasSuffix(name, ".json") {
			rawFile, err := os.ReadFile(initialStateDir + "/" + name)
			assert.Nil(t, err)
			assert.Nil(t, c.local.SetMeta(name, rawFile))
		}
	}
	return c, l.Close
}

func copyStore(store map[string]json.RawMessage) map[string]json.RawMessage {
	new := make(map[string]json.RawMessage, len(store))
	for k, raw := range store {
		newRaw := make([]byte, len(raw))
		copy(newRaw, []byte(raw))
		new[k] = json.RawMessage(newRaw)
	}
	return new
}
