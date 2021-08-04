package client

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

var (
	defaultPathPatterns = []string{"tmp", "*"}
	noMatchPathPatterns = []string{"vars", "null"}
)

func TestDelegationsIterator(t *testing.T) {
	var iteratorTests = []struct {
		testName    string
		roles       map[string][]data.DelegatedRole
		file        string
		resultOrder []string
		err         error
	}{
		{
			testName: "no termination",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns},
				},
				"c": {
					{Name: "d", Paths: defaultPathPatterns},
				},
				"e": {
					{Name: "f", Paths: defaultPathPatterns},
					{Name: "g", Paths: defaultPathPatterns},
				},
				"g": {
					{Name: "h", Paths: defaultPathPatterns},
					{Name: "i", Paths: defaultPathPatterns},
					{Name: "j", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
		},
		{
			testName: "terminated in b",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, Terminating: true},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns},
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c", "d"},
		},
		{
			testName: "path does not match b",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: noMatchPathPatterns},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "c", Paths: defaultPathPatterns},
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "e"},
		},
		{
			testName: "path does not match b - path prefixes",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", PathHashPrefixes: []string{"33472a4909"}},
					{Name: "c", PathHashPrefixes: []string{"34c85d1ee84f61f10d7dc633"}},
				},
				"c": {
					{Name: "d", PathHashPrefixes: []string{"8baf"}},
					{Name: "e", PathHashPrefixes: []string{"34c85d1ee84f61f10d7dc633472a49096ed87f8f764bd597831eac371f40ac39"}},
				},
			},
			file:        "/e/f/g.txt",
			resultOrder: []string{"targets", "c", "e"},
		},
		{
			testName: "err paths and pathHashPrefixes are set",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns, PathHashPrefixes: defaultPathPatterns},
				},
				"b": {},
			},
			file:        "",
			resultOrder: []string{"targets"},
			err:         data.ErrPathsAndPathHashesSet,
		},
		{
			testName: "cycle avoided 1",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "e", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "targets", Paths: defaultPathPatterns},
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "d", "e"},
		},
		{
			testName: "cycle avoided 2",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "targets", Paths: defaultPathPatterns},
					{Name: "b", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "targets", Paths: defaultPathPatterns},
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "c", Paths: defaultPathPatterns},
				},
				"c": {
					{Name: "c", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "c"},
		},
		{
			testName: "diamond delegation",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "b", Paths: defaultPathPatterns},
					{Name: "c", Paths: defaultPathPatterns},
				},
				"b": {
					{Name: "d", Paths: defaultPathPatterns},
				},
				"c": {
					{Name: "d", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "b", "d", "c"},
		},
		{
			testName: "simple cycle",
			roles: map[string][]data.DelegatedRole{
				"targets": {
					{Name: "a", Paths: defaultPathPatterns},
				},
				"a": {
					{Name: "a", Paths: defaultPathPatterns},
				},
			},
			file:        "",
			resultOrder: []string{"targets", "a"},
		},
	}

	for _, tt := range iteratorTests {
		t.Run(tt.testName, func(t *testing.T) {
			d := newDelegationsIterator(tt.file)
			var iterationOrder []string
			for {
				r, ok := d.next()
				if !ok {
					break
				}
				iterationOrder = append(iterationOrder, r.delegatee.Name)
				delegations, ok := tt.roles[r.delegatee.Name]
				if !ok {
					continue
				}
				err := d.add(delegations, r.delegatee.Name, verify.DelegationsVerifier{})
				assert.Equal(t, tt.err, err)
			}
			assert.Equal(t, tt.resultOrder, iterationOrder)
		})
	}
}

func TestGetTargetMeta(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer func() { assert.Nil(t, closer()) }()
	_, err := c.Update()
	assert.Nil(t, err)

	f, err := c.getTargetFileMeta("f.txt")
	assert.Nil(t, err)
	assert.Equal(t, int64(15), f.Length)
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
		version int
	}
	var persistedTests = []struct {
		file          string
		targets       []expectedTargets
		downloadError error
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
			fileContent:   "Contents: f.txt",
		},
	}

	for _, tt := range persistedTests {
		t.Run("search "+tt.file, func(t *testing.T) {
			var dest testDestination
			err = c.Download(tt.file, &dest)
			assert.Equal(t, tt.downloadError, err)
			assert.Equal(t, tt.fileContent, dest.String())

			p, err := c.local.GetMeta()
			assert.Nil(t, err)
			persisted := copyStore(p)
			// trim non targets metas
			for _, notTargets := range []string{"root.json", "snapshot.json", "timestamp.json"} {
				delete(persisted, notTargets)
			}
			for _, targets := range tt.targets {
				storedVersion, err := versionOfStoredTargets(targets.name, persisted)
				assert.Equal(t, targets.version, storedVersion)
				assert.Nil(t, err)
				delete(persisted, targets.name)
			}
			assert.Empty(t, persisted)
		})
	}
}

func versionOfStoredTargets(name string, store map[string]json.RawMessage) (int, error) {
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

	c := NewClient(MemoryLocalStore(), remote)
	rawFile, err := ioutil.ReadFile(initialStateDir + "/" + "root.json")
	assert.Nil(t, err)
	s := &data.Signed{}
	root := &data.Root{}
	assert.Nil(t, json.Unmarshal(rawFile, s))
	assert.Nil(t, json.Unmarshal(s.Signed, root))
	var keys []*data.Key
	for _, sig := range s.Signatures {
		k, ok := root.Keys[sig.KeyID]
		if ok {
			keys = append(keys, k)
		}
	}

	assert.Nil(t, c.Init(keys, 1))
	files, err := ioutil.ReadDir(initialStateDir)
	assert.Nil(t, err)

	// load local files
	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		// ignoring consistent snapshot when loading initial state
		if len(strings.Split(name, ".")) == 1 && strings.HasSuffix(name, ".json") {
			rawFile, err := ioutil.ReadFile(initialStateDir + "/" + name)
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
