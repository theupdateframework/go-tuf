package client

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/verify"
)

var (
	defaultPaths     = []string{"tmp", "*"}
	notMatchingPaths = []string{"vars", "null"}
)

func TestDelegationsIterator(t *testing.T) {
	var iteratorTests = []struct {
		testName       string
		roles          map[string][]data.DelegatedRole
		rootDelegation data.DelegatedRole
		file           string
		resultOrder    []string
	}{
		{
			"no termination",
			map[string][]data.DelegatedRole{
				"a": []data.DelegatedRole{{Name: "b", Paths: defaultPaths}, {Name: "e", Paths: defaultPaths}},
				"b": []data.DelegatedRole{{Name: "c", Paths: defaultPaths}, {Name: "d", Paths: defaultPaths}},
			},
			data.DelegatedRole{Name: "a", Paths: defaultPaths},
			"",
			[]string{"a", "b", "c", "d", "e"},
		},
		{
			"terminated in b",
			map[string][]data.DelegatedRole{
				"a": []data.DelegatedRole{{Name: "b", Paths: defaultPaths, Terminating: true}, {Name: "e", Paths: defaultPaths}},
				"b": []data.DelegatedRole{{Name: "c", Paths: defaultPaths}, {Name: "d", Paths: defaultPaths}},
			},
			data.DelegatedRole{Name: "a", Paths: defaultPaths},
			"",
			[]string{"a", "b", "c", "d"},
		},
		{
			"path does not match b",
			map[string][]data.DelegatedRole{
				"a": []data.DelegatedRole{{Name: "b", Paths: notMatchingPaths}, {Name: "e", Paths: defaultPaths}},
				"b": []data.DelegatedRole{{Name: "c", Paths: defaultPaths}, {Name: "d", Paths: defaultPaths}},
			},
			data.DelegatedRole{Name: "a", Paths: defaultPaths},
			"",
			[]string{"a", "e"},
		},
		{
			"cycle avoided",
			map[string][]data.DelegatedRole{
				"a": []data.DelegatedRole{{Name: "b", Paths: defaultPaths}, {Name: "e", Paths: defaultPaths}},
				"b": []data.DelegatedRole{{Name: "a", Paths: defaultPaths}, {Name: "d", Paths: defaultPaths}},
			},
			data.DelegatedRole{Name: "a", Paths: defaultPaths},
			"",
			[]string{"a", "b", "a", "e", "d"},
		},
	}

	for _, tt := range iteratorTests {
		t.Run(tt.testName, func(t *testing.T) {
			d := newDelegationsIterator(tt.rootDelegation, "root", tt.file)
			var iterationOrder []string
			for {
				r, ok := d.next()
				if !ok {
					break
				}
				iterationOrder = append(iterationOrder, r.child.Name)
				delegations, ok := tt.roles[r.child.Name]
				if !ok {
					continue
				}
				d.add(delegations, r.child.Name)
			}
			assert.Equal(t, len(iterationOrder), len(tt.resultOrder))
			for i, role := range iterationOrder {
				assert.Equal(t, role, tt.resultOrder[i])
			}
		})
	}
}

func TestGetTargetMeta(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer closer()
	_, err := c.Update()
	assert.Nil(t, err)

	f, err := c.getTargetFileMeta("f.txt")
	assert.Nil(t, err)
	assert.Equal(t, f.Length, int64(15))
}

func TestMaxDelegations(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer closer()
	_, err := c.Update()
	assert.Nil(t, err)
	c.MaxDelegations = 2
	_, err = c.getTargetFileMeta("c.txt")
	assert.Equal(t, err, ErrMaxDelegations{File: "c.txt", MaxDelegations: 2, SnapshotVersion: 2})
}

func TestMetaNotFound(t *testing.T) {
	verify.IsExpired = func(t time.Time) bool { return false }
	c, closer := initTestDelegationClient(t, "testdata/php-tuf-fixtures/TUFTestFixture3LevelDelegation")
	defer closer()
	_, err := c.Update()
	assert.Nil(t, err)
	_, err = c.getTargetFileMeta("unknown.txt")
	assert.Equal(t, err, ErrUnknownTarget{Name: "unknown.txt", SnapshotVersion: 2})
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
			"unknown",
			[]expectedTargets{
				{
					"targets.json",
					2,
				},
			},
			ErrUnknownTarget{Name: "unknown", SnapshotVersion: 2},
			"",
		},
		{
			"b.txt",
			[]expectedTargets{
				{
					"targets.json",
					2,
				},
				{
					"a.json",
					1,
				},
				{
					"b.json",
					1,
				},
			},
			nil,
			"Contents: b.txt",
		},
		{
			"f.txt",
			[]expectedTargets{
				{
					"targets.json",
					2,
				},
				{
					"a.json",
					1,
				},
				{
					"b.json",
					1,
				},
				{
					"c.json",
					1,
				},
				{
					"d.json",
					1,
				},
				{
					"e.json",
					1,
				},
				{
					"f.json",
					1,
				},
			},
			nil,
			"Contents: f.txt",
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
				assert.Equal(t, storedVersion, targets.version)
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
	rawFile, err := os.ReadFile(initialStateDir + "/" + "root.json")
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
