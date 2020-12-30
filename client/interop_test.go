package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path/filepath"

	"github.com/theupdateframework/go-tuf/data"
	"github.com/theupdateframework/go-tuf/util"
	. "gopkg.in/check.v1"

	goTufGenerator "github.com/theupdateframework/go-tuf/client/testdata/go-tuf/generator"
)

type InteropSuite struct{}

var _ = Suite(&InteropSuite{})

func (InteropSuite) TestGoClientIdentityConsistentSnapshotFalse(c *C) {
	checkGoIdentity(c, false)
}

func (InteropSuite) TestGoClientIdentityConsistentSnapshotTrue(c *C) {
	checkGoIdentity(c, true)
}

func checkGoIdentity(c *C, consistentSnapshot bool) {
	cwd, err := os.Getwd()
	c.Assert(err, IsNil)
	testDataDir := filepath.Join(cwd, "testdata")

	tempDir, err := ioutil.TempDir("", "")
	c.Assert(err, IsNil)
	defer os.RemoveAll(tempDir)

	// Generate the metadata and compute hashes for all the files.
	goTufGenerator.Generate(tempDir, filepath.Join(testDataDir, "keys.json"), consistentSnapshot)
	hashes := computeHashes(c, tempDir)

	snapshotDir := filepath.Join(testDataDir, "go-tuf", fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot))
	snapshotHashes := computeHashes(c, snapshotDir)

	c.Assert(hashes, DeepEquals, snapshotHashes, Commentf("metadata out of date, regenerate by running client/testdata/go-tuf/regenerate-metadata.sh"))
}

func computeHashes(c *C, dir string) map[string]string {
	hashes := make(map[string]string)

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}

		bytes, err := ioutil.ReadFile(path)
		if err != nil {
			return err
		}

		path, err = filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		hashes[path] = string(bytes)

		return nil
	})
	c.Assert(err, IsNil)

	return hashes
}

func (InteropSuite) TestGoClientCompatibility(c *C) {
	names := []string{
		"go-tuf",
		"go-tuf-transition-M3",
		"go-tuf-transition-M4",
	}
	options := &HTTPRemoteOptions{MetadataPath: "", TargetsPath: "targets"}

	for _, name := range names {
		for _, consistentSnapshot := range []bool{false, true} {
			t := newTestCase(c, name, consistentSnapshot, options)
			t.run(c)
		}
	}
}

type testCase struct {
	name               string
	consistentSnapshot bool
	options            *HTTPRemoteOptions
	local              LocalStore
	targets            map[string][]byte
	testDir            string
	testSteps          []string
}

func newTestCase(c *C, name string, consistentSnapshot bool, options *HTTPRemoteOptions) testCase {
	cwd, err := os.Getwd()
	c.Assert(err, IsNil)
	testDir := filepath.Join(cwd, "testdata", name, fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot))

	dirEntries, err := ioutil.ReadDir(testDir)
	c.Assert(err, IsNil)
	c.Assert(dirEntries, Not(HasLen), 0)

	testSteps := []string{}
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			testSteps = append(testSteps, dirEntry.Name())
		}
	}

	return testCase{
		name:               name,
		consistentSnapshot: consistentSnapshot,
		options:            options,
		local:              MemoryLocalStore(),
		targets:            make(map[string][]byte),
		testDir:            testDir,
		testSteps:          testSteps,
	}
}

func (t *testCase) run(c *C) {
	c.Logf("test case: %s consistent-snapshot: %t", t.name, t.consistentSnapshot)

	init := true
	for _, stepName := range t.testSteps {
		t.runStep(c, stepName, init)
		init = false
	}
}

func (t *testCase) runStep(c *C, stepName string, init bool) {
	c.Logf("step: %s", stepName)

	addr, cleanup := startFileServer(c, t.testDir)
	defer cleanup()

	remote, err := HTTPRemoteStore(fmt.Sprintf("http://%s/%s/repository", addr, stepName), t.options, nil)
	c.Assert(err, IsNil)

	client := NewClient(t.local, remote)

	// initiate a client with the root keys
	if init {
		keys := getKeys(c, remote)
		c.Assert(client.Init(keys, 1), IsNil)
	}

	// check update returns the correct updated targets
	files, err := client.Update()
	c.Assert(err, IsNil)
	c.Assert(files, HasLen, 1)

	targetName := stepName
	t.targets[targetName] = []byte(targetName)

	file, ok := files[targetName]
	if !ok {
		c.Fatalf("expected updated targets to contain %s", targetName)
	}

	data := t.targets[targetName]
	meta, err := util.GenerateTargetFileMeta(bytes.NewReader(data), file.HashAlgorithms()...)
	c.Assert(err, IsNil)
	c.Assert(util.TargetFileMetaEqual(file, meta), IsNil)

	c.Log(t.targets)
	// download the files and check they have the correct content
	for _, prefix := range []string{"", "/"} {
		var dest testDestination
		c.Assert(client.Download(prefix+targetName, &dest), IsNil)
		c.Assert(dest.deleted, Equals, false)
		c.Assert(dest.String(), Equals, string(data))
	}
}

func startFileServer(c *C, dir string) (string, func() error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, IsNil)
	addr := l.Addr().String()
	go http.Serve(l, http.FileServer(http.Dir(dir)))
	return addr, l.Close
}

func getKeys(c *C, remote RemoteStore) []*data.Key {
	r, _, err := remote.GetMeta("root.json")
	c.Assert(err, IsNil)

	type SignedRoot struct {
		Signed data.Root
	}
	root := &SignedRoot{}
	err = json.NewDecoder(r).Decode(&root)
	c.Assert(err, IsNil)

	rootRole, exists := root.Signed.Roles["root"]
	c.Assert(exists, Equals, true)

	rootKeys := []*data.Key{}

	for _, keyID := range rootRole.KeyIDs {
		key, exists := root.Signed.Keys[keyID]
		c.Assert(exists, Equals, true)

		rootKeys = append(rootKeys, key)
	}

	c.Assert(rootKeys, Not(HasLen), 0)

	return rootKeys
}
