package client

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/agl/ed25519"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/util"
	. "gopkg.in/check.v1"
)

type InteropSuite struct{}

var _ = Suite(&InteropSuite{})

func (InteropSuite) TestGoClientPythonGenerated(c *C) {
	// populate the remote store with the Python files
	remote := make(FakeRemoteStore)
	repoDir := filepath.Join("testdata", "repository")
	for _, file := range []string{"root.json", "snapshot.json", "targets.json", "timestamp.json"} {
		b, err := ioutil.ReadFile(filepath.Join(repoDir, "metadata", file))
		c.Assert(err, IsNil)
		remote[file] = newFakeFile(b)
	}
	targets := make(map[string][]byte)
	for _, name := range []string{"/file1.txt", "/dir/file2.txt"} {
		b, err := ioutil.ReadFile(filepath.Join(repoDir, "targets", name))
		c.Assert(err, IsNil)
		targets[name] = b
		remote["targets"+name] = newFakeFile(b)
	}

	// initiate a client with the root keys
	f, err := os.Open(filepath.Join("testdata", "keystore", "root_key.pub"))
	c.Assert(err, IsNil)
	key := &data.Key{}
	c.Assert(json.NewDecoder(f).Decode(key), IsNil)
	c.Assert(key.Type, Equals, "ed25519")
	c.Assert(key.Value.Public, HasLen, ed25519.PublicKeySize)
	client := NewClient(MemoryLocalStore(), remote)
	c.Assert(client.Init([]*data.Key{key}, 1), IsNil)

	// check update returns the correct updated targets
	files, err := client.Update()
	c.Assert(err, IsNil)
	c.Assert(files, HasLen, len(targets))
	for name, b := range targets {
		file, ok := files[name]
		if !ok {
			c.Fatalf("expected updated targets to contain %s", name)
		}
		meta, err := util.GenerateFileMeta(bytes.NewReader(b), file.HashAlgorithms()...)
		c.Assert(err, IsNil)
		c.Assert(util.FileMetaEqual(file, meta), IsNil)
	}

	// download the files and check they have the correct content
	for name := range targets {
		var dest testDestination
		c.Assert(client.Download(name, &dest), IsNil)
		c.Assert(dest.deleted, Equals, false)
		c.Assert(dest.String(), Equals, filepath.Base(name))
	}
}
