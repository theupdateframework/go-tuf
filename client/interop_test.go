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

	tuf "github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/util"
	"golang.org/x/crypto/ed25519"
	. "gopkg.in/check.v1"
)

type InteropSuite struct{}

var _ = Suite(&InteropSuite{})

func (InteropSuite) TestGoClientCompatibility(c *C) {
	// start file server
	cwd, err := os.Getwd()
	c.Assert(err, IsNil)
	testDataDir := filepath.Join(cwd, "testdata")
	addr, cleanup := startFileServer(c, testDataDir)
	defer cleanup()

	type dataKeys struct {
		Data []*data.Key `json:"data"`
	}

	versions := []string{
		"go-tuf-transition-M0",
		"go-tuf-transition-M1",
		"go-tuf-transition-M2",
		"go-tuf-transition-M3",
		"go-tuf-transition-M4",
	}

	for _, version := range versions {
		for _, consistentSnapshot := range []bool{false, true} {
			dir := fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot)
			local := MemoryLocalStore()

			init := false
			targets := map[string][]byte{}

			for _, step := range []string{"0", "1", "2", "3", "4", "5"} {
				dir := filepath.Join(dir, step)

				remote, err := HTTPRemoteStore(
					fmt.Sprintf("http://%s/%s/%s/repository", addr, version, dir),
					&HTTPRemoteOptions{MetadataPath: "", TargetsPath: "targets"},
					nil,
				)
				c.Assert(err, IsNil)

				client := NewClient(local, remote)

				// initiate a client with the root keys
				if !init {
					init = true
					f, err := os.Open(filepath.Join(testDataDir, version, dir, "keys", "root.json"))
					c.Assert(err, IsNil)
					keys := &dataKeys{}
					c.Assert(json.NewDecoder(f).Decode(keys), IsNil)

					for _, key := range keys.Data {
						c.Assert(key.Type, Equals, "ed25519")
						c.Assert(key.Value.Public, HasLen, ed25519.PublicKeySize)
					}
					c.Assert(client.Init(keys.Data, 1), IsNil)
				}

				// check update returns the correct updated targets
				files, err := client.Update()
				c.Assert(err, IsNil)
				c.Assert(files, HasLen, 1)

				name := step
				targets[name] = []byte(step)

				// FIXME(TUF-0.9) M0 and M1 contain leading
				// slashes in order to be backwards compatible
				// with go-tuf G0.
				var file data.TargetFileMeta
				var ok bool
				if version == "go-tuf-transition-M0" || version == "go-tuf-transition-M1" {
					file, ok = files["/"+name]
				} else {
					file, ok = files[name]
				}
				if !ok {
					c.Fatalf("expected updated targets to contain %s", name)
				}

				data := targets[name]
				meta, err := util.GenerateTargetFileMeta(bytes.NewReader(data), file.HashAlgorithms()...)
				c.Assert(err, IsNil)
				c.Assert(util.TargetFileMetaEqual(file, meta), IsNil)

				// download the files and check they have the correct content
				for name, data := range targets {
					for _, prefix := range []string{"", "/"} {
						var dest testDestination
						c.Assert(client.Download(prefix+name, &dest), IsNil)
						c.Assert(dest.deleted, Equals, false)
						c.Assert(dest.String(), Equals, string(data))
					}
				}
			}
		}
	}
}

func generateRepoFS(c *C, dir string, files map[string][]byte, consistentSnapshot bool) *tuf.Repo {
	repo, err := tuf.NewRepo(tuf.FileSystemStore(dir, nil))
	c.Assert(err, IsNil)
	if !consistentSnapshot {
		c.Assert(repo.Init(false), IsNil)
	}
	for _, role := range []string{"root", "snapshot", "targets", "timestamp"} {
		_, err := repo.GenKey(role)
		c.Assert(err, IsNil)
	}
	for file, data := range files {
		path := filepath.Join(dir, "staged", "targets", file)
		c.Assert(os.MkdirAll(filepath.Dir(path), 0755), IsNil)
		c.Assert(ioutil.WriteFile(path, data, 0644), IsNil)
		c.Assert(repo.AddTarget(file, nil), IsNil)
	}
	c.Assert(repo.Snapshot(tuf.CompressionTypeNone), IsNil)
	c.Assert(repo.Timestamp(), IsNil)
	c.Assert(repo.Commit(), IsNil)
	return repo
}

func startFileServer(c *C, dir string) (string, func() error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, IsNil)
	addr := l.Addr().String()
	go http.Serve(l, http.FileServer(http.Dir(dir)))
	return addr, l.Close
}
