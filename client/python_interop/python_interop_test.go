package client

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	tuf "github.com/theupdateframework/go-tuf"
	client "github.com/theupdateframework/go-tuf/client"
	"github.com/theupdateframework/go-tuf/util"
	. "gopkg.in/check.v1"
)

type InteropSuite struct{}

var _ = Suite(&InteropSuite{})

var pythonTargets = map[string][]byte{
	"file1.txt":     []byte("file1.txt"),
	"dir/file2.txt": []byte("file2.txt"),
}

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type testDestination struct {
	bytes.Buffer
	deleted bool
}

func (t *testDestination) Delete() error {
	t.deleted = true
	return nil
}

func (InteropSuite) TestGoClientPythonGenerated(c *C) {
	// start file server
	cwd, err := os.Getwd()
	c.Assert(err, IsNil)
	testDataDir := filepath.Join(cwd, "testdata", "python-tuf-v2.0.0")
	addr, cleanup := startFileServer(c, testDataDir)
	defer cleanup()

	for _, dir := range []string{"without-consistent-snapshot", "with-consistent-snapshot"} {
		remote, err := client.HTTPRemoteStore(
			fmt.Sprintf("http://%s/%s/repository", addr, dir),
			&client.HTTPRemoteOptions{MetadataPath: "metadata", TargetsPath: "targets"},
			nil,
		)
		c.Assert(err, IsNil)

		// initiate a client with the root metadata
		client := client.NewClient(client.MemoryLocalStore(), remote)
		rootJSON, err := os.ReadFile(filepath.Join(testDataDir, dir, "repository", "metadata", "1.root.json"))
		c.Assert(err, IsNil)
		c.Assert(client.Init(rootJSON), IsNil)

		// check update returns the correct updated targets
		files, err := client.Update()
		c.Assert(err, IsNil)
		c.Assert(files, HasLen, len(pythonTargets))
		for name, data := range pythonTargets {
			file, ok := files[name]
			if !ok {
				c.Fatalf("expected updated targets to contain %s", name)
			}
			meta, err := util.GenerateTargetFileMeta(bytes.NewReader(data), file.HashAlgorithms()...)
			c.Assert(err, IsNil)
			c.Assert(util.TargetFileMetaEqual(file, meta), IsNil)
		}

		// download the files and check they have the correct content
		for name, data := range pythonTargets {
			var dest testDestination
			c.Assert(client.Download(name, &dest), IsNil)
			c.Assert(dest.deleted, Equals, false)
			c.Assert(dest.String(), Equals, string(data))
		}
	}
}

func generateRepoFS(c *C, dir string, files map[string][]byte,
	consistentSnapshot bool) *tuf.Repo {
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
		c.Assert(os.WriteFile(path, data, 0644), IsNil)
		c.Assert(repo.AddTarget(file, nil), IsNil)
	}
	c.Assert(repo.Snapshot(), IsNil)
	c.Assert(repo.Timestamp(), IsNil)
	c.Assert(repo.Commit(), IsNil)
	return repo
}

func refreshRepo(c *C, repo *tuf.Repo) {
	c.Assert(repo.Snapshot(), IsNil)
	c.Assert(repo.Timestamp(), IsNil)
	c.Assert(repo.Commit(), IsNil)
}

func (InteropSuite) TestPythonClientGoGenerated(c *C) {
	// clone the Python client if necessary
	cwd, err := os.Getwd()
	c.Assert(err, IsNil)

	files := map[string][]byte{
		"foo.txt":     []byte("foo"),
		"bar/baz.txt": []byte("baz"),
	}

	for _, consistentSnapshot := range []bool{false, true} {
		// generate repository
		tmp := c.MkDir()
		// start file server
		addr, cleanup := startFileServer(c, tmp)
		defer cleanup()
		name := fmt.Sprintf("consistent-snapshot-%t", consistentSnapshot)
		dir := filepath.Join(tmp, name)
		generateRepoFS(c, dir, files, consistentSnapshot)

		// create initial files for Python client
		clientDir := filepath.Join(dir, "client")
		currDir := filepath.Join(clientDir, "tufrepo", "metadata", "current")
		prevDir := filepath.Join(clientDir, "tufrepo", "metadata", "previous")
		c.Assert(os.MkdirAll(currDir, 0755), IsNil)
		c.Assert(os.MkdirAll(prevDir, 0755), IsNil)
		rootJSON, err := os.ReadFile(filepath.Join(dir, "repository", "1.root.json"))
		c.Assert(err, IsNil)
		c.Assert(os.WriteFile(filepath.Join(currDir, "root.json"), rootJSON, 0644), IsNil)

		args := []string{
			filepath.Join(cwd, "testdata", "python-tuf-v2.0.0", "client.py"),
			"--repo=http://" + addr + "/" + name,
		}
		for path := range files {
			args = append(args, path)
		}

		// run Python client update
		cmd := exec.Command("python", args...)
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		c.Assert(cmd.Run(), IsNil)

		// check the target files got downloaded
		for path, expected := range files {
			actual, err := os.ReadFile(filepath.Join(clientDir, "tuftargets", url.QueryEscape(path)))
			c.Assert(err, IsNil)
			c.Assert(actual, DeepEquals, expected)
		}
	}
}

// This is a regression test for issue
// https://github.com/theupdateframework/go-tuf/issues/402
func (InteropSuite) TestPythonClientGoGeneratedNullDelegations(c *C) {
	// clone the Python client if necessary
	cwd, err := os.Getwd()
	c.Assert(err, IsNil)

	files := map[string][]byte{
		"foo.txt":     []byte("foo"),
		"bar/baz.txt": []byte("baz"),
	}

	for _, consistentSnapshot := range []bool{false, true} {
		// generate repository
		tmp := c.MkDir()
		// start file server
		addr, cleanup := startFileServer(c, tmp)
		defer cleanup()
		name := fmt.Sprintf("consistent-snapshot-delegations-%t", consistentSnapshot)
		dir := filepath.Join(tmp, name)
		repo := generateRepoFS(c, dir, files, consistentSnapshot)
		// "Reset" top-level targets delegations and re-sign
		c.Assert(repo.ResetTargetsDelegations("targets"), IsNil)
		refreshRepo(c, repo)

		// create initial files for Python client
		clientDir := filepath.Join(dir, "client")
		currDir := filepath.Join(clientDir, "tufrepo", "metadata", "current")
		prevDir := filepath.Join(clientDir, "tufrepo", "metadata", "previous")
		c.Assert(os.MkdirAll(currDir, 0755), IsNil)
		c.Assert(os.MkdirAll(prevDir, 0755), IsNil)
		rootJSON, err := os.ReadFile(filepath.Join(dir, "repository", "1.root.json"))
		c.Assert(err, IsNil)
		c.Assert(os.WriteFile(filepath.Join(currDir, "root.json"), rootJSON, 0644), IsNil)

		args := []string{
			filepath.Join(cwd, "testdata", "python-tuf-v2.0.0", "client.py"),
			"--repo=http://" + addr + "/" + name,
		}
		for path := range files {
			args = append(args, path)
		}

		// run Python client update
		cmd := exec.Command("python", args...)
		cmd.Dir = clientDir
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		c.Assert(cmd.Run(), IsNil)

		// check the target files got downloaded
		for path, expected := range files {
			actual, err := os.ReadFile(filepath.Join(clientDir, "tuftargets", url.QueryEscape(path)))
			c.Assert(err, IsNil)
			c.Assert(actual, DeepEquals, expected)
		}
	}
}

func startFileServer(c *C, dir string) (string, func() error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	c.Assert(err, IsNil)
	addr := l.Addr().String()
	go http.Serve(l, http.FileServer(http.Dir(dir)))
	return addr, l.Close
}
