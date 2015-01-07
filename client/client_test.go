package client

import (
	"bytes"
	"io"
	"testing"

	"github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/util"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ClientSuite struct {
	store  tuf.LocalStore
	repo   *tuf.Repo
	remote FakeRemoteStore
}

var _ = Suite(&ClientSuite{})

type FakeRemoteStore map[string][]byte

func (f FakeRemoteStore) Get(name string, size int64) (io.ReadCloser, error) {
	b, ok := f[name]
	if !ok {
		return nil, ErrNotFound
	}
	if size > 0 && int64(len(b)) != size {
		return nil, ErrWrongSize
	}
	return util.BytesReadCloser{bytes.NewReader(b)}, nil
}

var targetFiles = map[string][]byte{
	"foo.txt": []byte("foo"),
	"bar.txt": []byte("bar"),
	"baz.txt": []byte("baz"),
}

func (s *ClientSuite) SetUpTest(c *C) {
	s.store = tuf.MemoryStore(nil, targetFiles)

	// create a valid repo containing foo.txt
	var err error
	s.repo, err = tuf.NewRepo(s.store)
	c.Assert(err, IsNil)
	c.Assert(s.repo.GenKey("root"), IsNil)
	c.Assert(s.repo.GenKey("targets"), IsNil)
	c.Assert(s.repo.GenKey("snapshot"), IsNil)
	c.Assert(s.repo.GenKey("timestamp"), IsNil)
	c.Assert(s.repo.AddTarget("foo.txt", nil), IsNil)
	c.Assert(s.repo.Snapshot(tuf.CompressionTypeNone), IsNil)
	c.Assert(s.repo.Timestamp(), IsNil)

	// create a remote store containing valid repo files
	s.remote = make(FakeRemoteStore)
	s.syncRemote(c)
	for k, v := range targetFiles {
		s.remote["targets/"+k] = v
	}
}

func (s *ClientSuite) syncRemote(c *C) {
	meta, err := s.store.GetMeta()
	c.Assert(err, IsNil)
	for k, v := range meta {
		s.remote[k] = v
	}
}

func (s *ClientSuite) addRemoteTarget(c *C, name string) {
	c.Assert(s.repo.AddTarget(name, nil), IsNil)
	c.Assert(s.repo.Snapshot(tuf.CompressionTypeNone), IsNil)
	c.Assert(s.repo.Timestamp(), IsNil)
	s.syncRemote(c)
}

func (s *ClientSuite) rootKeys(c *C) []*data.Key {
	rootKeys, err := s.repo.RootKeys()
	c.Assert(err, IsNil)
	c.Assert(rootKeys, HasLen, 1)
	return rootKeys
}

func (s *ClientSuite) newClient(c *C) *Client {
	client := NewClient(MemoryLocalStore(), s.remote)
	c.Assert(client.Init(s.rootKeys(c)), IsNil)
	return client
}

func assertUpdatedFiles(c *C, files data.Files, names []string) {
	c.Assert(files, HasLen, len(names))
	for _, name := range names {
		target, ok := targetFiles[name]
		if !ok {
			c.Fatalf("unknown target %s", name)
		}
		meta, err := util.GenerateFileMeta(bytes.NewReader(target))
		c.Assert(err, IsNil)
		file, ok := files[name]
		if !ok {
			c.Fatalf("expected file update for %s", name)
		}
		c.Assert(util.FileMetaEqual(file, meta), Equals, true)
	}
}

func (s *ClientSuite) TestInit(c *C) {
	client := NewClient(MemoryLocalStore(), s.remote)

	// check Update() returns ErrNoRootKeys when uninitialized
	_, err := client.Update()
	c.Assert(err, Equals, ErrNoRootKeys)

	// check Update() does not return ErrNoRootKeys after initialization
	c.Assert(client.Init(s.rootKeys(c)), IsNil)
	_, err = client.Update()
	c.Assert(err, Not(Equals), ErrNoRootKeys)
}

func (s *ClientSuite) TestFirstUpdate(c *C) {
	files, err := s.newClient(c).Update()
	c.Assert(err, IsNil)
	c.Assert(files, HasLen, 1)
	assertUpdatedFiles(c, files, []string{"foo.txt"})
}

func (s *ClientSuite) TestMissingRemoteMetadata(c *C) {
	delete(s.remote, "targets.json")
	_, err := s.newClient(c).Update()
	c.Assert(err, Equals, ErrMissingRemoteMetadata{"targets.json"})
}

func (s *ClientSuite) TestNoChangeUpdate(c *C) {
	client := s.newClient(c)
	_, err := client.Update()
	c.Assert(err, IsNil)
	_, err = client.Update()
	c.Assert(err, Equals, ErrLatest)
}

func (s *ClientSuite) TestNewTargets(c *C) {
	client := s.newClient(c)
	files, err := client.Update()
	c.Assert(err, IsNil)
	assertUpdatedFiles(c, files, []string{"foo.txt"})

	s.addRemoteTarget(c, "bar.txt")
	s.addRemoteTarget(c, "baz.txt")

	files, err = client.Update()
	c.Assert(err, IsNil)
	assertUpdatedFiles(c, files, []string{"bar.txt", "baz.txt"})

	// Adding the same exact file should not lead to an update
	s.addRemoteTarget(c, "bar.txt")
	files, err = client.Update()
	c.Assert(err, IsNil)
	c.Assert(files, HasLen, 0)
}

// TODO: Implement these tests:
//
// * Test new timestamp with same snapshot
// * Test new root data (e.g. new targets keys)
// * Test locally expired metadata is ok
// * Test invalid timestamp / snapshot signature downloads root.json
// * Test invalid hash returns ErrChecksumFailed
