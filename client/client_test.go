package client

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/flynn/go-tuf"
	"github.com/flynn/go-tuf/data"
	"github.com/flynn/go-tuf/keys"
	"github.com/flynn/go-tuf/signed"
	"github.com/flynn/go-tuf/util"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ClientSuite struct {
	store  tuf.LocalStore
	repo   *tuf.Repo
	local  LocalStore
	remote FakeRemoteStore
}

var _ = Suite(&ClientSuite{})

type FakeRemoteStore map[string]*fakeFile

func (f FakeRemoteStore) Get(path string) (io.ReadCloser, int64, error) {
	file, ok := f[path]
	if !ok {
		return nil, 0, ErrNotFound{strings.TrimPrefix(path, "targets/")}
	}
	return file, file.size, nil
}

func newFakeFile(b []byte) *fakeFile {
	return &fakeFile{buf: bytes.NewReader(b), size: int64(len(b))}
}

type fakeFile struct {
	buf       *bytes.Reader
	bytesRead int
	size      int64
}

func (f *fakeFile) Read(p []byte) (int, error) {
	n, err := f.buf.Read(p)
	f.bytesRead += n
	return n, err
}

func (f *fakeFile) Close() error {
	f.buf.Seek(0, os.SEEK_SET)
	return nil
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
		s.remote["targets/"+k] = newFakeFile(v)
	}
}

func (s *ClientSuite) syncLocal(c *C) {
	meta, err := s.store.GetMeta()
	c.Assert(err, IsNil)
	for k, v := range meta {
		c.Assert(s.local.SetMeta(k, v), IsNil)
	}
}

func (s *ClientSuite) syncRemote(c *C) {
	meta, err := s.store.GetMeta()
	c.Assert(err, IsNil)
	for k, v := range meta {
		s.remote[k] = newFakeFile(v)
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
	s.local = MemoryLocalStore()
	client := NewClient(s.local, s.remote)
	c.Assert(client.Init(s.rootKeys(c), 1), IsNil)
	return client
}

func (s *ClientSuite) updatedClient(c *C) *Client {
	client := s.newClient(c)
	_, err := client.Update()
	c.Assert(err, IsNil)
	return client
}

func assertFiles(c *C, files data.Files, names []string) {
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
			c.Fatalf("expected files to contain %s", name)
		}
		c.Assert(util.FileMetaEqual(file, meta), IsNil)
	}
}

func (s *ClientSuite) TestInitRootTooLarge(c *C) {
	client := NewClient(MemoryLocalStore(), s.remote)
	s.remote["root.json"] = newFakeFile(make([]byte, maxMetaSize+1))
	c.Assert(client.Init(s.rootKeys(c), 0), Equals, ErrMetaTooLarge{"root.json", maxMetaSize + 1})
}

func (s *ClientSuite) TestInitRootExpired(c *C) {
	duration := 100 * time.Millisecond
	s.repo.GenKeyWithExpires("targets", time.Now().Add(duration))
	s.syncRemote(c)
	time.Sleep(duration)
	client := NewClient(MemoryLocalStore(), s.remote)
	c.Assert(client.Init(s.rootKeys(c), 1), Equals, ErrExpiredMeta{"root.json"})
}

func (s *ClientSuite) TestInit(c *C) {
	client := NewClient(MemoryLocalStore(), s.remote)

	// check Init() returns keys.ErrInvalidThreshold with an invalid threshold
	c.Assert(client.Init(s.rootKeys(c), 0), Equals, keys.ErrInvalidThreshold)

	// check Init() returns signed.ErrRoleThreshold when not enough keys
	c.Assert(client.Init(s.rootKeys(c), 2), Equals, signed.ErrRoleThreshold)

	// check Update() returns ErrNoRootKeys when uninitialized
	_, err := client.Update()
	c.Assert(err, Equals, ErrNoRootKeys)

	// check Update() does not return ErrNoRootKeys after initialization
	c.Assert(client.Init(s.rootKeys(c), 1), IsNil)
	_, err = client.Update()
	c.Assert(err, Not(Equals), ErrNoRootKeys)
}

func (s *ClientSuite) TestFirstUpdate(c *C) {
	files, err := s.newClient(c).Update()
	c.Assert(err, IsNil)
	c.Assert(files, HasLen, 1)
	assertFiles(c, files, []string{"foo.txt"})
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
	c.Assert(IsLatestSnapshot(err), Equals, true)
}

func (s *ClientSuite) TestNewTargets(c *C) {
	client := s.newClient(c)
	files, err := client.Update()
	c.Assert(err, IsNil)
	assertFiles(c, files, []string{"foo.txt"})

	s.addRemoteTarget(c, "bar.txt")
	s.addRemoteTarget(c, "baz.txt")

	files, err = client.Update()
	c.Assert(err, IsNil)
	assertFiles(c, files, []string{"bar.txt", "baz.txt"})

	// Adding the same exact file should not lead to an update
	s.addRemoteTarget(c, "bar.txt")
	files, err = client.Update()
	c.Assert(err, IsNil)
	c.Assert(files, HasLen, 0)
}

func (s *ClientSuite) TestLocalExpired(c *C) {
	client := s.newClient(c)
	duration := 100 * time.Millisecond
	syncAndWait := func() {
		s.syncLocal(c)
		time.Sleep(duration)
		c.Assert(client.getLocalMeta(), IsNil)
	}

	// locally expired timestamp.json is ok
	version := client.localTimestampVer
	s.repo.TimestampWithExpires(time.Now().Add(duration))
	syncAndWait()
	c.Assert(client.localTimestampVer > version, Equals, true)

	// locally expired snapshot.json is ok
	version = client.localSnapshotVer
	s.repo.SnapshotWithExpires(tuf.CompressionTypeNone, time.Now().Add(duration))
	syncAndWait()
	c.Assert(client.localSnapshotVer > version, Equals, true)

	// locally expired targets.json is ok
	version = client.localTargetsVer
	s.repo.AddTargetWithExpires("foo.txt", nil, time.Now().Add(duration))
	syncAndWait()
	c.Assert(client.localTargetsVer > version, Equals, true)

	// locally expired root.json is not ok
	version = client.localRootVer
	s.repo.GenKeyWithExpires("targets", time.Now().Add(duration))
	s.syncLocal(c)
	time.Sleep(duration)
	c.Assert(client.getLocalMeta(), Equals, signed.ErrExpired)
	c.Assert(client.localRootVer, Equals, version)
}

func (s *ClientSuite) TestTimestampTooLarge(c *C) {
	s.remote["timestamp.json"] = newFakeFile(make([]byte, maxMetaSize+1))
	_, err := s.newClient(c).Update()
	c.Assert(err, Equals, ErrMetaTooLarge{"timestamp.json", maxMetaSize + 1})
}

func (s *ClientSuite) TestUpdateLocalRootExpired(c *C) {
	client := s.newClient(c)
	duration := 100 * time.Millisecond

	// add soon to expire root.json to local storage
	c.Assert(s.repo.GenKeyWithExpires("timestamp", time.Now().Add(duration)), IsNil)
	c.Assert(s.repo.Timestamp(), IsNil)
	s.syncLocal(c)

	// add far expiring root.json to remote storage
	c.Assert(s.repo.GenKey("timestamp"), IsNil)
	s.addRemoteTarget(c, "bar.txt")
	s.syncRemote(c)

	// wait for local storage to expire then check the update is ok (as
	// the update will download the non expired remote root.json and
	// restart itself)
	time.Sleep(duration)
	c.Assert(client.getLocalMeta(), Equals, signed.ErrExpired)
	_, err := client.Update()
	c.Assert(err, IsNil)
}

func (s *ClientSuite) TestUpdateRemoteExpired(c *C) {
	client := s.updatedClient(c)
	duration := 100 * time.Millisecond
	syncAndWait := func() {
		s.syncRemote(c)
		time.Sleep(duration)
	}

	// expired remote metadata should always be rejected
	c.Assert(s.repo.TimestampWithExpires(time.Now().Add(duration)), IsNil)
	syncAndWait()
	_, err := client.Update()
	c.Assert(err, DeepEquals, ErrExpiredMeta{"timestamp.json"})

	c.Assert(s.repo.SnapshotWithExpires(tuf.CompressionTypeNone, time.Now().Add(duration)), IsNil)
	c.Assert(s.repo.Timestamp(), IsNil)
	syncAndWait()
	_, err = client.Update()
	c.Assert(err, DeepEquals, ErrExpiredMeta{"snapshot.json"})

	c.Assert(s.repo.AddTargetWithExpires("bar.txt", nil, time.Now().Add(duration)), IsNil)
	c.Assert(s.repo.Snapshot(tuf.CompressionTypeNone), IsNil)
	c.Assert(s.repo.Timestamp(), IsNil)
	syncAndWait()
	_, err = client.Update()
	c.Assert(err, DeepEquals, ErrExpiredMeta{"targets.json"})

	c.Assert(s.repo.GenKeyWithExpires("timestamp", time.Now().Add(duration)), IsNil)
	c.Assert(s.repo.RemoveTarget("bar.txt"), IsNil)
	c.Assert(s.repo.Snapshot(tuf.CompressionTypeNone), IsNil)
	c.Assert(s.repo.Timestamp(), IsNil)
	syncAndWait()
	_, err = client.Update()
	c.Assert(err, DeepEquals, ErrExpiredMeta{"root.json"})
}

// TODO: Implement these tests:
//
// * Test new timestamp with same snapshot
// * Test new root data (e.g. new targets keys)
// * Test invalid timestamp / snapshot signature downloads root.json
// * Test invalid hash returns ErrDownloadFailed

type testDestination struct {
	bytes.Buffer
	deleted bool
}

func (t *testDestination) Delete() error {
	t.deleted = true
	return nil
}

func (s *ClientSuite) TestDownloadUnknownTarget(c *C) {
	client := s.updatedClient(c)
	var dest testDestination
	c.Assert(client.Download("nonexistent", &dest), Equals, ErrUnknownTarget{"nonexistent"})
	c.Assert(dest.deleted, Equals, true)
}

func (s *ClientSuite) TestDownloadNoExist(c *C) {
	client := s.updatedClient(c)
	delete(s.remote, "targets/foo.txt")
	var dest testDestination
	c.Assert(client.Download("foo.txt", &dest), Equals, ErrNotFound{"foo.txt"})
	c.Assert(dest.deleted, Equals, true)
}

func (s *ClientSuite) TestDownloadOK(c *C) {
	client := s.updatedClient(c)
	var dest testDestination
	c.Assert(client.Download("foo.txt", &dest), IsNil)
	c.Assert(dest.deleted, Equals, false)
	c.Assert(dest.String(), Equals, "foo")
}

func (s *ClientSuite) TestDownloadWrongSize(c *C) {
	client := s.updatedClient(c)
	remoteFile := &fakeFile{buf: bytes.NewReader([]byte("wrong-size")), size: 10}
	s.remote["targets/foo.txt"] = remoteFile
	var dest testDestination
	c.Assert(client.Download("foo.txt", &dest), DeepEquals, ErrWrongSize{"foo.txt", 10, 3})
	c.Assert(remoteFile.bytesRead, Equals, 0)
	c.Assert(dest.deleted, Equals, true)
}

func (s *ClientSuite) TestDownloadTargetTooLong(c *C) {
	client := s.updatedClient(c)
	remoteFile := s.remote["targets/foo.txt"]
	remoteFile.buf = bytes.NewReader([]byte("foo-ooo"))
	var dest testDestination
	c.Assert(client.Download("foo.txt", &dest), IsNil)
	c.Assert(remoteFile.bytesRead, Equals, 3)
	c.Assert(dest.deleted, Equals, false)
	c.Assert(dest.String(), Equals, "foo")
}

func (s *ClientSuite) TestDownloadTargetTooShort(c *C) {
	client := s.updatedClient(c)
	remoteFile := s.remote["targets/foo.txt"]
	remoteFile.buf = bytes.NewReader([]byte("fo"))
	var dest testDestination
	c.Assert(client.Download("foo.txt", &dest), DeepEquals, ErrWrongSize{"foo.txt", 2, 3})
	c.Assert(dest.deleted, Equals, true)
}

func (s *ClientSuite) TestDownloadTargetCorruptData(c *C) {
	client := s.updatedClient(c)
	remoteFile := s.remote["targets/foo.txt"]
	remoteFile.buf = bytes.NewReader([]byte("corrupt"))
	var dest testDestination
	err := client.Download("foo.txt", &dest)
	// just test the type of err rather using DeepEquals (as it contains sha512
	// hashes we don't necessarily care about here).
	e, ok := err.(ErrDownloadFailed)
	if !ok {
		c.Fatalf("expected err to have type ErrDownloadFailed, got %T", err)
	}
	if _, ok := e.Err.(util.ErrWrongHash); !ok {
		c.Fatalf("expected err.Err to have type util.ErrWrongHash, got %T", err)
	}
	c.Assert(dest.deleted, Equals, true)
}

func (s *ClientSuite) TestAvailableTargets(c *C) {
	client := s.updatedClient(c)
	files, err := client.Targets()
	c.Assert(err, IsNil)
	assertFiles(c, files, []string{"foo.txt"})

	s.addRemoteTarget(c, "bar.txt")
	s.addRemoteTarget(c, "baz.txt")
	_, err = client.Update()
	c.Assert(err, IsNil)
	files, err = client.Targets()
	c.Assert(err, IsNil)
	assertFiles(c, files, []string{"foo.txt", "bar.txt", "baz.txt"})
}
