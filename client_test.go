package tuf

import (
	"io"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type ClientSuite struct{}

var _ = Suite(&ClientSuite{})

type FakeRemoteStore map[string]FakeFile

func (f FakeRemoteStore) Get(name string, size int64) (io.ReadCloser, error) {
	file, ok := f[name]
	if !ok {
		return nil, ErrNotFound
	}
	if size != file.Size {
		return nil, ErrWrongSize
	}
	return file.ReadCloser, nil
}

type FakeFile struct {
	io.ReadCloser
	Size int64
}

func (ClientSuite) TestFirstUpdate(c *C) {
	remote := make(FakeRemoteStore)
	r := NewRepo(MemoryLocalStore(), remote)
	_ = r
}
