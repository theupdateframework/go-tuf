package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/check.v1"

	"github.com/theupdateframework/go-tuf/client"
)

type FileJSONStoreSuite struct{}

var _ = check.Suite(&FileJSONStoreSuite{})

// Hook up gocheck into the "go test" runner
func Test(t *testing.T) { check.TestingT(t) }

func (FileJSONStoreSuite) TestNewOk(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")

	// Assert path does not exist
	fi, err := os.Stat(p)
	c.Assert(fi, check.IsNil)
	c.Assert(errors.Is(err, os.ErrNotExist), check.Equals, true)

	// Create implementation
	s, err := NewFileJSONStore(p)
	c.Assert(err, check.IsNil)
	c.Assert(s, check.NotNil)

	// Assert path does exist and is a directory
	fi, err = os.Stat(p)
	c.Assert(fi, check.NotNil)
	c.Assert(err, check.IsNil)
	c.Assert(fi.IsDir(), check.Equals, true)
}

func (FileJSONStoreSuite) TestNewFileExists(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")

	// Create an empty file
	f, err := os.Create(p)
	c.Assert(err, check.IsNil)
	f.Close()

	// Create implementation
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.IsNil)
	c.Assert(err, check.NotNil)
	found := strings.Contains(err.Error(), ", not a directory")
	c.Assert(found, check.Equals, true)
}

func (FileJSONStoreSuite) TestNewDirectoryExists(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")

	err := os.Mkdir(p, 0750)
	c.Assert(err, check.IsNil)

	// Create implementation
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	// Modify the directory permission and try again
	err = os.Chmod(p, 0751)
	s, err = NewFileJSONStore(p)
	c.Assert(s, check.IsNil)
	c.Assert(err, check.Equals, ErrTooPermissive)
}

func (FileJSONStoreSuite) TestNewNoCreate(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")

	// Clear the write bit for the user
	err := os.Chmod(tmp, 0551)
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.IsNil)
	c.Assert(err, check.NotNil)
}

func (FileJSONStoreSuite) TestGetMetaEmpty(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)

	md, err := s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 0)
}

func (FileJSONStoreSuite) TestGetNoDirectory(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)

	err = os.Remove(p)
	c.Assert(err, check.IsNil)

	md, err := s.GetMeta()
	c.Assert(md, check.IsNil)
	c.Assert(err, check.NotNil)
}

func (FileJSONStoreSuite) TestMetadataOperations(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	expected := map[string]json.RawMessage{
		"file1.json": []byte{0xf1, 0xe1, 0xd1},
		"file2.json": []byte{0xf2, 0xe2, 0xd2},
		"file3.json": []byte{0xf3, 0xe3, 0xd3},
	}

	for k, v := range expected {
		err := s.SetMeta(k, v)
		c.Assert(err, check.IsNil)
	}

	md, err := s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 3)
	c.Assert(md, check.DeepEquals, expected)

	// Delete all items
	count := 3
	for k := range expected {
		err = s.DeleteMeta(k)
		count--
		c.Assert(err, check.IsNil)
		md, err := s.GetMeta()
		c.Assert(err, check.IsNil)
		c.Assert(md, check.HasLen, count)
	}

	md, err = s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 0)
}

func (FileJSONStoreSuite) TestGetNoJSON(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	// Create a file which does not end with '.json'
	fp := filepath.FromSlash(filepath.Join(p, "meta.xml"))
	err = os.WriteFile(fp, []byte{}, 0644)
	c.Assert(err, check.IsNil)

	md, err := s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 0)
}

func (FileJSONStoreSuite) TestGetTooPermissive(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	// Create a file which does not end with '.json'
	fp := filepath.FromSlash(filepath.Join(p, "meta.json"))
	err = os.WriteFile(fp, []byte{}, 0644)
	c.Assert(err, check.IsNil)

	md, err := s.GetMeta()
	c.Assert(md, check.IsNil)
	c.Assert(err, check.Equals, ErrTooPermissive)
}

func (FileJSONStoreSuite) TestNoJSON(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	files := []string{
		"file.xml",
		"file",
		"",
	}
	for _, f := range files {
		err := s.SetMeta(f, []byte{})
		c.Assert(err, check.Equals, ErrNotJSON)
	}
}

func (FileJSONStoreSuite) TestClose(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	err = s.Close()
	c.Assert(err, check.IsNil)
}

func (FileJSONStoreSuite) TestDelete(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	err = s.DeleteMeta("not_json.yml")
	c.Assert(err, check.Equals, ErrNotJSON)
	err = s.DeleteMeta("non_existing.json")
	c.Assert(errors.Is(err, os.ErrNotExist), check.Equals, true)
}

func (FileJSONStoreSuite) TestInterface(c *check.C) {
	var localStore client.LocalStore
	var err error

	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	localStore, err = NewFileJSONStore(p)
	c.Assert(localStore, check.NotNil)
	c.Assert(err, check.IsNil)
}

// test 3 file exist and is too permissive
// test 4 remote base dir after create
