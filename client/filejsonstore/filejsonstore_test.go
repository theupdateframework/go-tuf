package client

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/check.v1"
)

type RawJSONStoreSuite struct{}

var _ = check.Suite(&RawJSONStoreSuite{})

// Hook up gocheck into the "go test" runnder
func Test(t *testing.T) { check.TestingT(t) }

func (RawJSONStoreSuite) TestNewOk(c *check.C) {
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

func (RawJSONStoreSuite) TestNewFileExists(c *check.C) {
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

func (RawJSONStoreSuite) TestGetMetaEmpty(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)

	md, err := s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 0)
}

func (RawJSONStoreSuite) TestMetadataOperations(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	expected := map[string]json.RawMessage{
		"file1.json": []byte{0xf1, 0xe1, 0xd1},
		"file2.json": []byte{0xf2, 0xe2, 0xd2},
		"file3.json": []byte{0xf3, 0xe3, 0xd3},
	}

	for k, v := range expected {
		s.SetMeta(k, v)
	}

	md, err := s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 3)
	c.Assert(md, check.DeepEquals, expected)

	// Nuke items
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

func (RawJSONStoreSuite) TestGetNoJSON(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	// Create a file which does not end with '.json'
	fp := filepath.FromSlash(filepath.Join(p, "meta.xml"))
	os.WriteFile(fp, []byte{}, 0644)

	md, err := s.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 0)
}

func (RawJSONStoreSuite) TestNoJSON(c *check.C) {
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

func (RawJSONStoreSuite) TestClose(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	err = s.Close()
	c.Assert(err, check.IsNil)
}

func (RawJSONStoreSuite) TestDelete(c *check.C) {
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
