//go:build !windows
// +build !windows

package client

import (
	"os"
	"path/filepath"

	"gopkg.in/check.v1"
)

func (FileJSONStoreSuite) TestNewDirectoryExistsWrongPerm(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")

	err := os.Mkdir(p, 0750)
	c.Assert(err, check.IsNil)

	// Modify the directory permission and try again
	err = os.Chmod(p, 0751)
	c.Assert(err, check.IsNil)
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.IsNil)
	c.Assert(err, check.ErrorMatches, "permission bits for file tuf_raw.db failed.*")
}

func (FileJSONStoreSuite) TestNewNoCreate(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")

	// Clear the write bit for the user
	err := os.Chmod(tmp, 0551)
	c.Assert(err, check.IsNil)
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.IsNil)
	c.Assert(err, check.NotNil)
}

func (FileJSONStoreSuite) TestGetTooPermissive(c *check.C) {
	tmp := c.MkDir()
	p := filepath.Join(tmp, "tuf_raw.db")
	s, err := NewFileJSONStore(p)
	c.Assert(s, check.NotNil)
	c.Assert(err, check.IsNil)

	fp := filepath.Join(p, "meta.json")
	err = os.WriteFile(fp, []byte{}, 0644)
	c.Assert(err, check.IsNil)

	md, err := s.GetMeta()
	c.Assert(md, check.IsNil)
	c.Assert(err, check.ErrorMatches, "permission bits for file meta.json failed.*")
}
