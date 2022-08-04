package client

import (
	"encoding/json"
	"testing"

	"gopkg.in/check.v1"
)

type ConcurrentStoreSuite struct{}

var _ = check.Suite(&ConcurrentStoreSuite{})

// Hook up gocheck into the "go test" runnder
func ConcurrentTest(t *testing.T) { check.TestingT(t) }

func (ConcurrentStoreSuite) TestOperations(c *check.C) {
	mem := MemoryLocalStore()
	store := NewConcurrentLocalStore(mem)

	c.Assert(store, check.NotNil)
	expected := map[string]json.RawMessage{
		"file1.json": []byte{0xf1, 0xe1, 0xd1},
		"file2.json": []byte{0xf2, 0xe2, 0xd2},
		"file3.json": []byte{0xf3, 0xe3, 0xd3},
	}

	for k, v := range expected {
		err := store.SetMeta(k, v)
		c.Assert(err, check.IsNil)
	}

	md, err := store.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 3)
	c.Assert(md, check.DeepEquals, expected)

	// Nuke items
	count := 3
	for k := range expected {
		err = store.DeleteMeta(k)
		count--
		c.Assert(err, check.IsNil)
		md, err := store.GetMeta()
		c.Assert(err, check.IsNil)
		c.Assert(md, check.HasLen, count)
	}

	md, err = store.GetMeta()
	c.Assert(err, check.IsNil)
	c.Assert(md, check.HasLen, 0)

	err = store.Close()
	c.Assert(err, check.IsNil)
}
