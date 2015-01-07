package util

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/flynn/go-tuf/data"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type UtilSuite struct{}

var _ = Suite(&UtilSuite{})

func (UtilSuite) TestGenerateFileMeta(c *C) {
	r := bytes.NewReader([]byte("foo"))
	meta, err := GenerateFileMeta(r)
	c.Assert(err, IsNil)
	c.Assert(meta.Length, Equals, int64(3))
	hashes := meta.Hashes
	c.Assert(hashes, HasLen, 1)
	hash, ok := hashes["sha512"]
	if !ok {
		c.Fatal("missing sha512 hash")
	}
	c.Assert(hash.String(), DeepEquals, "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7")
}

func (UtilSuite) TestFileMetaEqual(c *C) {
	type test struct {
		name string
		b    data.FileMeta
		a    data.FileMeta
		err  func(test) error
	}
	fileMeta := func(length int64, hashes map[string]string) data.FileMeta {
		m := data.FileMeta{Length: length, Hashes: make(map[string]data.HexBytes, len(hashes))}
		for typ, hash := range hashes {
			v, err := hex.DecodeString(hash)
			c.Assert(err, IsNil)
			m.Hashes[typ] = v
		}
		return m
	}
	tests := []test{
		{
			name: "wrong length",
			a:    data.FileMeta{Length: 1},
			b:    data.FileMeta{Length: 2},
			err:  func(test) error { return ErrWrongLength },
		},
		{
			name: "wrong sha512 hash",
			a:    fileMeta(10, map[string]string{"sha512": "111111"}),
			b:    fileMeta(10, map[string]string{"sha512": "222222"}),
			err:  func(t test) error { return ErrWrongHash{"sha512", t.b.Hashes["sha512"], t.a.Hashes["sha512"]} },
		},
		{
			name: "intersecting hashes",
			a:    fileMeta(10, map[string]string{"sha512": "111111", "md5": "222222"}),
			b:    fileMeta(10, map[string]string{"sha512": "111111", "sha256": "333333"}),
			err:  func(test) error { return nil },
		},
		{
			name: "no common hashes",
			a:    fileMeta(10, map[string]string{"sha512": "111111"}),
			b:    fileMeta(10, map[string]string{"sha256": "222222", "md5": "333333"}),
			err:  func(t test) error { return ErrNoCommonHash{t.b.Hashes, t.a.Hashes} },
		},
	}
	for _, t := range tests {
		c.Assert(FileMetaEqual(t.a, t.b), DeepEquals, t.err(t), Commentf("name = %s", t.name))
	}
}
