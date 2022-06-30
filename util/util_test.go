package util

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"testing"

	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type UtilSuite struct{}

var _ = Suite(&UtilSuite{})

func (UtilSuite) TestGenerateTargetFileMetaDefault(c *C) {
	// default is sha512
	r := bytes.NewReader([]byte("foo"))
	meta, err := GenerateTargetFileMeta(r)
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

func (UtilSuite) TestGenerateTargetFileMetaExplicit(c *C) {
	r := bytes.NewReader([]byte("foo"))
	meta, err := GenerateTargetFileMeta(r, "sha256", "sha512")
	c.Assert(err, IsNil)
	c.Assert(meta.Length, Equals, int64(3))
	hashes := meta.Hashes
	c.Assert(hashes, HasLen, 2)
	for name, val := range map[string]string{
		"sha256": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		"sha512": "f7fbba6e0636f890e56fbbf3283e524c6fa3204ae298382d624741d0dc6638326e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7",
	} {
		hash, ok := hashes[name]
		if !ok {
			c.Fatalf("missing %s hash", name)
		}
		c.Assert(hash.String(), DeepEquals, val)
	}
}

func makeHashes(c *C, hashes map[string]string) data.Hashes {
	h := make(map[string]data.HexBytes, len(hashes))
	for typ, hash := range hashes {
		v, err := hex.DecodeString(hash)
		c.Assert(err, IsNil)
		h[typ] = v
	}
	return h
}

type testMetaFile struct {
	name     string
	actual   data.FileMeta
	expected data.FileMeta
	err      func(testMetaFile) error
}

func testMetaFileCases(c *C) []testMetaFile {
	fileMeta := func(c *C, length int64, hashes map[string]string) data.FileMeta {
		return data.FileMeta{
			Length: length,
			Hashes: makeHashes(c, hashes),
		}
	}

	return []testMetaFile{
		{
			name:     "wrong length",
			actual:   data.FileMeta{Length: 1},
			expected: data.FileMeta{Length: 2},
			err:      func(testMetaFile) error { return ErrWrongLength{Actual: 1, Expected: 2} },
		},
		{
			name:     "wrong sha512 hash",
			actual:   fileMeta(c, 10, map[string]string{"sha512": "111111"}),
			expected: fileMeta(c, 10, map[string]string{"sha512": "222222"}),
			err: func(t testMetaFile) error {
				return ErrWrongHash{"sha512", t.expected.Hashes["sha512"], t.actual.Hashes["sha512"]}
			},
		},
		{
			name:     "intersecting hashes",
			actual:   fileMeta(c, 10, map[string]string{"sha512": "111111", "md5": "222222"}),
			expected: fileMeta(c, 10, map[string]string{"sha512": "111111", "sha256": "333333"}),
			err:      func(testMetaFile) error { return nil },
		},
		{
			name:     "no common hashes",
			actual:   fileMeta(c, 10, map[string]string{"sha512": "111111"}),
			expected: fileMeta(c, 10, map[string]string{"sha256": "222222", "md5": "333333"}),
			err:      func(t testMetaFile) error { return ErrNoCommonHash{t.expected.Hashes, t.actual.Hashes} },
		},
	}
}

func (UtilSuite) TestSnapshotFileMetaEqual(c *C) {
	type test struct {
		name     string
		actual   data.SnapshotFileMeta
		expected data.SnapshotFileMeta
		err      func(test) error
	}

	fileMeta := func(version int64, length int64, hashes map[string]string) data.SnapshotFileMeta {
		return data.SnapshotFileMeta{
			FileMeta: data.FileMeta{
				Length: length,
				Hashes: makeHashes(c, hashes),
			},
			Version: version,
		}
	}

	tests := []test{
		{
			name:     "same version",
			actual:   fileMeta(1, 10, map[string]string{"sha512": "111111"}),
			expected: fileMeta(1, 10, map[string]string{"sha512": "111111"}),
			err:      func(test) error { return nil },
		},
		{
			name:     "wrong version",
			actual:   fileMeta(0, 10, map[string]string{"sha512": "111111"}),
			expected: fileMeta(1, 10, map[string]string{"sha512": "111111"}),
			err:      func(test) error { return ErrWrongVersion{Expected: 1, Actual: 0} },
		},
		{
			name:     "wrong version",
			actual:   fileMeta(1, 10, map[string]string{"sha512": "111111"}),
			expected: fileMeta(0, 10, map[string]string{"sha512": "111111"}),
			err:      func(test) error { return ErrWrongVersion{Expected: 0, Actual: 1} },
		},
		{
			name:     "wrong version",
			actual:   fileMeta(1, 10, map[string]string{"sha512": "111111"}),
			expected: fileMeta(2, 10, map[string]string{"sha512": "111111"}),
			err:      func(test) error { return ErrWrongVersion{Expected: 2, Actual: 1} },
		},
	}

	for _, t := range tests {
		c.Assert(SnapshotFileMetaEqual(t.actual, t.expected), DeepEquals, t.err(t), Commentf("name = %s", t.name))
	}

	for _, t := range testMetaFileCases(c) {
		actual := data.SnapshotFileMeta{FileMeta: t.actual}
		expected := data.SnapshotFileMeta{FileMeta: t.expected}
		c.Assert(SnapshotFileMetaEqual(actual, expected), DeepEquals, t.err(t), Commentf("name = %s", t.name))
	}
}

func (UtilSuite) TestNormalizeTarget(c *C) {
	for before, after := range map[string]string{
		"":                    "",
		"foo.txt":             "foo.txt",
		"/bar.txt":            "bar.txt",
		"foo//bar.txt":        "foo/bar.txt",
		"/with/./a/dot":       "with/a/dot",
		"/with/double/../dot": "with/dot",
	} {
		c.Assert(NormalizeTarget(before), Equals, after)
	}
}

func (UtilSuite) TestHashedPaths(c *C) {
	hexBytes := func(s string) data.HexBytes {
		v, err := hex.DecodeString(s)
		c.Assert(err, IsNil)
		return v
	}
	hashes := data.Hashes{
		"sha512": hexBytes("abc123"),
		"sha256": hexBytes("def456"),
	}
	paths := HashedPaths("foo/bar.txt", hashes)
	// cannot use DeepEquals as the returned order is non-deterministic
	c.Assert(paths, HasLen, 2)
	expected := map[string]struct{}{"foo/abc123.bar.txt": {}, "foo/def456.bar.txt": {}}
	for _, path := range paths {
		if _, ok := expected[path]; !ok {
			c.Fatalf("unexpected path: %s", path)
		}
		delete(expected, path)
	}
}

func (UtilSuite) TestVersionEqual(c *C) {
	c.Assert(VersionEqual(1, 1), IsNil)
	c.Assert(VersionEqual(1, 3), Equals, ErrWrongVersion{3, 1})
}

func makeHash(b []byte, alg string) []byte {
	var h hash.Hash

	switch alg {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	}
	h.Write(b)
	return h.Sum(nil)
}

func (UtilSuite) TestBytesMatchLenAndHashes(c *C) {
	type test struct {
		name   string
		bytes  []byte
		length int64
		hashes data.Hashes
		err    func(test) error
	}

	b := []byte{82, 253, 252, 7, 33, 130, 101, 79, 22, 63, 95, 15, 154, 98, 29, 114}
	bhashes := data.Hashes{
		"sha512": makeHash(b, "sha512"),
		"sha256": makeHash(b, "sha256"),
	}

	tests := []test{
		{
			name:   "correct len and hashes",
			bytes:  b,
			length: 16,
			hashes: bhashes,
			err:    func(test) error { return nil },
		},
		{
			name:   "incorrect len",
			bytes:  b,
			length: 32,
			hashes: bhashes,
			err:    func(test) error { return ErrWrongLength{32, 16} },
		},
		{
			name:   "incorrect hashes sha512",
			bytes:  b,
			length: 16,
			hashes: data.Hashes{
				"sha512": makeHash(b, "sha256"),
			},
			err: func(test) error { return ErrWrongHash{"sha512", bhashes["sha256"], bhashes["sha512"]} },
		},
		{
			name:   "incorrect hashes sha256",
			bytes:  b,
			length: 16,
			hashes: data.Hashes{
				"sha256": makeHash(b, "sha512"),
			},
			err: func(test) error { return ErrWrongHash{"sha256", bhashes["sha512"], bhashes["sha256"]} },
		},
		{
			name:   "incorrect len and hashes",
			bytes:  b,
			length: 32,
			hashes: data.Hashes{
				"sha512": makeHash(b, "sha256"),
				"sha256": makeHash(b, "sha512"),
			},
			err: func(test) error { return ErrWrongLength{32, 16} },
		},
	}

	for _, t := range tests {
		c.Assert(BytesMatchLenAndHashes(t.bytes, t.length, t.hashes), DeepEquals, t.err(t), Commentf("name = %s", t.name))
	}
}
