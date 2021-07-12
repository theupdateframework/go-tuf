package data

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	. "gopkg.in/check.v1"
)

const (
	// This public key is from the TUF specs:
	//
	// https://github.com/theupdateframework/specification
	//
	public       = `"72378e5bc588793e58f81c8533da64a2e8f1565c1fcc7f253496394ffc52542c"`
	keyid10      = "1bf1c6e3cdd3d3a8420b19199e27511999850f4b376c4547b2f32fba7e80fca3"
	keyid10algos = "506a349b85945d0d99c7289c3f0f1f6c550218089d1d38a3f64824db31e827ac"
)

type TypesSuite struct{}

var _ = Suite(&TypesSuite{})

func (TypesSuite) TestKeyIDs(c *C) {
	var hexbytes HexBytes
	err := json.Unmarshal([]byte(public), &hexbytes)
	c.Assert(err, IsNil)

	key := Key{
		Type:   KeyTypeEd25519,
		Scheme: KeySchemeEd25519,
		Value:  KeyValue{Public: hexbytes},
	}
	c.Assert(key.IDs(), DeepEquals, []string{keyid10})

	key = Key{
		Type:       KeyTypeEd25519,
		Scheme:     KeySchemeEd25519,
		Algorithms: KeyAlgorithms,
		Value:      KeyValue{Public: hexbytes},
	}
	c.Assert(key.IDs(), DeepEquals, []string{keyid10algos})
}

func (TypesSuite) TestRootAddKey(c *C) {
	var hexbytes HexBytes
	err := json.Unmarshal([]byte(public), &hexbytes)
	c.Assert(err, IsNil)

	key := &Key{
		Type:   KeyTypeEd25519,
		Scheme: KeySchemeEd25519,
		Value:  KeyValue{Public: hexbytes},
	}

	root := NewRoot()

	c.Assert(root.AddKey(key), Equals, true)
	c.Assert(root.AddKey(key), Equals, false)
}

func (TypesSuite) TestRoleAddKeyIDs(c *C) {
	var hexbytes HexBytes
	err := json.Unmarshal([]byte(public), &hexbytes)
	c.Assert(err, IsNil)

	key := &Key{
		Type:   KeyTypeEd25519,
		Scheme: KeySchemeEd25519,
		Value:  KeyValue{Public: hexbytes},
	}

	role := &Role{}
	c.Assert(role.KeyIDs, HasLen, 0)

	c.Assert(role.AddKeyIDs(key.IDs()), Equals, true)
	c.Assert(role.KeyIDs, DeepEquals, []string{keyid10})

	// Adding the key again doesn't modify the array.
	c.Assert(role.AddKeyIDs(key.IDs()), Equals, false)
	c.Assert(role.KeyIDs, DeepEquals, []string{keyid10})

	// Add another key.
	key = &Key{
		Type:       KeyTypeEd25519,
		Scheme:     KeySchemeEd25519,
		Algorithms: KeyAlgorithms,
		Value:      KeyValue{Public: hexbytes},
	}

	// Adding the key again doesn't modify the array.
	c.Assert(role.AddKeyIDs(key.IDs()), Equals, true)
	c.Assert(role.KeyIDs, DeepEquals, []string{keyid10, keyid10algos})
}

func TestDelegatedRolePathMatch(t *testing.T) {
	var tts = []struct {
		testName         string
		file             string
		pathHashPrefixes []string
		paths            []string
		matches          bool
	}{
		{
			testName: "no path",
			file:     "licence.txt",
		},
		{
			testName: "match path *",
			paths:    []string{"null", "targets/*.tgz"},
			file:     "targets/foo.tgz",
			matches:  true,
		},
		{
			testName: "does not match path *",
			paths:    []string{"null", "targets/*.tgz"},
			file:     "targets/foo.txt",
		},
		{
			testName: "match path ?",
			paths:    []string{"foo-version-?.tgz"},
			file:     "foo-version-a.tgz",
			matches:  true,
		},
		{
			testName: "does not match ?",
			paths:    []string{"foo-version-?.tgz"},
			file:     "foo-version-alpha.tgz",
		},
		// picked from https://github.com/theupdateframework/tuf/blob/30ba6e9f9ab25e0370e29ce574dada2d8809afa0/tests/test_updater.py#L1726-L1734
		{
			testName:         "match hash prefix",
			pathHashPrefixes: []string{"badd", "8baf"},
			file:             "/file3.txt",
			matches:          true,
		},
		{
			testName:         "does not match hash prefix",
			pathHashPrefixes: []string{"badd"},
			file:             "/file3.txt",
		},
	}
	for _, tt := range tts {
		t.Run(tt.testName, func(t *testing.T) {
			d := DelegatedRole{
				PathHashPrefixes: tt.pathHashPrefixes,
				Paths:            tt.paths,
			}
			assert.Equal(t, tt.matches, d.MatchesPath(tt.file))
		})

	}
}
