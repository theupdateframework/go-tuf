package data

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	cjson "github.com/tent/canonical-json-go"
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
		testName              string
		file                  string
		matchWithHashPrefixes bool
		pathMatchers          []string
		matches               bool
	}{
		{
			testName: "no path",
			file:     "licence.txt",
		},
		{
			testName:     "match path *",
			pathMatchers: []string{"null", "targets/*.tgz"},
			file:         "targets/foo.tgz",
			matches:      true,
		},
		{
			testName:     "does not match path *",
			pathMatchers: []string{"null", "targets/*.tgz"},
			file:         "targets/foo.txt",
		},
		{
			testName:     "match path ?",
			pathMatchers: []string{"foo-version-?.tgz"},
			file:         "foo-version-a.tgz",
			matches:      true,
		},
		{
			testName:     "does not match ?",
			pathMatchers: []string{"foo-version-?.tgz"},
			file:         "foo-version-alpha.tgz",
		},
		// picked from https://github.com/theupdateframework/tuf/blob/30ba6e9f9ab25e0370e29ce574dada2d8809afa0/tests/test_updater.py#L1726-L1734
		{
			testName:              "match hash prefix",
			pathMatchers:          []string{"badd", "8baf"},
			file:                  "/file3.txt",
			matchWithHashPrefixes: true,
			matches:               true,
		},
		{
			testName:              "does not match hash prefix",
			pathMatchers:          []string{"badd"},
			matchWithHashPrefixes: true,
			file:                  "/file3.txt",
		},
		{
			testName:              "hash prefix first char",
			pathMatchers:          []string{"2"},
			matchWithHashPrefixes: true,
			file:                  "/a/b/c/file_d.txt",
			matches:               true,
		},
		{
			testName:              "full hash prefix",
			pathMatchers:          []string{"34c85d1ee84f61f10d7dc633472a49096ed87f8f764bd597831eac371f40ac39"},
			matchWithHashPrefixes: true,
			file:                  "/e/f/g.txt",
			matches:               true,
		},
	}
	for _, tt := range tts {
		t.Run(tt.testName, func(t *testing.T) {
			d := DelegatedRole{
				PathMatchers:          tt.pathMatchers,
				MatchWithHashPrefixes: tt.matchWithHashPrefixes,
			}
			assert.Equal(t, tt.matches, d.MatchesPath(tt.file))
		})

	}
}

func TestDelegatedRoleJSON(t *testing.T) {
	var tts = []struct {
		testName string
		d        DelegatedRole
		rawCJSON string
	}{{
		"all fields with hashes",
		DelegatedRole{
			Name:                  "n1",
			KeyIDs:                []string{"k1"},
			Threshold:             5,
			Terminating:           true,
			MatchWithHashPrefixes: true,
			PathMatchers:          []string{"8f"},
		},
		`{"keyids":["k1"],"name":"n1","path_hash_prefixes":["8f"],"paths":null,"terminating":true,"threshold":5}`,
	},
		{
			"paths only",
			DelegatedRole{
				Name:         "n2",
				KeyIDs:       []string{"k1", "k3"},
				Threshold:    12,
				PathMatchers: []string{"*.txt"},
			},
			`{"keyids":["k1","k3"],"name":"n2","paths":["*.txt"],"terminating":false,"threshold":12}`,
		},
		{
			"default",
			DelegatedRole{},
			`{"keyids":null,"name":"","paths":null,"terminating":false,"threshold":0}`,
		},
	}

	for _, tt := range tts {
		t.Run(tt.testName, func(t *testing.T) {
			d := &DelegatedRole{}
			*d = tt.d

			raw, err := cjson.Marshal(d)
			assert.Nil(t, err)
			assert.Equal(t, tt.rawCJSON, string(raw))

			var newD DelegatedRole
			assert.Nil(t, json.Unmarshal(raw, &newD))
			assert.Equal(t, d, &newD)
		})
	}
}

func TestDelegatedRoleUnmarshalErr(t *testing.T) {
	targetsWithBothMatchers := []byte(`{"keyids":null,"name":"","paths":["*.txt"],"path_hash_prefixes":["8f"],"terminating":false,"threshold":0}`)
	var d DelegatedRole
	assert.Equal(t, json.Unmarshal(targetsWithBothMatchers, &d), ErrPathsAndPathHashesSet)

	// test for type errors
	err := json.Unmarshal([]byte(`{"keyids":"a"}`), &d)
	assert.Equal(t, err.Error(), "json: cannot unmarshal string into Go struct field delegatedRoleJSON.keyids of type []string")
}
