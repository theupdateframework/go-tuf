package keys

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type KeysSuite struct{}

var _ = Suite(&KeysSuite{})

func (KeysSuite) TestSignerKeyIDs(c *C) {
	key, err := GenerateEd25519Key()
	c.Assert(err, IsNil)
	c.Assert(key.PublicData().IDs(), DeepEquals, key.IDs())

	// If we have a TUF-0.9 key, we won't have a scheme.
	key, err = GenerateEd25519Key()
	c.Assert(err, IsNil)
	privKey, err := key.MarshalPrivate()
	c.Assert(err, IsNil)
	privKey.Scheme = ""
	err = key.UnmarshalSigner(*privKey)
	c.Assert(err, IsNil)
	c.Assert(key.PublicData().IDs(), DeepEquals, key.IDs())

	// Make sure we preserve ids if we don't have any
	// keyid_hash_algorithms.
	key, err = GenerateEd25519Key()
	c.Assert(err, IsNil)
	privKey, err = key.MarshalPrivate()
	c.Assert(err, IsNil)
	privKey.Algorithms = []string{}
	err = key.UnmarshalSigner(*privKey)
	c.Assert(err, IsNil)
	c.Assert(key.PublicData().IDs(), DeepEquals, key.IDs())
}
