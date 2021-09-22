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
	_, err := GenerateEd25519Key()
	c.Assert(err, IsNil)

	// If we have a TUF-0.9 key, we won't have a scheme.
	key, err := GenerateEd25519Key()
	c.Assert(err, IsNil)
	privKey, err := key.MarshalSigner()
	c.Assert(err, IsNil)
	privKey.Scheme = ""
	err = key.UnmarshalSigner(privKey)
	c.Assert(err, IsNil)

	// Make sure we preserve ids if we don't have any
	// keyid_hash_algorithms.
	key, err = GenerateEd25519Key()
	c.Assert(err, IsNil)
	privKey, err = key.MarshalSigner()
	c.Assert(err, IsNil)
	privKey.Algorithms = []string{}
	err = key.UnmarshalSigner(privKey)
	c.Assert(err, IsNil)
}
