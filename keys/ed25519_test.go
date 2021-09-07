package keys

import (
	"crypto"
	"crypto/rand"

	. "gopkg.in/check.v1"
)

type Ed25519Suite struct{}

var _ = Suite(&Ed25519Suite{})

func (Ed25519Suite) TestSignVerify(c *C) {
	key, err := GenerateEd25519Key()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := key.Sign(rand.Reader, msg, crypto.Hash(0))
	c.Assert(err, IsNil)
	publicData := key.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}
