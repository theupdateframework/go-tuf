package keys

import (
	. "gopkg.in/check.v1"
)

type RsaSuite struct{}

var _ = Suite(&RsaSuite{})

func (RsaSuite) TestSignVerify(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sigs, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	for _, sig := range sigs {
		c.Assert(pubKey.Verify(msg, sig.Signature), IsNil)
	}
}

func (RsaSuite) TestMarshalUnmarshal(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.MarshalPublicKey(), DeepEquals, publicData)
}
