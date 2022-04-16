package keys

import (
	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type EcdsaSuite struct{}

var _ = Suite(EcdsaSuite{})

func (EcdsaSuite) TestSignVerify(c *C) {
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}

func (EcdsaSuite) TestMarshalUnmarshalPublicKey(c *C) {
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.MarshalPublicKey(), DeepEquals, publicData)
}

func (EcdsaSuite) TestMarshalUnmarshalPrivateKey(c *C) {
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	privateData, err := signer.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(privateData.Type, Equals, data.KeyTypeECDSA_SHA2_P256)
	c.Assert(privateData.Scheme, Equals, data.KeySchemeECDSA_SHA2_P256)
	c.Assert(privateData.Algorithms, DeepEquals, data.HashAlgorithms)
	s, err := GetSigner(privateData)
	c.Assert(err, IsNil)
	c.Assert(s, DeepEquals, signer)
}
