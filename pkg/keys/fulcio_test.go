package keys

import (
	"encoding/json"

	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type FulcioSuite struct{}

var _ = Suite(&FulcioSuite{})

func (FulcioSuite) TestUnmarshalEd25519(c *C) {
	badKeyValue, _ := json.Marshal(true)
	badKey := &data.PublicKey{
		Type:       data.KeyTypeRSASSA_PSS_SHA256,
		Scheme:     data.KeySchemeRSASSA_PSS_SHA256,
		Algorithms: data.HashAlgorithms,
		Value:      badKeyValue,
	}
	verifier := NewP256Verifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
}

/*
func (FulcioSuite) TestSignVerify(c *C) {
	signer, err := GenerateFulcioKey()
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
}*/
