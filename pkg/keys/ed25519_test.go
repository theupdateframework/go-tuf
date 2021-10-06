package keys

import (
	"encoding/json"

	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type Ed25519Suite struct{}

var _ = Suite(&Ed25519Suite{})

func (Ed25519Suite) TestUnmarshalEd25519(c *C) {
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

func (Ed25519Suite) TestSignVerify(c *C) {
	signer, err := GenerateEd25519Key()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}
