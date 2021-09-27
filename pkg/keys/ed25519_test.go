package keys

import (
	"crypto"
	"crypto/rand"
	"encoding/json"

	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type Ed25519Suite struct{}

var _ = Suite(&Ed25519Suite{})

func (Ed25519Suite) TestUnmarshalEd25519(c *C) {
	badKeyValue, _ := json.Marshal(true)
	badKey := &data.Key{
		Type:       data.KeyTypeRSASSA_PSS_SHA256,
		Scheme:     data.KeySchemeRSASSA_PSS_SHA256,
		Algorithms: data.KeyAlgorithms,
		Value:      badKeyValue,
	}
	verifier := NewP256Verifier()
	c.Assert(verifier.UnmarshalKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
}

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
