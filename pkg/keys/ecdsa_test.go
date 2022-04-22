package keys

import (
	"crypto/rand"
	"encoding/json"
	"io"

	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type ECDSASuite struct{}

var _ = Suite(&ECDSASuite{})

func (ECDSASuite) TestUnmarshalECDSA(c *C) {
	badKeyValue, _ := json.Marshal(true)
	badKey := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      badKeyValue,
	}
	verifier := NewEcdsaVerifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
}

func (ECDSASuite) TestUnmarshalECDSA_TooLongContent(c *C) {
	randomSeed := make(json.RawMessage, 1024*1024)
	io.ReadFull(rand.Reader, randomSeed)

	tooLongPayload, _ := json.Marshal(
		&ed25519Verifier{
			PublicKey: data.HexBytes(randomSeed),
		},
	)

	badKey := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      tooLongPayload,
	}
	verifier := NewEcdsaVerifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "unexpected EOF")
}
