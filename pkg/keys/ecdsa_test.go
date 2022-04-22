package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	fuzz "github.com/google/gofuzz"
	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type ECDSASuite struct{}

var _ = Suite(&ECDSASuite{})

func (Ed25519Suite) TestUnmarshalECDSA(c *C) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader("00001-deterministic-buffer-for-key-generation"))

	// Marshall as non compressed point
	pub := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)

	publicKey, _ := json.Marshal(map[string]string{
		"public": hex.EncodeToString(pub),
	})
	badKey := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      publicKey,
	}
	verifier := NewEcdsaVerifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), IsNil)
}

func (ECDSASuite) TestUnmarshalECDSA_Invalid(c *C) {
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

func (ECDSASuite) TestUnmarshalECDSA_FastFuzz(c *C) {
	verifier := NewEcdsaVerifier()
	for i := 0; i < 50; i++ {
		// Ensure no basic panic

		f := fuzz.New()
		var publicData data.PublicKey
		f.Fuzz(&publicData)

		verifier.UnmarshalPublicKey(&publicData)
	}
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
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, ".*: unexpected EOF")
}
