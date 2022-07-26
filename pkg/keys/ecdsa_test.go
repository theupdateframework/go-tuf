package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	fuzz "github.com/google/gofuzz"
	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type ECDSASuite struct{}

var _ = Suite(&ECDSASuite{})

func (ECDSASuite) TestUnmarshalECDSA(c *C) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader("00001-deterministic-buffer-for-key-generation"))
	c.Assert(err, IsNil)

	// Marshall as non compressed point
	pub := elliptic.Marshal(elliptic.P256(), priv.X, priv.Y)

	publicKey, err := json.Marshal(map[string]string{
		"public": hex.EncodeToString(pub),
	})
	c.Assert(err, IsNil)

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
	badKeyValue, err := json.Marshal(true)
	c.Assert(err, IsNil)

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
	randomSeed := make([]byte, MaxJSONKeySize)
	_, err := io.ReadFull(rand.Reader, randomSeed)
	c.Assert(err, IsNil)

	tooLongPayload, err := json.Marshal(
		&ed25519Verifier{
			PublicKey: data.HexBytes(hex.EncodeToString(randomSeed)),
		},
	)
	c.Assert(err, IsNil)

	badKey := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      tooLongPayload,
	}
	verifier := NewEcdsaVerifier()
	err = verifier.UnmarshalPublicKey(badKey)
	c.Assert(errors.Is(err, io.ErrUnexpectedEOF), Equals, true)
}
