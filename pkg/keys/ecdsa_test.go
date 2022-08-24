package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	fuzz "github.com/google/gofuzz"
	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
	"io"
	"strings"
	"testing"
)

type ECDSASuite struct{}

var _ = Suite(&ECDSASuite{})

// keySize for ECDSA equals 40 because, 256 / 8 = 32, and 32 + 8 = 40

const keySize = 40

func FuzzUnmarshalECDSA(f *testing.F) {
	f.Add("00001-deterministic-buffer-for-key-generation")

	f.Fuzz(func(t *testing.T, s string) {
		if len(s) <= keySize {
			// len(s) <= 40 is because 256 / 8 = 32, and 32 + 8 = 40, this is from the bitsize of the curve
			t.Skip()
		}

		c := &C{}
		priv, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader(s))
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
	})
}

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

func FuzzInvalidUnmarshalECDSA(f *testing.F) {
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > keySize {
			// len(s) > 40 is because 256 / 8 = 32, and 32 + 8 = 40, this is from the bitsize of the curve, we skip
			// this because only then will we get bad data
			t.Skip()
		}

		badKeyValue, err := json.Marshal(s)
		if err != nil {
			t.Skip()
		}

		c := &C{}

		badKey := &data.PublicKey{
			Type:       data.KeyTypeECDSA_SHA2_P256,
			Scheme:     data.KeySchemeECDSA_SHA2_P256,
			Algorithms: data.HashAlgorithms,
			Value:      badKeyValue,
		}
		verifier := NewEcdsaVerifier()
		c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
	})
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
