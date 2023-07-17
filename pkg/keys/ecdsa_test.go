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

	"github.com/DataDog/go-tuf/data"
	fuzz "github.com/google/gofuzz"
	. "gopkg.in/check.v1"
)

type ECDSASuite struct{}

var _ = Suite(ECDSASuite{})

func (ECDSASuite) TestSignVerify(c *C) {
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

func (ECDSASuite) TestECDSAVerifyMismatchMessage(c *C) {
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify([]byte("notfoo"), sig), ErrorMatches, "tuf: ecdsa signature verification failed")
}

func (ECDSASuite) TestECDSAVerifyMismatchPubKey(c *C) {
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)

	signerNew, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	pubKey, err := GetVerifier(signerNew.PublicData())
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify([]byte("notfoo"), sig), ErrorMatches, "tuf: ecdsa signature verification failed")
}

func (ECDSASuite) TestSignVerifyDeprecatedFails(c *C) {
	// Create an ecdsa key with a deprecated format.
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)

	type deprecatedP256Verifier struct {
		PublicKey data.HexBytes `json:"public"`
	}
	pub := signer.PublicKey
	keyValBytes, err := json.Marshal(&deprecatedP256Verifier{PublicKey: elliptic.Marshal(pub.Curve, pub.X, pub.Y)})
	c.Assert(err, IsNil)
	publicData := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}

	_, err = GetVerifier(publicData)
	c.Assert(err, ErrorMatches, "tuf: error unmarshalling key: invalid PEM value")
}

func (ECDSASuite) TestMarshalUnmarshalPublicKey(c *C) {
	signer, err := GenerateEcdsaKey()
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.MarshalPublicKey(), DeepEquals, publicData)
}

func (ECDSASuite) TestMarshalUnmarshalPrivateKey(c *C) {
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

func (ECDSASuite) TestUnmarshalECDSA(c *C) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), strings.NewReader("00001-deterministic-buffer-for-key-generation"))
	c.Assert(err, IsNil)

	signer := &ecdsaSigner{priv}
	goodKey := signer.PublicData()

	verifier := NewEcdsaVerifier()
	c.Assert(verifier.UnmarshalPublicKey(goodKey), IsNil)
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
