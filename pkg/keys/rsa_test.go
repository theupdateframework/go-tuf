package keys

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/DataDog/go-tuf/data"
	. "gopkg.in/check.v1"
)

type RsaSuite struct{}

var _ = Suite(&RsaSuite{})

func (RsaSuite) TestSignVerify(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}

func (RsaSuite) TestRSAVerifyMismatchMessage(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify([]byte("notfoo"), sig), ErrorMatches, "crypto/rsa: verification error")
}

func (RsaSuite) TestRSAVerifyMismatchPubKey(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)

	signerNew, err := GenerateRsaKey()
	c.Assert(err, IsNil)

	pubKey, err := GetVerifier(signerNew.PublicData())
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify([]byte("notfoo"), sig), ErrorMatches, "crypto/rsa: verification error")
}

func (RsaSuite) TestMarshalUnmarshalPublicKey(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.MarshalPublicKey(), DeepEquals, publicData)
}

func (RsaSuite) TestMarshalUnmarshalPrivateKey(c *C) {
	signer, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	privateData, err := signer.MarshalPrivateKey()
	c.Assert(err, IsNil)
	c.Assert(privateData.Type, Equals, data.KeyTypeRSASSA_PSS_SHA256)
	c.Assert(privateData.Scheme, Equals, data.KeySchemeRSASSA_PSS_SHA256)
	c.Assert(privateData.Algorithms, DeepEquals, data.HashAlgorithms)
	s, err := GetSigner(privateData)
	c.Assert(err, IsNil)
	c.Assert(s, DeepEquals, signer)
}

func (ECDSASuite) TestUnmarshalRSA_Invalid(c *C) {
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

func (ECDSASuite) TestUnmarshalRSAPublicKey(c *C) {
	priv, err := GenerateRsaKey()
	c.Assert(err, IsNil)

	signer := &rsaSigner{priv.PrivateKey}
	goodKey := signer.PublicData()

	verifier := newRsaVerifier()
	c.Assert(verifier.UnmarshalPublicKey(goodKey), IsNil)
}

func (ECDSASuite) TestUnmarshalRSA_TooLongContent(c *C) {
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
	verifier := newRsaVerifier()
	err = verifier.UnmarshalPublicKey(badKey)
	c.Assert(errors.Is(err, io.ErrUnexpectedEOF), Equals, true)
}
