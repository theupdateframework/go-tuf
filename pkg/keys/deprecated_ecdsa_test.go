package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type DeprecatedECDSASuite struct{}

var _ = Suite(DeprecatedECDSASuite{})

type deprecatedEcdsaSigner struct {
	*ecdsa.PrivateKey
}

type deprecatedEcdsaPublic struct {
	PublicKey data.HexBytes `json:"public"`
}

func (s deprecatedEcdsaSigner) PublicData() *data.PublicKey {
	pub := s.Public().(*ecdsa.PublicKey)
	keyValBytes, _ := json.Marshal(deprecatedEcdsaPublic{
		PublicKey: elliptic.Marshal(pub.Curve, pub.X, pub.Y)})
	return &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}
}

func (s deprecatedEcdsaSigner) SignMessage(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return s.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
}

func (s deprecatedEcdsaSigner) ContainsID(id string) bool {
	return s.PublicData().ContainsID(id)
}

func (deprecatedEcdsaSigner) MarshalPrivateKey() (*data.PrivateKey, error) {
	return nil, errors.New("not implemented for test")
}

func (deprecatedEcdsaSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	return errors.New("not implemented for test")
}

func generatedDeprecatedSigner() (*deprecatedEcdsaSigner, error) {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &deprecatedEcdsaSigner{privkey}, nil
}

func (DeprecatedECDSASuite) TestSignVerifyDeprecatedFormat(c *C) {
	// Create an ecdsa key with a deprecated format.
	signer, err := generatedDeprecatedSigner()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)

	pub := signer.PublicKey

	keyValBytes, err := json.Marshal(&deprecatedP256Verifier{PublicKey: elliptic.Marshal(pub.Curve, pub.X, pub.Y)})
	c.Assert(err, IsNil)
	publicData := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}

	deprecatedEcdsa := NewDeprecatedEcdsaVerifier()
	err = deprecatedEcdsa.UnmarshalPublicKey(publicData)
	c.Assert(err, IsNil)
	c.Assert(deprecatedEcdsa.Verify(msg, sig), IsNil)
}

func (DeprecatedECDSASuite) TestECDSAVerifyMismatchMessage(c *C) {
	signer, err := generatedDeprecatedSigner()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	deprecatedEcdsa := NewDeprecatedEcdsaVerifier()
	err = deprecatedEcdsa.UnmarshalPublicKey(publicData)
	c.Assert(err, IsNil)
	c.Assert(deprecatedEcdsa.Verify([]byte("notfoo"), sig), ErrorMatches, "tuf: deprecated ecdsa signature verification failed")
}

func (DeprecatedECDSASuite) TestECDSAVerifyMismatchPubKey(c *C) {
	signer, err := generatedDeprecatedSigner()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)

	signerNew, err := generatedDeprecatedSigner()
	c.Assert(err, IsNil)
	deprecatedEcdsa := NewDeprecatedEcdsaVerifier()
	err = deprecatedEcdsa.UnmarshalPublicKey(signerNew.PublicData())
	c.Assert(err, IsNil)
	c.Assert(deprecatedEcdsa.Verify([]byte("notfoo"), sig), ErrorMatches, "tuf: deprecated ecdsa signature verification failed")
}

func (DeprecatedECDSASuite) TestMarshalUnmarshalPublicKey(c *C) {
	signer, err := generatedDeprecatedSigner()
	c.Assert(err, IsNil)

	pub := signer.PublicData()

	deprecatedEcdsa := NewDeprecatedEcdsaVerifier()
	err = deprecatedEcdsa.UnmarshalPublicKey(pub)
	c.Assert(err, IsNil)

	c.Assert(deprecatedEcdsa.MarshalPublicKey(), DeepEquals, pub)
}
