package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	. "gopkg.in/check.v1"

	"github.com/theupdateframework/go-tuf/data"
)

type rsaSigner struct {
	*rsa.PrivateKey
}

type rsaPublic struct {
	// PEM encoded public key.
	PublicKey string `json:"public"`
}

func (s rsaSigner) PublicData() *data.Key {
	pub, _ := x509.MarshalPKIXPublicKey(s.Public().(*rsa.PublicKey))
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pub,
	})

	keyValBytes, _ := json.Marshal(rsaPublic{PublicKey: string(pubBytes)})
	return &data.Key{
		Type:       data.KeyTypeRSASSA_PSS_SHA256,
		Scheme:     data.KeySchemeRSASSA_PSS_SHA256,
		Algorithms: data.KeyAlgorithms,
		Value:      keyValBytes,
	}
}

func (s rsaSigner) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	hash := sha256.Sum256(msg)
	return rsa.SignPSS(rand, s.PrivateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{})
}

func (s rsaSigner) IDs() []string {
	return s.PublicData().IDs()
}

func (s rsaSigner) ContainsID(id string) bool {
	return s.PublicData().ContainsID(id)
}

func (rsaSigner) MarshalSigner() (*data.PrivateKey, error) {
	return nil, errors.New("not implemented for test")
}

func (rsaSigner) UnmarshalSigner(key *data.PrivateKey) error {
	return errors.New("not implemented for test")
}

func GenerateRsaKey() (*rsaSigner, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &rsaSigner{privkey}, nil
}

type RsaSuite struct{}

var _ = Suite(&RsaSuite{})

func (RsaSuite) TestSignVerify(c *C) {
	key, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := key.Sign(rand.Reader, msg, crypto.Hash(0))
	c.Assert(err, IsNil)
	publicData := key.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}

func (RsaSuite) TestMarshalUnmarshal(c *C) {
	key, err := GenerateRsaKey()
	c.Assert(err, IsNil)
	publicData := key.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.MarshalKey(), DeepEquals, publicData)
}
