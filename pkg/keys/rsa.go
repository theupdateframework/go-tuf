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
	"fmt"

	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	VerifierMap.Store(data.KeyTypeRSASSA_PSS_SHA256, newRsaVerifier)
	SignerMap.Store(data.KeyTypeRSASSA_PSS_SHA256, newRsaSigner)
}

func newRsaVerifier() Verifier {
	return &rsaVerifier{}
}

func newRsaSigner() Signer {
	return &rsaSigner{}
}

type rsaVerifier struct {
	PublicKey *data.PKIXPublicKey `json:"public"`
	rsaKey    *rsa.PublicKey
	key       *data.PublicKey
}

func (p *rsaVerifier) Public() string {
	r, _ := x509.MarshalPKIXPublicKey(p.rsaKey)
	return string(r)
}

func (p *rsaVerifier) Verify(msg, sigBytes []byte) error {
	hash := sha256.Sum256(msg)

	return rsa.VerifyPSS(p.rsaKey, crypto.SHA256, hash[:], sigBytes, &rsa.PSSOptions{})
}

func (p *rsaVerifier) MarshalPublicKey() *data.PublicKey {
	return p.key
}

func (p *rsaVerifier) UnmarshalPublicKey(key *data.PublicKey) error {
	if err := json.Unmarshal(key.Value, p); err != nil {
		return err
	}
	rsaKey, ok := p.PublicKey.PublicKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key")
	}
	p.rsaKey = rsaKey
	p.key = key
	return nil
}

type rsaSigner struct {
	*rsa.PrivateKey
}

type rsaPrivateKeyValue struct {
	Private string              `json:"private"`
	Public  *data.PKIXPublicKey `json:"public"`
}

func (s *rsaSigner) PublicData() *data.PublicKey {
	keyValBytes, _ := json.Marshal(rsaVerifier{PublicKey: &data.PKIXPublicKey{PublicKey: s.Public()}})
	return &data.PublicKey{
		Type:       data.KeyTypeRSASSA_PSS_SHA256,
		Scheme:     data.KeySchemeRSASSA_PSS_SHA256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}
}

func (s *rsaSigner) SignMessage(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, s.PrivateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{})
}

func (s *rsaSigner) ContainsID(id string) bool {
	return s.PublicData().ContainsID(id)
}

func (s *rsaSigner) MarshalPrivateKey() (*data.PrivateKey, error) {
	priv := x509.MarshalPKCS1PrivateKey(s.PrivateKey)
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: priv})
	val, err := json.Marshal(rsaPrivateKeyValue{
		Private: string(pemKey),
		Public:  &data.PKIXPublicKey{PublicKey: s.Public()},
	})
	if err != nil {
		return nil, err
	}
	return &data.PrivateKey{
		Type:       data.KeyTypeRSASSA_PSS_SHA256,
		Scheme:     data.KeySchemeRSASSA_PSS_SHA256,
		Algorithms: data.HashAlgorithms,
		Value:      val,
	}, nil
}

func (s *rsaSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	val := rsaPrivateKeyValue{}
	if err := json.Unmarshal(key.Value, &val); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(val.Private))
	if block == nil {
		return errors.New("invalid PEM value")
	}
	if block.Type != "RSA PRIVATE KEY" {
		return fmt.Errorf("invalid block type: %s", block.Type)
	}
	k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	s.PrivateKey = k
	return nil
}

func GenerateRsaKey() (*rsaSigner, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &rsaSigner{privkey}, nil
}
