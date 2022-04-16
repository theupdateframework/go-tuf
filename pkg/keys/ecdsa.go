package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	VerifierMap.Store(data.KeyTypeECDSA_SHA2_P256, newEcdsaVerifier)
	SignerMap.Store(data.KeyTypeECDSA_SHA2_P256, newEcdsaSigner)
}

func newEcdsaVerifier() Verifier {
	return &ecdsaVerifier{}
}

func newEcdsaSigner() Signer {
	return &ecdsaSigner{}
}

type ecdsaVerifier struct {
	PublicKey *data.PKIXPublicKey `json:"public"`
	ecdsaKey  *ecdsa.PublicKey
	key       *data.PublicKey
}

func (p *ecdsaVerifier) Public() string {
	r, _ := x509.MarshalPKIXPublicKey(p.ecdsaKey)
	return string(r)
}

func (p *ecdsaVerifier) Verify(msg, sigBytes []byte) error {
	hash := sha256.Sum256(msg)

	if !ecdsa.VerifyASN1(p.ecdsaKey, hash[:], sigBytes) {
		return errors.New("signature verification failed")
	}
	return nil
}

func (p *ecdsaVerifier) MarshalPublicKey() *data.PublicKey {
	return p.key
}

func (p *ecdsaVerifier) UnmarshalPublicKey(key *data.PublicKey) error {
	if err := json.Unmarshal(key.Value, p); err != nil {
		return err
	}
	ecdsaKey, ok := p.PublicKey.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("invalid public key")
	}
	p.ecdsaKey = ecdsaKey
	p.key = key
	return nil
}

type ecdsaSigner struct {
	*ecdsa.PrivateKey
}

type ecdsaPrivateKeyValue struct {
	Private string              `json:"private"`
	Public  *data.PKIXPublicKey `json:"public"`
}

func (s *ecdsaSigner) PublicData() *data.PublicKey {
	keyValBytes, _ := json.Marshal(ecdsaVerifier{PublicKey: &data.PKIXPublicKey{PublicKey: s.Public()}})
	return &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}
}

func (s *ecdsaSigner) SignMessage(message []byte) ([]byte, error) {
	hash := sha256.Sum256(message)
	return ecdsa.SignASN1(rand.Reader, s.PrivateKey, hash[:])
}

func (s *ecdsaSigner) MarshalPrivateKey() (*data.PrivateKey, error) {
	priv, err := x509.MarshalECPrivateKey(s.PrivateKey)
	if err != nil {
		return nil, err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: priv})
	val, err := json.Marshal(ecdsaPrivateKeyValue{
		Private: string(pemKey),
		Public:  &data.PKIXPublicKey{PublicKey: s.Public()},
	})
	if err != nil {
		return nil, err
	}
	return &data.PrivateKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      val,
	}, nil
}

func (s *ecdsaSigner) UnmarshalPrivateKey(key *data.PrivateKey) error {
	val := ecdsaPrivateKeyValue{}
	if err := json.Unmarshal(key.Value, &val); err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(val.Private))
	if block == nil {
		return errors.New("invalid PEM value")
	}
	if block.Type != "EC PRIVATE KEY" {
		return fmt.Errorf("invalid block type: %s", block.Type)
	}
	k, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	if k.Curve != elliptic.P256() {
		return errors.New("invalid ecdsa curve")
	}
	s.PrivateKey = k
	return nil
}

func GenerateEcdsaKey() (*ecdsaSigner, error) {
	privkey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return &ecdsaSigner{privkey}, nil
}
