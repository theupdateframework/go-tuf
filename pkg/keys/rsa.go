package keys

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"

	"github.com/pkg/errors"

	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	VerifierMap.Store(data.KeyTypeRSASSA_PSS_SHA256, NewRsaVerifier)
}

func NewRsaVerifier() Verifier {
	return &rsaVerifier{}
}

type rsaVerifier struct {
	PublicKey string `json:"public"`
	rsaKey    *rsa.PublicKey
	key       *data.Key
}

func (p *rsaVerifier) Public() string {
	// Unique public key identifier, use a uniform encodng
	r, err := x509.MarshalPKIXPublicKey(p.rsaKey)
	if err != nil {
		// This shouldn't happen with a valid rsa key, but fallback on the
		// JSON public key string
		return string(p.PublicKey)
	}
	return string(r)
}

func (p *rsaVerifier) Verify(msg, sigBytes []byte) error {
	hash := sha256.Sum256(msg)

	return rsa.VerifyPSS(p.rsaKey, crypto.SHA256, hash[:], sigBytes, &rsa.PSSOptions{})
}

func (p *rsaVerifier) MarshalKey() *data.Key {
	return p.key
}

func (p *rsaVerifier) UnmarshalKey(key *data.Key) error {
	if err := json.Unmarshal(key.Value, p); err != nil {
		return err
	}
	var err error
	p.rsaKey, err = parseKey(p.PublicKey)
	if err != nil {
		return err
	}
	p.key = key
	return nil
}

// parseKey tries to parse a PEM []byte slice by attempting PKCS1 and PKIX in order.
func parseKey(data string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(data))
	if block == nil {
		return nil, errors.New("tuf: pem decoding public key failed")
	}
	rsaPub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return rsaPub, nil
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		rsaPub, ok := key.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("tuf: invalid rsa key")
		}
		return rsaPub, nil
	}
	return nil, errors.New("tuf: error unmarshalling rsa key")
}
