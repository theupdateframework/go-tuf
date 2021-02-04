package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/theupdateframework/go-tuf/data"
	"golang.org/x/crypto/ed25519"
)

// A Verifier verifies public key signatures.
type Verifier interface {
	// Verify takes a key, message and signature, all as byte slices,
	// and determines whether the signature is valid for the given
	// key and message.
	Verify(key, msg, sig []byte) error

	// ValidKey returns true if the provided public key is valid and usable to
	// verify signatures with this verifier.
	ValidKey([]byte) bool
}

// Verifiers is used to map key types to Verifier instances.
var Verifiers = map[string]Verifier{
	data.KeySchemeEd25519:           ed25519Verifier{},
	data.KeySchemeECDSA_SHA2_P256:   p256Verifier{},
	data.KeySchemeRSASSA_PSS_SHA256: rsaVerifier{},
}

type ed25519Verifier struct{}

func (ed25519Verifier) Verify(key, msg, sig []byte) error {
	if !ed25519.Verify(key, msg, sig) {
		return ErrInvalid
	}
	return nil
}

func (ed25519Verifier) ValidKey(k []byte) bool {
	return len(k) == ed25519.PublicKeySize
}

type ecdsaSignature struct {
	R, S *big.Int
}

type p256Verifier struct{}

func (p256Verifier) Verify(key, msg, sigBytes []byte) error {
	x, y := elliptic.Unmarshal(elliptic.P256(), key)
	k := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     x,
		Y:     y,
	}

	var sig ecdsaSignature
	if _, err := asn1.Unmarshal(sigBytes, &sig); err != nil {
		return ErrInvalid
	}

	hash := sha256.Sum256(msg)

	if !ecdsa.Verify(k, hash[:], sig.R, sig.S) {
		return ErrInvalid
	}
	return nil
}

func (p256Verifier) ValidKey(k []byte) bool {
	x, _ := elliptic.Unmarshal(elliptic.P256(), k)
	return x != nil
}

type rsaVerifier struct{}

func (v rsaVerifier) Verify(key, msg, sig []byte) error {
	digest := sha256.Sum256(msg)
	pub, err := parseKey(key)
	if err != nil {
		return ErrInvalid
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return ErrInvalid
	}

	if err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, digest[:], sig); err != nil {
		return ErrInvalid
	}
	return nil
}

func (v rsaVerifier) ValidKey(k []byte) bool {
	pub, err := parseKey(k)
	if err != nil {
		return false
	}

	if _, ok := pub.(*rsa.PublicKey); !ok {
		return false
	}
	return true
}

// parseKey tries to parse a PEM []byte slice by attempting PKCS8, PKCS1, and PKIX in order.
func parseKey(data []byte) (interface{}, error) {
	key, err := x509.ParsePKCS8PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKCS1PrivateKey(data)
	if err == nil {
		return key, nil
	}
	key, err = x509.ParsePKIXPublicKey(data)
	if err == nil {
		return key, nil
	}
	return nil, ErrInvalid
}
