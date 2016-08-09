package signed

import (
	"github.com/flynn/go-tuf/data"
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
	data.KeyTypeEd25519: ed25519Verifier{},
}

// RegisterVerifier provides a convenience function for init() functions
// to register additional verifiers or replace existing ones.
func RegisterVerifier(name string, v Verifier) {
	Verifiers[name] = v
}

type ed25519Verifier struct{}

func (ed25519Verifier) Verify(key, msg, sig []byte) error {
	if !ed25519.Verify(key, msg, sig) {
		return ErrInvalid
	}
	return nil
}

func (ed25519Verifier) ValidKey(k []byte) {
	return len(k) == ed25519.PublicKeySize
}
