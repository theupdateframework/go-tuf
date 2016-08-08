package signed

import (
	"golang.org/x/crypto/ed25519"
)

// Verifier describes the verification interface. Implement this interface
// to add additional verifiers to go-tuf.
type Verifier interface {
	// Verify takes a key, message and signature, all as byte slices,
	// and determines whether the signature is valid for the given
	// key and message.
	Verify(key, msg, sig []byte) error
}

// Verifiers is used to map algorithm names to Verifier instances.
var Verifiers = map[string]Verifier{
	"ed25519": Ed25519Verifier{},
}

// RegisterVerifier provides a convenience function for init() functions
// to register additional verifiers or replace existing ones.
func RegisterVerifier(name string, v Verifier) {
	Verifiers[name] = v
}

// Ed25519Verifier is an implementation of a Verifier that verifies ed25519 signatures
type Ed25519Verifier struct{}

func (v Ed25519Verifier) Verify(key []byte, msg []byte, sig []byte) error {
	if !ed25519.Verify(key, msg, sig) {
		return ErrInvalid
	}
	return nil
}
