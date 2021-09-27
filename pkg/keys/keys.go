package keys

import (
	"crypto"
	"sync"

	"github.com/pkg/errors"
	"github.com/theupdateframework/go-tuf/data"
)

// SignerMap stores mapping between key type strings and signer constructors.
var SignerMap sync.Map

// Verifier stores mapping between key type strings and verifier constructors.
var VerifierMap sync.Map

var (
	ErrInvalid    = errors.New("tuf: signature verification failed")
	ErrInvalidKey = errors.New("invalid key")
)

// A Verifier verifies public key signatures.
type Verifier interface {
	// UnmarshalKey takes key data to a working verifier implementation for the key type.
	// This performs any validation over the data.Key to ensure that the verifier is usable
	// to verify signatures.
	UnmarshalKey(key *data.Key) error

	// MarshalKey returns the data.Key object associated with the verifier.
	MarshalKey() *data.Key

	// This is the public string used as a unique identifier for the verifier instance.
	Public() string

	// Verify takes a message and signature, all as byte slices,
	// and determines whether the signature is valid for the given
	// key and message.
	Verify(msg, sig []byte) error
}

type Signer interface {
	// MarshalSigner returns the private key data.
	MarshalSigner() (*data.PrivateKey, error)

	// UnmarshalSigner takes private key data to a working Signer implementation for the key type.
	UnmarshalSigner(key *data.PrivateKey) error

	// Returns the public data.Key from the private key
	PublicData() *data.Key

	// Signer is used to sign messages and provides access to the public key.
	// The signer is expected to do its own hashing, so the full message will be
	// provided as the message to Sign with a zero opts.HashFunc().
	crypto.Signer
}

func GetVerifier(key *data.Key) (Verifier, error) {
	st, ok := VerifierMap.Load(key.Type)
	if !ok {
		return nil, ErrInvalidKey
	}
	s := st.(func() Verifier)()
	if err := s.UnmarshalKey(key); err != nil {
		return nil, errors.Wrap(err, "tuf: error unmarshalling key")
	}
	return s, nil
}

func GetSigner(key *data.PrivateKey) (Signer, error) {
	st, ok := SignerMap.Load(key.Type)
	if !ok {
		return nil, ErrInvalidKey
	}
	s := st.(func() Signer)()
	if err := s.UnmarshalSigner(key); err != nil {
		return nil, errors.Wrap(err, "tuf: error unmarshalling key")
	}
	return s, nil
}
