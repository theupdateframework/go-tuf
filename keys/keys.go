package keys

import (
	"crypto"
	"errors"
	"sync"

	"github.com/theupdateframework/go-tuf/data"
)

// KeyMap stores mapping between key type strings and verifier constructors.
var KeyMap sync.Map

type SignerVerifier struct {
	Signer   Signer
	Verifier Verifier
}

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

	// This is the public string used as a unique identifier for the verifier instance.
	Public() string

	// IDs returns the TUF key ids
	IDs() []string

	// Verify takes a message and signature, all as byte slices,
	// and determines whether the signature is valid for the given
	// key and message.
	Verify(msg, sig []byte) error

	// Key returns the data.Key object associated with the verifier.
	Key() *data.Key
}

type Signer interface {
	// Marshal into a private key.
	MarshalPrivate() (*data.PrivateKey, error)

	// UnmarshalKey takes private key data to a working Signer implementation for the key type.
	UnmarshalSigner(key *data.PrivateKey) error

	// Returns the public data.Key from the private key
	PublicData() *data.Key

	// IDs returns the TUF key ids
	IDs() []string

	// ContainsID returns if the signer contains the key id
	ContainsID(id string) bool

	// Type returns the TUF key type
	Type() string

	// Scheme returns the TUF key scheme
	Scheme() string

	// Signer is used to sign messages and provides access to the public key.
	// The signer is expected to do its own hashing, so the full message will be
	// provided as the message to Sign with a zero opts.HashFunc().
	crypto.Signer
}

func GetVerifier(key *data.Key) (Verifier, error) {
	st, ok := KeyMap.Load(key.Type)
	if !ok {
		return nil, ErrInvalidKey
	}
	s := st.(func() SignerVerifier)()
	if s.Verifier == nil {
		return nil, ErrInvalidKey
	}
	if err := s.Verifier.UnmarshalKey(key); err != nil {
		return nil, ErrInvalidKey
	}
	return s.Verifier, nil
}

func GetSigner(key *data.PrivateKey) (Signer, error) {
	st, ok := KeyMap.Load(key.Type)
	if !ok {
		return nil, ErrInvalidKey
	}
	s := st.(func() SignerVerifier)()
	if s.Signer == nil {
		return nil, ErrInvalidKey
	}
	if err := s.Signer.UnmarshalSigner(key); err != nil {
		return nil, ErrInvalidKey
	}
	return s.Signer, nil
}
