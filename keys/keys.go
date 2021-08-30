package keys

import (
	"crypto"
	"encoding/json"
	"errors"
	"sync"

	"github.com/theupdateframework/go-tuf/data"
)

// KeyMap stores mapping between key type strings and verifier constructors.
var KeyMap sync.Map

var (
	ErrInvalid = errors.New("tuf: signature verification failed")
)

// A Verifier verifies public key signatures.
type Verifier interface {
	// UnmarshalKey takes key data to a working verifier implementation for the key type.
	UnmarshalKey(key data.Key) error

	// This is the public string used as a unique identifier for the verifier instance.
	Public() string

	// Verify takes a message and signature, all as byte slices,
	// and determines whether the signature is valid for the given
	// key and message.
	Verify(msg, sig []byte) error

	// ValidKey returns true if the provided public key is valid and usable to
	// verify signatures with this verifier.
	ValidKey(value json.RawMessage) bool
}

type Signer interface {
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

type PrivateKey struct {
	Type       string          `json:"keytype"`
	Scheme     string          `json:"scheme,omitempty"`
	Algorithms []string        `json:"keyid_hash_algorithms,omitempty"`
	Value      PrivateKeyValue `json:"keyval"`
}

type PrivateKeyValue struct {
	Public  data.HexBytes `json:"public"`
	Private data.HexBytes `json:"private"`
}

func (k *PrivateKey) PublicData() *data.Key {
	return &data.Key{
		Type:       k.Type,
		Scheme:     k.Scheme,
		Algorithms: k.Algorithms,
		Value:      data.KeyValue{Public: k.Value.Public},
	}
}
