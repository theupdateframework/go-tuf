package sign

import (
	"crypto/rand"
	"sync"

	"github.com/flynn/go-tuf/data"
	"golang.org/x/crypto/ed25519"
)

type PrivateKey struct {
	Type       string          `json:"keytype"`
	Scheme     string          `json:"scheme,omitempty"`
	Algorithms []string        `json:"keyid_hash_algorithms,omitempty"`
	Value      PrivateKeyValue `json:"keyval"`
}

type PrivateKeyValue struct {
	Public data.HexBytes `json:"public"`

	// FIXME(TUF-0.9) This is removed in TUF 1.0, keeping around for
	// compatibility with TUF 0.9.
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

func (k *PrivateKey) Signer() Signer {
	return &ed25519Signer{PrivateKey: ed25519.PrivateKey(k.Value.Private)}
}

func GenerateEd25519Key() (*PrivateKey, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.KeyAlgorithms,
		Value: PrivateKeyValue{
			Public:  data.HexBytes(public),
			Private: data.HexBytes(private),
		},
	}, nil
}

type ed25519Signer struct {
	ed25519.PrivateKey

	ids    []string
	idOnce sync.Once
}

var _ Signer = &ed25519Signer{}

func (s *ed25519Signer) IDs() []string {
	s.idOnce.Do(func() { s.ids = s.publicData().IDs() })
	return s.ids
}

func (s *ed25519Signer) ContainsID(id string) bool {
	for _, keyid := range s.IDs() {
		if id == keyid {
			return true
		}
	}
	return false
}

func (s *ed25519Signer) publicData() *data.Key {
	return &data.Key{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.KeyAlgorithms,
		Value:      data.KeyValue{Public: []byte(s.PrivateKey.Public().(ed25519.PublicKey))},
	}
}

func (s *ed25519Signer) Type() string {
	return data.KeyTypeEd25519
}

func (s *ed25519Signer) Scheme() string {
	return data.KeySchemeEd25519
}
