package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sync"

	"github.com/theupdateframework/go-tuf/data"
)

func init() {
	KeyMap.Store(data.KeySchemeEd25519, NewP256)
}

func NewP256() Verifier {
	v := ed25519Verifier{}
	return &v
}

type ed25519Verifier struct {
	public ed25519.PublicKey
}

func (e ed25519Verifier) Verify(msg, sig []byte) error {
	if !ed25519.Verify(e.public, msg, sig) {
		return ErrInvalid
	}
	return nil
}

func (e ed25519Verifier) ValidKey(v json.RawMessage) bool {
	if err := json.Unmarshal(v, e.public); err != nil {
		return false
	}
	return len(e.public) == ed25519.PublicKeySize
}

func (k *PrivateKey) Signer() Signer {
	return &ed25519Signer{
		PrivateKey:    ed25519.PrivateKey(k.Value.Private),
		keyType:       k.Type,
		keyScheme:     k.Scheme,
		keyAlgorithms: k.Algorithms,
	}
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

	keyType       string
	keyScheme     string
	keyAlgorithms []string
	ids           []string
	idOnce        sync.Once
}

var _ Signer = &ed25519Signer{}

func (s *ed25519Signer) IDs() []string {
	s.idOnce.Do(func() { s.ids = s.MarshalKey().IDs() })
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

func (s *ed25519Signer) MarshalKey() *data.Key {
	keyValBytes, _ := json.Marshal(data.KeyValue{Public: []byte(s.PrivateKey.Public().(ed25519.PublicKey))})
	return &data.Key{
		Type:       s.keyType,
		Scheme:     s.keyScheme,
		Algorithms: s.keyAlgorithms,
		Value:      keyValBytes,
	}
}

func (s *ed25519Signer) Type() string {
	return s.keyType
}

func (s *ed25519Signer) Scheme() string {
	return s.keyScheme
}
