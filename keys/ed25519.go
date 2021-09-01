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

func NewP256() SignerVerifier {
	sv := SignerVerifier{
		Signer:   &ed25519Signer{},
		Verifier: &ed25519Verifier{},
	}
	return sv
}

type ed25519Verifier struct {
	PublicKey data.HexBytes `json:"public"`
	key       *data.Key
}

func (e ed25519Verifier) Public() string {
	return string(e.PublicKey)
}

func (e ed25519Verifier) Verify(msg, sig []byte) error {
	if !ed25519.Verify([]byte(e.PublicKey), msg, sig) {
		return ErrInvalid
	}
	return nil
}

func (e *ed25519Verifier) ValidKey(v json.RawMessage) bool {
	if err := json.Unmarshal(v, e); err != nil {
		return false
	}
	return len(e.PublicKey) == ed25519.PublicKeySize
}

func (e ed25519Verifier) Key() *data.Key {
	return e.key
}

func (e *ed25519Verifier) UnmarshalKey(key *data.Key) error {
	e.key = key
	return json.Unmarshal(key.Value, e)
}

func (e ed25519Verifier) IDs() []string {
	return e.key.IDs()
}

type ed25519PrivateKeyValue struct {
	Public  data.HexBytes `json:"public"`
	Private data.HexBytes `json:"private"`
}

func GenerateEd25519Key() (*ed25519Signer, error) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return &ed25519Signer{
		PrivateKey:    ed25519.PrivateKey(data.HexBytes(private)),
		keyType:       data.KeyTypeEd25519,
		keyScheme:     data.KeySchemeEd25519,
		keyAlgorithms: data.KeyAlgorithms,
	}, nil
}

func (e ed25519Signer) MarshalPrivate() (*data.PrivateKey, error) {
	valueBytes, err := json.Marshal(ed25519PrivateKeyValue{
		Public:  data.HexBytes([]byte(e.PrivateKey.Public().(ed25519.PublicKey))),
		Private: data.HexBytes(e.PrivateKey),
	})
	if err != nil {
		return nil, err
	}
	return &data.PrivateKey{
		Type:       e.keyType,
		Scheme:     e.keyScheme,
		Algorithms: e.keyAlgorithms,
		Value:      valueBytes,
	}, nil
}

func (e *ed25519Signer) UnmarshalSigner(key *data.PrivateKey) error {
	keyValue := &ed25519PrivateKeyValue{}
	if err := json.Unmarshal(key.Value, keyValue); err != nil {
		return err
	}
	*e = ed25519Signer{
		PrivateKey:    ed25519.PrivateKey(data.HexBytes(keyValue.Private)),
		keyType:       key.Type,
		keyScheme:     key.Scheme,
		keyAlgorithms: key.Algorithms,
	}
	return nil
}

func (e ed25519Signer) PublicData() *data.Key {
	keyValBytes, _ := json.Marshal(ed25519Verifier{PublicKey: []byte(e.PrivateKey.Public().(ed25519.PublicKey))})
	return &data.Key{
		Type:       e.keyType,
		Scheme:     e.keyScheme,
		Algorithms: e.keyAlgorithms,
		Value:      keyValBytes,
	}
}

type ed25519Signer struct {
	ed25519.PrivateKey

	keyType       string
	keyScheme     string
	keyAlgorithms []string
	ids           []string
	idOnce        sync.Once
}

// var _ Signer = &ed25519Signer{}

func (s *ed25519Signer) IDs() []string {
	s.idOnce.Do(func() { s.ids = s.PublicData().IDs() })
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

func (s *ed25519Signer) Type() string {
	return s.keyType
}

func (s *ed25519Signer) Scheme() string {
	return s.keyScheme
}
