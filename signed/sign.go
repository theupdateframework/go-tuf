package signed

import (
	"github.com/agl/ed25519"
	"github.com/flynn/go-tuf/data"
	"github.com/tent/canonical-json-go"
)

func Sign(s *data.Signed, k *data.Key) {
	priv := [ed25519.PrivateKeySize]byte{}
	copy(priv[:], k.Value.Private)
	sig := ed25519.Sign(&priv, s.Signed)
	s.Signatures = append(s.Signatures, data.Signature{
		KeyID:     k.ID(),
		Method:    "ed25519",
		Signature: sig[:],
	})
}

func Marshal(v interface{}, keys ...*data.Key) (*data.Signed, error) {
	b, err := cjson.Marshal(v)
	if err != nil {
		return nil, err
	}
	s := &data.Signed{Signed: b}
	for _, k := range keys {
		Sign(s, k)
	}
	return s, nil
}
