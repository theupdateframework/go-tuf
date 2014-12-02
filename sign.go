package tuf

import (
	"github.com/agl/ed25519"
	"github.com/flynn/tuf/data"
	"github.com/flynn/tuf/keys"
)

func Sign(s *data.Signed, k *keys.Key) {
	sig := ed25519.Sign(k.Private, s.Signed)
	s.Signatures = append(s.Signatures, data.Signature{
		KeyID:     k.ID,
		Method:    "ed25519",
		Signature: sig[:],
	})
}
