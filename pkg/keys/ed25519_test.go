package keys

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"

	fuzz "github.com/google/gofuzz"
	"github.com/theupdateframework/go-tuf/data"
	. "gopkg.in/check.v1"
)

type Ed25519Suite struct{}

var _ = Suite(&Ed25519Suite{})

func (Ed25519Suite) TestUnmarshalEd25519(c *C) {
	pub, _, _ := ed25519.GenerateKey(strings.NewReader("00001-deterministic-buffer-for-key-generation"))

	publicKey, _ := json.Marshal(map[string]string{
		"public": hex.EncodeToString(pub),
	})
	badKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      publicKey,
	}
	verifier := NewEd25519Verifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), IsNil)
}

func (Ed25519Suite) TestUnmarshalEd25519_Invalid(c *C) {
	badKeyValue, _ := json.Marshal(true)
	badKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      badKeyValue,
	}
	verifier := NewEd25519Verifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, "json: cannot unmarshal.*")
}

func (Ed25519Suite) TestUnmarshalEd25519_FastFuzz(c *C) {
	verifier := NewEd25519Verifier()
	for i := 0; i < 50; i++ {
		// Ensure no basic panic

		f := fuzz.New()
		var publicData data.PublicKey
		f.Fuzz(&publicData)

		verifier.UnmarshalPublicKey(&publicData)
	}
}

func (Ed25519Suite) TestUnmarshalEd25519_TooLongContent(c *C) {
	randomSeed := make(json.RawMessage, 1024*1024)
	io.ReadFull(rand.Reader, randomSeed)

	tooLongPayload, _ := json.Marshal(
		&ed25519Verifier{
			PublicKey: data.HexBytes(randomSeed),
		},
	)

	badKey := &data.PublicKey{
		Type:       data.KeyTypeEd25519,
		Scheme:     data.KeySchemeEd25519,
		Algorithms: data.HashAlgorithms,
		Value:      tooLongPayload,
	}
	verifier := NewEd25519Verifier()
	c.Assert(verifier.UnmarshalPublicKey(badKey), ErrorMatches, ".*: unexpected EOF")
}

func (Ed25519Suite) TestSignVerify(c *C) {
	signer, err := GenerateEd25519Key()
	c.Assert(err, IsNil)
	msg := []byte("foo")
	sig, err := signer.SignMessage(msg)
	c.Assert(err, IsNil)
	publicData := signer.PublicData()
	pubKey, err := GetVerifier(publicData)
	c.Assert(err, IsNil)
	c.Assert(pubKey.Verify(msg, sig), IsNil)
}
