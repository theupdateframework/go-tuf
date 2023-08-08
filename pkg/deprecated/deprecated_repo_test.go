package deprecated

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	repo "github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/data"
	_ "github.com/theupdateframework/go-tuf/pkg/deprecated/set_ecdsa"
	"github.com/theupdateframework/go-tuf/pkg/keys"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type RepoSuite struct{}

var _ = Suite(&RepoSuite{})

func genKey(c *C, r *repo.Repo, role string) []string {
	keyids, err := r.GenKey(role)
	c.Assert(err, IsNil)
	c.Assert(len(keyids) > 0, Equals, true)
	return keyids
}

// Deprecated ecdsa key support: Support verification against roots that were
// signed with hex-encoded ecdsa keys.
func (rs *RepoSuite) TestDeprecatedHexEncodedKeysSucceed(c *C) {
	type deprecatedP256Verifier struct {
		PublicKey data.HexBytes `json:"public"`
	}
	files := map[string][]byte{"foo.txt": []byte("foo")}
	local := repo.MemoryStore(make(map[string]json.RawMessage), files)
	r, err := repo.NewRepo(local)
	c.Assert(err, IsNil)

	r.Init(false)

	// Add a root key with hex-encoded ecdsa format - compliant "ecdsa"
	signer, err := keys.GenerateEcdsaKey()
	c.Assert(err, IsNil)
	pub := signer.PublicKey
	keyValBytes, err := json.Marshal(&deprecatedP256Verifier{PublicKey: elliptic.Marshal(pub.Curve, pub.X, pub.Y)})
	c.Assert(err, IsNil)
	publicData := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytes,
	}
	err = r.AddVerificationKey("root", publicData)
	c.Assert(err, IsNil)

	// Add a root key with hex-encoded ecdsa format - deprecated "ecdsa-sha2-nistp256"
	signerDeprecated, err := keys.GenerateEcdsaKey()
	c.Assert(err, IsNil)
	pubDeprecated := signerDeprecated.PublicKey
	keyValBytesDeprecated, err := json.Marshal(&deprecatedP256Verifier{PublicKey: elliptic.Marshal(pubDeprecated.Curve, pubDeprecated.X, pubDeprecated.Y)})
	c.Assert(err, IsNil)
	publicDataDeprecated := &data.PublicKey{
		Type:       data.KeyTypeECDSA_SHA2_P256_OLD_FMT,
		Scheme:     data.KeySchemeECDSA_SHA2_P256,
		Algorithms: data.HashAlgorithms,
		Value:      keyValBytesDeprecated,
	}
	err = r.AddVerificationKey("root", publicDataDeprecated)
	c.Assert(err, IsNil)

	// Add other keys as normal
	genKey(c, r, "targets")
	genKey(c, r, "snapshot")
	genKey(c, r, "timestamp")
	c.Assert(r.AddTarget("foo.txt", nil), IsNil)

	// Sign the root role manually
	rootMeta, err := r.SignedMeta("root.json")
	c.Assert(err, IsNil)
	rootCanonical, err := cjson.EncodeCanonical(rootMeta.Signed)
	c.Assert(err, IsNil)
	hash := sha256.Sum256(rootCanonical)
	rootSig, err := signer.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	c.Assert(err, IsNil)
	for _, id := range publicData.IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: rootSig}), IsNil)
	}

	rootSigDeprecated, err := signerDeprecated.PrivateKey.Sign(rand.Reader, hash[:], crypto.SHA256)
	c.Assert(err, IsNil)
	for _, id := range publicDataDeprecated.IDs() {
		c.Assert(r.AddOrUpdateSignature("root.json", data.Signature{
			KeyID:     id,
			Signature: rootSigDeprecated}), IsNil)
	}

	// Committing should succeed because the deprecated key pkg is added.
	c.Assert(r.Snapshot(), IsNil)
	c.Assert(r.Timestamp(), IsNil)
	c.Assert(r.Commit(), IsNil)
}
