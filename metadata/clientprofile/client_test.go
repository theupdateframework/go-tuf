//go:build tuf_client

package clientprofile_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"reflect"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func signRoot(t *testing.T, root *metadata.Metadata[metadata.RootType], key *mldsa.PrivateKey, id string) {
	t.Helper()
	encoded, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(encoded)
	payload := append([]byte{'t', 'u', 'f', 1}, digest[:]...)
	signature, err := key.Sign(nil, payload, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = append(root.Signatures, metadata.Signature{KeyID: id, Signature: signature})
}

func TestMLDSAClientProfileVerifiesNativeTAP21AndRejectsTampering(t *testing.T) {
	for _, parameters := range []mldsa.Parameters{mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87()} {
		t.Run(parameters.String(), func(t *testing.T) {
			key, err := mldsa.GenerateKey(parameters)
			if err != nil {
				t.Fatal(err)
			}
			public, err := metadata.KeyFromPublicKey(key.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			root := metadata.Root(time.Now().Add(time.Hour))
			if err := root.Signed.AddKey(public, metadata.ROOT); err != nil {
				t.Fatal(err)
			}
			id, err := public.ID()
			if err != nil {
				t.Fatal(err)
			}
			signRoot(t, root, key, id)
			if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
				t.Fatalf("native TAP21 verification: %v", err)
			}
			root.Signatures[0].Signature[0] ^= 1
			if err := root.VerifyDelegate(metadata.ROOT, root); err == nil {
				t.Fatal("tampered signature accepted")
			}
		})
	}
	if _, present := reflect.TypeOf(metadata.Root()).MethodByName("Sign"); present {
		t.Fatal("publisher signing method is present in the ML-DSA client profile")
	}
}

func TestClientProfileSupportsClassicalKeysAndApplicationPolicy(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	public, err := metadata.KeyFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := metadata.Root(time.Now().Add(time.Hour))
	if err := root.Signed.AddKey(public, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	encoded, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	signature, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	id, err := public.ID()
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: id, Signature: signature}}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		t.Fatal(err)
	}
	if err := root.VerifyDelegateWithVerifier(metadata.ROOT, root, onlyMLDSA); err == nil {
		t.Fatal("application policy accepted ECDSA")
	}
}

func TestMLDSAClientProfileDoesNotCountAliasedKeysTwice(t *testing.T) {
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	public, err := metadata.KeyFromPublicKey(key.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	alias := *public
	alias.Value.PublicKey += "\n"
	root := metadata.Root(time.Now().Add(time.Hour))
	for _, value := range []*metadata.Key{public, &alias} {
		if err := root.Signed.AddKey(value, metadata.ROOT); err != nil {
			t.Fatal(err)
		}
	}
	root.Signed.Roles[metadata.ROOT].Threshold = 2
	for _, value := range []*metadata.Key{public, &alias} {
		id, err := value.ID()
		if err != nil {
			t.Fatal(err)
		}
		signRoot(t, root, key, id)
	}
	if err := root.VerifyDelegate(metadata.ROOT, root); err == nil {
		t.Fatal("one key with two aliases met a two-key threshold")
	}
}

func onlyMLDSA(key *metadata.Key) (metadata.Verifier, error) {
	if key.Type != metadata.KeyTypeMLDSA {
		return nil, errors.New("ML-DSA required")
	}
	return metadata.NewVerifier(key)
}
func onlyEd25519(key *metadata.Key) (metadata.Verifier, error) {
	if key.Type != metadata.KeyTypeEd25519 {
		return nil, errors.New("Ed25519 required")
	}
	return metadata.NewVerifier(key)
}

func TestClientProfilePolicyIsPerTrustInstanceAndChecksRootRotation(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := metadata.Root(time.Now().Add(time.Hour))
	tufKey, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Signed.AddKey(tufKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	id, err := tufKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	sign := func() []byte {
		payload, err := cjson.EncodeCanonical(root.Signed)
		if err != nil {
			t.Fatal(err)
		}
		root.Signatures = []metadata.Signature{{KeyID: id, Signature: ed25519.Sign(key, payload)}}
		data, err := root.ToBytes(false)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	data := sign()
	trusted, err := trustedmetadata.NewWithVerifier(data, onlyEd25519)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedmetadata.NewWithVerifier(data, onlyMLDSA); err == nil {
		t.Fatal("ML-DSA policy accepted an Ed25519 bootstrap")
	}
	// Rotate to ML-DSA with both old-root and new-root signatures: default TUF
	// accepts this valid transition, but the Ed25519-only instance must refuse it.
	root.Signed.Version++
	pq, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pqKey, err := metadata.KeyFromPublicKey(pq.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	root.Signed.Keys = map[string]*metadata.Key{}
	root.Signed.Roles[metadata.ROOT].KeyIDs = nil
	if err := root.Signed.AddKey(pqKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	data = sign() // old root still authorizes this signature using its own key table
	pqID, err := pqKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	signRoot(t, root, pq, pqID)
	data, err = root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trusted.UpdateRoot(data); err == nil {
		t.Fatal("policy was bypassed by root rotation")
	}
	permissive, err := trustedmetadata.New(signOriginalEdRoot(t, pub, key, id))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := permissive.UpdateRoot(data); err != nil {
		t.Fatalf("valid unrestricted rotation refused: %v", err)
	}
}
func signOriginalEdRoot(t *testing.T, pub ed25519.PublicKey, key ed25519.PrivateKey, id string) []byte {
	t.Helper()
	root := metadata.Root(time.Now().Add(time.Hour))
	k, err := metadata.KeyFromPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Signed.AddKey(k, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	payload, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: id, Signature: ed25519.Sign(key, payload)}}
	data, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestClientProfileVerifiesRSAPSS(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := metadata.KeyFromPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	root := metadata.Root(time.Now().Add(time.Hour))
	if err := root.Signed.AddKey(public, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	payload, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	sig, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	id, err := public.ID()
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: id, Signature: sig}}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		t.Fatal(err)
	}
	root.Signatures[0].Signature[0] ^= 1
	if err := root.VerifyDelegate(metadata.ROOT, root); err == nil {
		t.Fatal("tampered RSA-PSS signature accepted")
	}
}

// customVerifier uses real Ed25519 with a new test key type/codec. TUF core
// does not know that type: only this caller-supplied implementation does.
type customVerifier struct {
	public ed25519.PublicKey
	der    []byte
}

func (v *customVerifier) PublicKeyBytes() []byte { return v.der }
func (v *customVerifier) VerifySignature(signature, payload []byte) error {
	if !ed25519.Verify(v.public, payload, signature) {
		return errors.New("invalid custom signature")
	}
	return nil
}
func customConstructor(key *metadata.Key) (metadata.Verifier, error) {
	if key.Type != "test-ed25519-provider" {
		return metadata.NewVerifier(key)
	}
	public, err := hex.DecodeString(key.Value.PublicKey)
	if err != nil {
		return nil, err
	}
	if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("invalid custom key")
	}
	der, err := x509.MarshalPKIXPublicKey(ed25519.PublicKey(public))
	if err != nil {
		return nil, err
	}
	return &customVerifier{public: public, der: der}, nil
}
func TestCallerCanSupplyAnUnknownKeyTypeWithoutChangingTUF(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := metadata.Root(time.Now().Add(time.Hour))
	tufKey := &metadata.Key{Type: "test-ed25519-provider", Scheme: "test-ed25519", Value: metadata.KeyVal{PublicKey: hex.EncodeToString(public)}}
	if err := root.Signed.AddKey(tufKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	id, err := tufKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	payload, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: id, Signature: ed25519.Sign(key, payload)}}
	data, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedmetadata.New(data); err == nil {
		t.Fatal("default verifier accepted an unknown key type")
	}
	if _, err := trustedmetadata.NewWithVerifier(data, customConstructor); err != nil {
		t.Fatal(err)
	}
	root.Signatures[0].Signature[0] ^= 1
	corrupt, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := trustedmetadata.NewWithVerifier(corrupt, customConstructor); err == nil {
		t.Fatal("caller-supplied verifier accepted a tampered bootstrap")
	}
	root.Signatures[0].Signature[0] ^= 1
	// The default and custom key encodings identify the same public key and
	// must not contribute twice to a two-key threshold.
	ordinary, err := metadata.KeyFromPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	if err := root.Signed.AddKey(ordinary, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	root.Signed.Roles[metadata.ROOT].Threshold = 2
	payload, err = cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	ordinaryID, err := ordinary.ID()
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(key, payload)
	root.Signatures = []metadata.Signature{{KeyID: id, Signature: signature}, {KeyID: ordinaryID, Signature: signature}}
	if err := root.VerifyDelegateWithVerifier(metadata.ROOT, root, customConstructor); err == nil {
		t.Fatal("aliases across verifier implementations met a two-key threshold")
	}
}
