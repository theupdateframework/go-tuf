// Copyright 2026 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

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
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/multirepo"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

var errMLDSARequired = errors.New("ML-DSA required")

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
		return nil, errMLDSARequired
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

func TestECDSAP384PKCS1RSAAndDefensiveKeyGuards(t *testing.T) {
	// 1. ECDSA P-384 (SHA-384) verifies cleanly.
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Pub, err := metadata.KeyFromPublicKey(&p384Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if p384Pub.Scheme != metadata.KeySchemeECDSA_SHA2_P384 {
		t.Fatalf("expected P-384 scheme, got %s", p384Pub.Scheme)
	}
	root := metadata.Root(time.Now().Add(time.Hour))
	if err := root.Signed.AddKey(p384Pub, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	payload, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	digest384 := sha512.Sum384(payload)
	sig384, err := ecdsa.SignASN1(rand.Reader, p384Key, digest384[:])
	if err != nil {
		t.Fatal(err)
	}
	p384ID, err := p384Pub.ID()
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: p384ID, Signature: sig384}}
	if err := root.VerifyDelegate(metadata.ROOT, root); err != nil {
		t.Fatalf("P-384 verification failed: %v", err)
	}

	// 2. PKCS#1 "RSA PUBLIC KEY" PEM is accepted alongside PKIX "PUBLIC KEY".
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pkcs1PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey),
	})
	rsaTUFKey := &metadata.Key{
		Type:   metadata.KeyTypeRSASSA_PSS_SHA256,
		Scheme: metadata.KeySchemeRSASSA_PSS_SHA256,
		Value:  metadata.KeyVal{PublicKey: string(pkcs1PEM)},
	}
	rsaRoot := metadata.Root(time.Now().Add(time.Hour))
	if err := rsaRoot.Signed.AddKey(rsaTUFKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	rsaPayload, err := cjson.EncodeCanonical(rsaRoot.Signed)
	if err != nil {
		t.Fatal(err)
	}
	digest256 := sha256.Sum256(rsaPayload)
	rsaSig, err := rsa.SignPSS(rand.Reader, rsaKey, crypto.SHA256, digest256[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	rsaID, err := rsaTUFKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	rsaRoot.Signatures = []metadata.Signature{{KeyID: rsaID, Signature: rsaSig}}
	if err := rsaRoot.VerifyDelegate(metadata.ROOT, rsaRoot); err != nil {
		t.Fatalf("PKCS#1 RSA-PSS verification failed: %v", err)
	}

	// 3. Nil *Key, uninitialized &mldsa.PublicKey{}, and PublicKeyBytes() immutability.
	if _, err := metadata.NewVerifier(nil); !errors.Is(err, &metadata.ErrValue{}) {
		t.Fatalf("expected ErrValue for NewVerifier(nil), got %v", err)
	}
	if _, err := metadata.KeyFromPublicKey(&mldsa.PublicKey{}); err == nil {
		t.Fatal("expected error for uninitialized &mldsa.PublicKey{}")
	}
	v, err := metadata.NewVerifier(p384Pub)
	if err != nil {
		t.Fatal(err)
	}
	b1 := v.PublicKeyBytes()
	b1[0] ^= 0xff
	if v.PublicKeyBytes()[0] == b1[0] {
		t.Fatal("mutating PublicKeyBytes() slice mutated verifier state")
	}

	// 4. Broken Verifier returning nil or empty PublicKeyBytes fails closed with ErrValue.
	err = root.VerifyDelegateWithVerifier(metadata.ROOT, root, func(*metadata.Key) (metadata.Verifier, error) {
		return nil, nil
	})
	if !errors.Is(err, &metadata.ErrValue{}) || errors.Is(err, &metadata.ErrRepository{}) {
		t.Fatalf("expected non-repository ErrValue for nil verifier, got %v", err)
	}
	err = root.VerifyDelegateWithVerifier(metadata.ROOT, root, func(*metadata.Key) (metadata.Verifier, error) {
		return &customVerifier{}, nil
	})
	if !errors.Is(err, &metadata.ErrValue{}) || errors.Is(err, &metadata.ErrRepository{}) {
		t.Fatalf("expected non-repository ErrValue for empty PublicKeyBytes, got %v", err)
	}
}

func TestHybridRolePolicySkipsDisallowedKeysAndWrapsErrorsWhenBelowThreshold(t *testing.T) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edKey, err := metadata.KeyFromPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	edID, err := edKey.ID()
	if err != nil {
		t.Fatal(err)
	}

	pqPriv, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	pqKey, err := metadata.KeyFromPublicKey(pqPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pqID, err := pqKey.ID()
	if err != nil {
		t.Fatal(err)
	}

	// Place the Ed25519 key FIRST in KeyIDs and sign with BOTH keys.
	root := metadata.Root(time.Now().Add(time.Hour))
	if err := root.Signed.AddKey(edKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	if err := root.Signed.AddKey(pqKey, metadata.ROOT); err != nil {
		t.Fatal(err)
	}
	root.Signed.Roles[metadata.ROOT].Threshold = 1

	payload, err := cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: edID, Signature: ed25519.Sign(edPriv, payload)}}
	signRoot(t, root, pqPriv, pqID)

	if err := root.VerifyDelegateWithVerifier(metadata.ROOT, root, onlyMLDSA); err != nil {
		t.Fatalf("expected hybrid role with valid ML-DSA signature to meet threshold=1 regardless of KeyIDs order: %v", err)
	}

	// Raising threshold to 2 requires both keys, so onlyMLDSA must fail with
	// ErrUnsignedMetadata (which is also ErrRepository) wrapping errMLDSARequired.
	root.Signed.Roles[metadata.ROOT].Threshold = 2
	payload, err = cjson.EncodeCanonical(root.Signed)
	if err != nil {
		t.Fatal(err)
	}
	root.Signatures = []metadata.Signature{{KeyID: edID, Signature: ed25519.Sign(edPriv, payload)}}
	signRoot(t, root, pqPriv, pqID)

	err = root.VerifyDelegateWithVerifier(metadata.ROOT, root, onlyMLDSA)
	if !errors.Is(err, &metadata.ErrUnsignedMetadata{}) || !errors.Is(err, &metadata.ErrRepository{}) || !errors.Is(err, errMLDSARequired) {
		t.Fatalf("expected ErrUnsignedMetadata + ErrRepository + errMLDSARequired, got %v", err)
	}
}

func signMetadataEd25519(t *testing.T, signed any, priv ed25519.PrivateKey, keyID string) metadata.Signature {
	t.Helper()
	payload, err := cjson.EncodeCanonical(signed)
	if err != nil {
		t.Fatal(err)
	}
	return metadata.Signature{KeyID: keyID, Signature: ed25519.Sign(priv, payload)}
}

func signMetadataMLDSA(t *testing.T, signed any, priv *mldsa.PrivateKey, keyID string) metadata.Signature {
	t.Helper()
	encoded, err := cjson.EncodeCanonical(signed)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha512.Sum512(encoded)
	payload := append([]byte{'t', 'u', 'f', 1}, digest[:]...)
	sig, err := priv.Sign(nil, payload, &mldsa.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return metadata.Signature{KeyID: keyID, Signature: sig}
}

func TestUpdaterDiamondDelegationCacheRecoveryAndMultiRepoVerifier(t *testing.T) {
	exp := time.Now().UTC().Add(time.Hour).Truncate(time.Second)

	pqPriv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatal(err)
	}
	pqKey, err := metadata.KeyFromPublicKey(pqPriv.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	pqID, err := pqKey.ID()
	if err != nil {
		t.Fatal(err)
	}

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edKey, err := metadata.KeyFromPublicKey(edPub)
	if err != nil {
		t.Fatal(err)
	}
	edID, err := edKey.ID()
	if err != nil {
		t.Fatal(err)
	}

	customEdKey := &metadata.Key{
		Type:   "test-ed25519-provider",
		Scheme: "test-ed25519",
		Value:  metadata.KeyVal{PublicKey: hex.EncodeToString(edPub)},
	}
	customEdID, err := customEdKey.ID()
	if err != nil {
		t.Fatal(err)
	}

	// Build repository with diamond delegation:
	// targets -> parentA (a/*, ML-DSA -> shared) and parentB (b/*, Ed25519 -> shared)
	// and parentC (c/*, custom key type -> shared).
	root := metadata.Root(exp)
	root.Signed.ConsistentSnapshot = false
	for _, r := range []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		if err := root.Signed.AddKey(pqKey, r); err != nil {
			t.Fatal(err)
		}
	}
	root.Signatures = []metadata.Signature{signMetadataMLDSA(t, root.Signed, pqPriv, pqID)}
	rootBytes, err := root.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	targets := metadata.Targets(exp)
	targets.Signed.Delegations = &metadata.Delegations{
		Keys: map[string]*metadata.Key{pqID: pqKey},
		Roles: []metadata.DelegatedRole{
			{Name: "parentA", KeyIDs: []string{pqID}, Threshold: 1, Paths: []string{"a/*"}},
			{Name: "parentB", KeyIDs: []string{pqID}, Threshold: 1, Paths: []string{"b/*"}},
			{Name: "parentC", KeyIDs: []string{pqID}, Threshold: 1, Paths: []string{"c/*"}},
		},
	}
	targets.Signatures = []metadata.Signature{signMetadataMLDSA(t, targets.Signed, pqPriv, pqID)}
	targetsBytes, err := targets.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	makeParent := func(k *metadata.Key, kid, pattern string) []byte {
		p := metadata.Targets(exp)
		p.Signed.Delegations = &metadata.Delegations{
			Keys:  map[string]*metadata.Key{kid: k},
			Roles: []metadata.DelegatedRole{{Name: "shared", KeyIDs: []string{kid}, Threshold: 1, Paths: []string{pattern}}},
		}
		p.Signatures = []metadata.Signature{signMetadataMLDSA(t, p.Signed, pqPriv, pqID)}
		b, err := p.ToBytes(false)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	parentABytes := makeParent(pqKey, pqID, "a/*")
	parentBBytes := makeParent(edKey, edID, "b/*")
	parentCBytes := makeParent(customEdKey, customEdID, "c/*")

	shared := metadata.Targets(exp)
	for _, p := range []string{"a/file.txt", "b/file.txt", "c/file.txt"} {
		tf, err := metadata.TargetFile().FromBytes(p, []byte("ok"))
		if err != nil {
			t.Fatal(err)
		}
		shared.Signed.Targets[p] = tf
	}
	shared.Signatures = []metadata.Signature{
		signMetadataMLDSA(t, shared.Signed, pqPriv, pqID),
		signMetadataEd25519(t, shared.Signed, edPriv, edID),
		signMetadataEd25519(t, shared.Signed, edPriv, customEdID),
	}
	sharedBytes, err := shared.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	snap := metadata.Snapshot(exp)
	snap.Signed.Meta = map[string]*metadata.MetaFiles{
		"targets.json": metadata.MetaFile(1),
		"parentA.json": metadata.MetaFile(1),
		"parentB.json": metadata.MetaFile(1),
		"parentC.json": metadata.MetaFile(1),
		"shared.json":  metadata.MetaFile(1),
	}
	snap.Signatures = []metadata.Signature{signMetadataMLDSA(t, snap.Signed, pqPriv, pqID)}
	snapBytes, err := snap.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	ts := metadata.Timestamp(exp)
	ts.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metadata.MetaFile(1)}
	ts.Signatures = []metadata.Signature{signMetadataMLDSA(t, ts.Signed, pqPriv, pqID)}
	tsBytes, err := ts.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{
		"/1.root.json":    rootBytes,
		"/timestamp.json": tsBytes,
		"/snapshot.json":  snapBytes,
		"/targets.json":   targetsBytes,
		"/parentA.json":   parentABytes,
		"/parentB.json":   parentBBytes,
		"/parentC.json":   parentCBytes,
		"/shared.json":    sharedBytes,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if b, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	// 1. Local cache recovery when cached snapshot.json used a disallowed key
	// (Ed25519) and remote now serves ML-DSA.
	staleSnap := metadata.Snapshot(exp)
	staleSnap.Signed.Meta = map[string]*metadata.MetaFiles{"targets.json": metadata.MetaFile(1)}
	staleSnap.Signatures = []metadata.Signature{signMetadataEd25519(t, staleSnap.Signed, edPriv, edID)}
	staleSnapBytes, err := staleSnap.ToBytes(false)
	if err != nil {
		t.Fatal(err)
	}

	metaDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(metaDir, "snapshot.json"), staleSnapBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	pqCfg, err := config.New(srv.URL, rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	pqCfg.LocalMetadataDir = metaDir
	pqCfg.LocalTargetsDir = t.TempDir()
	pqCfg.NewVerifier = onlyMLDSA

	pqUpdater, err := updater.New(pqCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := pqUpdater.Refresh(); err != nil {
		t.Fatalf("expected Refresh to recover from stale local snapshot rejected by policy: %v", err)
	}

	// 2a. Diamond delegation under onlyMLDSA: parentA (ML-DSA) caches "shared",
	// then parentB (Ed25519) MUST NOT bypass onlyMLDSA via cachedTargets!
	if _, err := pqUpdater.GetTargetInfo("a/file.txt"); err != nil {
		t.Fatalf("parentA ML-DSA delegation failed: %v", err)
	}
	if _, err := pqUpdater.GetTargetInfo("b/file.txt"); err == nil {
		t.Fatal("cachedTargets bypassed onlyMLDSA policy on second delegator parentB")
	}

	// 2b. Diamond delegation under customConstructor: parentA (ML-DSA) caches "shared",
	// then parentC ("test-ed25519-provider") MUST succeed via cachedTargets!
	customCfg, err := config.New(srv.URL, rootBytes)
	if err != nil {
		t.Fatal(err)
	}
	customCfg.LocalMetadataDir = t.TempDir()
	customCfg.LocalTargetsDir = t.TempDir()
	customCfg.NewVerifier = customConstructor

	customUpdater, err := updater.New(customCfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := customUpdater.GetTargetInfo("a/file.txt"); err != nil {
		t.Fatal(err)
	}
	if _, err := customUpdater.GetTargetInfo("c/file.txt"); err != nil {
		t.Fatalf("cachedTargets failed to pass NewVerifier for custom key on parentC: %v", err)
	}

	// 3. MultiRepoConfig propagates NewVerifier to repository Updaters.
	mapBytes, err := json.Marshal(multirepo.MultiRepoMapType{
		Repositories: map[string][]string{"repo1": {srv.URL}},
		Mapping:      []*multirepo.Mapping{{Paths: []string{"*"}, Repositories: []string{"repo1"}, Threshold: 1, Terminating: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mrCfg, err := multirepo.NewConfig(mapBytes, map[string][]byte{"repo1": rootBytes})
	if err != nil {
		t.Fatal(err)
	}
	mrCfg.DisableLocalCache = true
	mrCfg.NewVerifier = onlyEd25519
	if _, err := multirepo.New(mrCfg); err == nil {
		t.Fatal("MultiRepoClient ignored MultiRepoConfig.NewVerifier during bootstrap")
	}
	mrCfg.NewVerifier = onlyMLDSA
	mrClient, err := multirepo.New(mrCfg)
	if err != nil {
		t.Fatalf("MultiRepoClient with matching NewVerifier failed: %v", err)
	}
	if err := mrClient.Refresh(); err != nil {
		t.Fatalf("MultiRepoClient Refresh failed: %v", err)
	}
}
