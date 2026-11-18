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

package metadata_test

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// opaqueKey only offers Public and Sign, the way a key held by an HSM, a
// hardware token or a KMS does, so nothing can type-assert its way to the
// private key.
type opaqueKey struct {
	key    crypto.Signer
	public crypto.PublicKey
}

func (k opaqueKey) Public() crypto.PublicKey {
	if k.public != nil {
		return k.public
	}
	return k.key.Public()
}

func (k opaqueKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return k.key.Sign(rand, digest, opts)
}

// signTargetsWith delegates the targets role to the signer's public key, signs
// targets metadata with the signer and returns both the delegator and the
// delegate.
func signTargetsWith(t *testing.T, signer *cryptoSigner) (*metadata.Metadata[metadata.RootType], *metadata.Metadata[metadata.TargetsType]) {
	t.Helper()

	key, err := metadata.KeyFromPublicKey(signer.key.Public())
	require.NoError(t, err)
	keyID, err := key.ID()
	require.NoError(t, err)

	expires := time.Now().AddDate(0, 0, 7).UTC()
	root := metadata.Root(expires)
	require.NoError(t, root.Signed.AddKey(key, metadata.TARGETS))

	targets := metadata.Targets(expires)
	sig, err := targets.Sign(signer)
	require.NoError(t, err)
	assert.Equal(t, keyID, sig.KeyID)
	assert.Equal(t, []metadata.Signature{*sig}, targets.Signatures)

	return root, targets
}

// TestSignWithExternalSigner ensures that Sign only relies on the
// signature.Signer interface, i.e. that metadata can be signed with keys
// go-tuf has no access to.
func TestSignWithExternalSigner(t *testing.T) {
	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mldsaKey, err := mldsa.GenerateKey(mldsa.MLDSA65())
	require.NoError(t, err)

	for _, tc := range []struct {
		name   string
		key    crypto.Signer
		opts   crypto.SignerOpts
		scheme string
	}{
		{"ed25519", ed25519Key, crypto.Hash(0), metadata.KeySchemeEd25519},
		{"ecdsa", ecdsaKey, crypto.SHA256, metadata.KeySchemeECDSA_SHA2_P256},
		{"rsa-pss", rsaKey, &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}, metadata.KeySchemeRSASSA_PSS_SHA256},
		{"ml-dsa", mldsaKey, crypto.Hash(0), metadata.KeySchemeMLDSA65},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := &cryptoSigner{key: opaqueKey{key: tc.key}, opts: tc.opts}
			root, targets := signTargetsWith(t, signer)
			assert.Equal(t, tc.scheme, root.Signed.Keys[targets.Signatures[0].KeyID].Scheme)
			assert.NoError(t, root.VerifyDelegate(metadata.TARGETS, targets))

			// the signature covers the signed content
			targets.Signed.Version++
			assert.ErrorIs(t, root.VerifyDelegate(metadata.TARGETS, targets), &metadata.ErrUnsignedMetadata{})
		})
	}

	// TUF uses RSASSA-PSS, so a signer producing PKCS #1 v1.5 signatures
	// gets to sign, but what it returns does not verify
	t.Run("rsa-pkcs1v15", func(t *testing.T) {
		signer := &cryptoSigner{key: opaqueKey{key: rsaKey}, opts: crypto.SHA256}
		root, targets := signTargetsWith(t, signer)
		assert.ErrorIs(t, root.VerifyDelegate(metadata.TARGETS, targets), &metadata.ErrUnsignedMetadata{})
	})

	// the TUF key is derived from the signer's public key, so its type has
	// to be one of those KeyFromPublicKey knows
	t.Run("unsupported public key type", func(t *testing.T) {
		ecdhKey, err := ecdh.X25519().GenerateKey(rand.Reader)
		require.NoError(t, err)
		signer := &cryptoSigner{key: opaqueKey{key: ed25519Key, public: ecdhKey.PublicKey()}, opts: crypto.Hash(0)}

		targets := metadata.Targets()
		_, err = targets.Sign(signer)
		assert.ErrorContains(t, err, "unsupported public key type")
		assert.Empty(t, targets.Signatures)
	})
}
