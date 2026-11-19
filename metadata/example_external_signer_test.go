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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// cryptoSigner adapts a crypto.Signer to the signature.Signer interface that
// Metadata.Sign expects.
//
// crypto.Signer is what PKCS#11, TPM, PIV (YubiKey) and cloud KMS client
// libraries usually hand out for a key that never leaves the device or the
// service, so an adapter like this one is all it takes to sign TUF metadata
// with such a key.
type cryptoSigner struct {
	key crypto.Signer
	// opts selects what go-tuf verifies for the key type:
	//   - ECDSA:   crypto.SHA256 for a P-256 key, crypto.SHA384 for a P-384 key
	//   - RSA:     &rsa.PSSOptions{Hash: crypto.SHA256, SaltLength: rsa.PSSSaltLengthEqualsHash}
	//   - Ed25519: crypto.Hash(0)
	//   - ML-DSA:  crypto.Hash(0)
	opts crypto.SignerOpts
}

// PublicKey returns the public key go-tuf derives the TUF key and its ID from.
func (s *cryptoSigner) PublicKey(_ ...signature.PublicKeyOption) (crypto.PublicKey, error) {
	return s.key.Public(), nil
}

// SignMessage signs the payload handed over by Metadata.Sign.
func (s *cryptoSigner) SignMessage(message io.Reader, _ ...signature.SignOption) ([]byte, error) {
	payload, err := io.ReadAll(message)
	if err != nil {
		return nil, err
	}
	// crypto.Signer takes a digest, unless the scheme signs the message
	// itself (Ed25519, ML-DSA)
	if hash := s.opts.HashFunc(); hash != crypto.Hash(0) {
		h := hash.New()
		h.Write(payload)
		payload = h.Sum(nil)
	}
	return s.key.Sign(rand.Reader, payload, s.opts)
}

// Sign metadata with a key go-tuf never gets to see, e.g. one held by an HSM,
// a YubiKey, a TPM or a cloud KMS. Metadata.Sign only needs a signature.Signer,
// so any implementation of that interface works: a hand-written one like the
// adapter above, or one of the ready-made sigstore KMS signers
// (https://github.com/sigstore/sigstore/tree/main/pkg/signature/kms).
func ExampleMetadata_Sign_externalSigner() {
	// Stand-in for the external key: from here on it is only reachable
	// through crypto.Signer, i.e. Public() and Sign()
	var externalKey crypto.Signer
	externalKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	signer := &cryptoSigner{key: externalKey, opts: crypto.SHA256}

	// The TUF key (type, scheme, value and key ID) is derived from the
	// public key, so it has to be an RSA, ECDSA, Ed25519 or ML-DSA one
	key, err := metadata.KeyFromPublicKey(externalKey.Public())
	if err != nil {
		panic(err)
	}
	keyID, err := key.ID()
	if err != nil {
		panic(err)
	}

	// Let root delegate the targets role to that key
	expires := time.Now().AddDate(0, 0, 7).UTC()
	root := metadata.Root(expires)
	if err := root.Signed.AddKey(key, metadata.TARGETS); err != nil {
		panic(err)
	}

	// Sign targets with the external signer
	targets := metadata.Targets(expires)
	sig, err := targets.Sign(signer)
	if err != nil {
		panic(err)
	}

	// Sign derives the same key ID from the signer's public key, so the
	// signature can be verified the usual way
	fmt.Println("key type:", key.Type)
	fmt.Println("key scheme:", key.Scheme)
	fmt.Println("signature key ID matches:", sig.KeyID == keyID)
	fmt.Println("verify error:", root.VerifyDelegate(metadata.TARGETS, targets))

	// Output:
	// key type: ecdsa
	// key scheme: ecdsa-sha2-nistp256
	// signature key ID matches: true
	// verify error: <nil>
}
