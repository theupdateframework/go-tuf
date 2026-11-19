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
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// writeKeyPair stores a new Ed25519 key pair as PEM files (PKCS #8 and PKIX,
// the same encodings "openssl genpkey" and "openssl pkey -pubout" produce) and
// returns their paths.
func writeKeyPair(dir string) (privatePath, publicPath string, err error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	privatePEM, err := cryptoutils.MarshalPrivateKeyToPEM(private)
	if err != nil {
		return "", "", err
	}
	publicPEM, err := cryptoutils.MarshalPublicKeyToPEM(public)
	if err != nil {
		return "", "", err
	}
	privatePath = filepath.Join(dir, "targets_key")
	publicPath = filepath.Join(dir, "targets_key.pub")
	if err := os.WriteFile(privatePath, privatePEM, 0600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(publicPath, publicPEM, 0644); err != nil {
		return "", "", err
	}
	return privatePath, publicPath, nil
}

// Load PEM encoded keys from files and use them to sign and verify metadata.
// go-tuf has no key file format of its own: reading the file and decoding the
// PEM with sigstore's cryptoutils package yields a crypto.PrivateKey or a
// crypto.PublicKey, and from there on it is signature.LoadSigner and
// metadata.KeyFromPublicKey.
func ExampleMetadata_Sign_keyFromFile() {
	dir, err := os.MkdirTemp("", "go-tuf-keys")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	privatePath, publicPath, err := writeKeyPair(dir)
	if err != nil {
		panic(err)
	}

	// Private key: file -> crypto.PrivateKey -> signature.Signer.
	// Pass a cryptoutils.PassFunc instead of SkipPassword if the key is
	// encrypted.
	privatePEM, err := os.ReadFile(privatePath)
	if err != nil {
		panic(err)
	}
	privateKey, err := cryptoutils.UnmarshalPEMToPrivateKey(privatePEM, cryptoutils.SkipPassword)
	if err != nil {
		panic(err)
	}
	// NOTE: for an RSA key use signature.LoadRSAPSSSigner(key, crypto.SHA256,
	// &rsa.PSSOptions{Hash: crypto.SHA256}) instead, as LoadSigner would
	// return a PKCS #1 v1.5 signer while TUF uses RSASSA-PSS
	signer, err := signature.LoadSigner(privateKey, crypto.SHA256)
	if err != nil {
		panic(err)
	}

	// Public key: file -> crypto.PublicKey -> TUF key
	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		panic(err)
	}
	publicKey, err := cryptoutils.UnmarshalPEMToPublicKey(publicPEM)
	if err != nil {
		panic(err)
	}
	key, err := metadata.KeyFromPublicKey(publicKey)
	if err != nil {
		panic(err)
	}

	// Let root delegate the targets role to the public key and sign targets
	// with the private one
	expires := time.Now().AddDate(0, 0, 7).UTC()
	root := metadata.Root(expires)
	if err := root.Signed.AddKey(key, metadata.TARGETS); err != nil {
		panic(err)
	}
	targets := metadata.Targets(expires)
	if _, err := targets.Sign(signer); err != nil {
		panic(err)
	}

	// ... and back again: TUF key -> crypto.PublicKey
	roundTripped, err := key.ToPublicKey()
	if err != nil {
		panic(err)
	}

	fmt.Println("key type:", key.Type)
	fmt.Println("key scheme:", key.Scheme)
	fmt.Println("public key round trip:", cryptoutils.EqualKeys(publicKey, roundTripped) == nil)
	fmt.Println("verify error:", root.VerifyDelegate(metadata.TARGETS, targets))

	// Output:
	// key type: ed25519
	// key scheme: ed25519
	// public key round trip: true
	// verify error: <nil>
}
