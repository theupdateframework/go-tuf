//go:build tuf_client

// Copyright 2024 The Update Framework Authors
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

package metadata

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"fmt"
)

// The lightweight profile changes the verification implementation, not the
// algorithm policy. Applications choose their policy by supplying or wrapping the verifier constructor.
// Payload domain separation remains in the common preparePayload codec.
func verifyMetadataSignature(publicKey crypto.PublicKey, hash crypto.Hash, _ string, sig, payload []byte) error {
	switch key := publicKey.(type) {
	case *mldsa.PublicKey:
		if _, err := validateMLDSAPublicKey(key); err != nil {
			return err
		}
		return mldsa.Verify(key, payload, sig, &mldsa.Options{})
	case ed25519.PublicKey:
		if len(key) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid ed25519 public key length %d, expected %d", len(key), ed25519.PublicKeySize)
		}
		if ed25519.Verify(key, payload, sig) {
			return nil
		}
		return fmt.Errorf("invalid Ed25519 signature")
	case *ecdsa.PublicKey:
		if key == nil {
			return fmt.Errorf("nil ECDSA public key")
		}
		if !hash.Available() {
			return fmt.Errorf("unsupported ECDSA hash")
		}
		digest := hash.New()
		_, _ = digest.Write(payload)
		if ecdsa.VerifyASN1(key, digest.Sum(nil), sig) {
			return nil
		}
		return fmt.Errorf("invalid ECDSA signature")
	case *rsa.PublicKey:
		if key == nil {
			return fmt.Errorf("nil RSA public key")
		}
		if !hash.Available() {
			return fmt.Errorf("unsupported RSA-PSS hash")
		}
		digest := hash.New()
		_, _ = digest.Write(payload)
		return rsa.VerifyPSS(key, hash, digest.Sum(nil), sig, &rsa.PSSOptions{Hash: hash})
	default:
		return fmt.Errorf("unsupported public key type")
	}
}
