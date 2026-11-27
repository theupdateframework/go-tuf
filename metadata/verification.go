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

package metadata

import (
	"bytes"
	"crypto"
	"crypto/x509"
)

// NewVerifier constructs the default verifier for a TUF key. The standard build
// uses the signing SDK; tuf_client uses native Go verification. Applications
// can wrap this ordinary constructor to enforce their own algorithm policy.
func NewVerifier(key *Key) (Verifier, error) {
	public, err := key.ToPublicKey()
	if err != nil {
		return nil, err
	}
	encoded, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	hash := crypto.Hash(0)
	if key.Type != KeyTypeEd25519 && key.Type != KeyTypeMLDSA {
		switch key.Scheme {
		case KeySchemeECDSA_SHA2_P256:
			hash = crypto.SHA256
		case KeySchemeECDSA_SHA2_P384:
			hash = crypto.SHA384
		default:
			hash = crypto.SHA256
		}
	}
	return &keyVerifier{key: *key, public: public, encoded: encoded, hash: hash}, nil
}

type keyVerifier struct {
	key     Key
	public  crypto.PublicKey
	encoded []byte
	hash    crypto.Hash
}

func (v *keyVerifier) PublicKeyBytes() []byte { return bytes.Clone(v.encoded) }
func (v *keyVerifier) VerifySignature(signature, payload []byte) error {
	prepared, err := preparePayload(&v.key, payload)
	if err != nil {
		return err
	}
	return verifyMetadataSignature(v.public, v.hash, v.key.Type, signature, prepared)
}
