// Copyright 2026 The Update Framework Authors
// SPDX-License-Identifier: Apache-2.0

package metadata

import (
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

func (v *keyVerifier) PublicKeyBytes() []byte { return v.encoded }
func (v *keyVerifier) VerifySignature(signature, payload []byte) error {
	prepared, err := preparePayload(&v.key, payload)
	if err != nil {
		return err
	}
	return verifyMetadataSignature(v.public, v.hash, v.key.Type, signature, prepared)
}
