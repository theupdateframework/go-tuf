//go:build !tuf_client

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
	"bytes"
	"fmt"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Sign creates a signature over Signed and stores it in Signatures. It
// replaces any existing signature from the same key, as a key ID must be
// unique in Signatures. The new signature is verified against the key derived
// from the signer's public key, and if it does not verify an error is returned
// and Signatures is left unchanged.
//
// Any signature.Signer implementation can be used, so the private key does not
// have to be available to go-tuf: it can be held in memory, in a KMS, an HSM
// or a hardware token. The TUF key and its ID are derived from the signer's
// public key through KeyFromPublicKey, so the signer has to return a public
// key type supported by it and a signature matching the resulting key scheme.
func (meta *Metadata[T]) Sign(signer signature.Signer) (*Signature, error) {
	// encode the Signed part to canonical JSON so signatures are consistent
	payload, err := cjson.EncodeCanonical(meta.Signed)
	if err != nil {
		return nil, err
	}
	// get the signer's PublicKey
	publ, err := signer.PublicKey()
	if err != nil {
		return nil, err
	}
	// convert to TUF Key type to get keyID
	key, err := KeyFromPublicKey(publ)
	if err != nil {
		return nil, err
	}
	keyID, err := key.ID()
	if err != nil {
		return nil, err
	}

	payloadToSign, err := preparePayload(key, payload)
	if err != nil {
		return nil, err
	}

	// sign the Signed part
	sb, err := signer.SignMessage(bytes.NewReader(payloadToSign))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", &ErrUnsignedMetadata{Msg: "problem signing metadata"}, err)
	}
	// make sure the signature verifies for the key derived above, i.e. the
	// signer uses the algorithm that the key type and scheme declare
	verifier, err := NewVerifier(key)
	if err != nil {
		return nil, err
	}
	if err := verifier.VerifySignature(sb, payload); err != nil {
		return nil, &ErrUnsignedMetadata{Msg: fmt.Sprintf(
			"signature created with key ID %s does not verify for keytype %s and scheme %s",
			keyID, key.Type, key.Scheme)}
	}
	// build signature
	sig := &Signature{
		KeyID:     keyID,
		Signature: sb,
	}
	// update the Signatures part, replacing any signature from the same key
	// at its position
	signatures := make([]Signature, 0, len(meta.Signatures)+1)
	stored := false
	for _, existing := range meta.Signatures {
		if existing.KeyID != keyID {
			signatures = append(signatures, existing)
		} else if !stored {
			signatures = append(signatures, *sig)
			stored = true
		}
	}
	if !stored {
		signatures = append(signatures, *sig)
	}
	meta.Signatures = signatures
	// return the new signature
	log.Info("Signed metadata with key", "ID", keyID)
	return sig, nil
}
