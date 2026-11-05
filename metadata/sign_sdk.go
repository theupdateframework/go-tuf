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

// Sign create signature over Signed and assign it to Signatures
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
	// build signature
	sig := &Signature{
		KeyID:     keyID,
		Signature: sb,
	}
	// update the Signatures part
	meta.Signatures = append(meta.Signatures, *sig)
	// return the new signature
	log.Info("Signed metadata with key", "ID", keyID)
	return sig, nil
}
