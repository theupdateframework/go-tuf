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
	"crypto"
	"crypto/rsa"
	"github.com/sigstore/sigstore/pkg/signature"
)

func verifyMetadataSignature(publicKey crypto.PublicKey, hash crypto.Hash, keyType string, sig, payload []byte) error {
	var verifier signature.Verifier
	var err error
	if keyType == KeyTypeRSASSA_PSS_SHA256 {
		publicKeyRSAPSS, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return &ErrType{Msg: "failed to convert public key to RSA PSS key"}
		}
		verifier, err = signature.LoadRSAPSSVerifier(publicKeyRSAPSS, hash, &rsa.PSSOptions{Hash: crypto.SHA256})
	} else {
		verifier, err = signature.LoadVerifier(publicKey, hash)
	}
	if err != nil {
		return err
	}
	return verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload))
}
