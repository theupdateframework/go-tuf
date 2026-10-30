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
	"bytes"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

func unmarshalPEMToPublicKey(data []byte) (crypto.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("invalid SubjectPublicKeyInfo")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}
func marshalPublicKeyToPEM(key crypto.PublicKey) ([]byte, error) {
	data, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: data}), nil
}
func validateMLDSAPublicKey(key *mldsa.PublicKey) (mldsa.Parameters, error) {
	if key == nil {
		return mldsa.Parameters{}, fmt.Errorf("nil ML-DSA key")
	}
	switch key.Parameters() {
	case mldsa.MLDSA44(), mldsa.MLDSA65(), mldsa.MLDSA87():
		return key.Parameters(), nil
	}
	return mldsa.Parameters{}, fmt.Errorf("unsupported ML-DSA parameters")
}
