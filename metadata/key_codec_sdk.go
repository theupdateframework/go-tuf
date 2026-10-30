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
	"crypto"
	"crypto/mldsa"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

func unmarshalPEMToPublicKey(data []byte) (crypto.PublicKey, error) {
	return cryptoutils.UnmarshalPEMToPublicKey(data)
}
func marshalPublicKeyToPEM(key crypto.PublicKey) ([]byte, error) {
	return cryptoutils.MarshalPublicKeyToPEM(key)
}
func validateMLDSAPublicKey(key *mldsa.PublicKey) (mldsa.Parameters, error) {
	return cryptoutils.ValidateMLDSAPublicKey(key)
}
