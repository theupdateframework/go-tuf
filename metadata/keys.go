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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"

	"filippo.io/mldsa"
	mldsax509 "filippo.io/mldsa/x509"
	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
)

const (
	KeyTypeEd25519                = "ed25519"
	KeyTypeECDSA_SHA2_P256_COMPAT = "ecdsa-sha2-nistp256"
	KeyTypeECDSA_SHA2_P256        = "ecdsa"
	KeyTypeRSASSA_PSS_SHA256      = "rsa"
	KeyTypeMLDSA                  = "ml-dsa"
	KeySchemeEd25519              = "ed25519"
	KeySchemeECDSA_SHA2_P256      = "ecdsa-sha2-nistp256"
	KeySchemeECDSA_SHA2_P384      = "ecdsa-sha2-nistp384"
	KeySchemeRSASSA_PSS_SHA256    = "rsassa-pss-sha256"
	KeySchemeMLDSA44              = "ml-dsa-44/1"
	KeySchemeMLDSA65              = "ml-dsa-65/1"
	KeySchemeMLDSA87              = "ml-dsa-87/1"
)

// ToPublicKey generate crypto.PublicKey from metadata type Key
func (k *Key) ToPublicKey() (crypto.PublicKey, error) {
	switch k.Type {
	case KeyTypeRSASSA_PSS_SHA256:
		publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(k.Value.PublicKey))
		if err != nil {
			return nil, err
		}
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid rsa public key")
		}
		// done for verification - ref. https://github.com/theupdateframework/go-tuf/pull/357
		if _, err := x509.MarshalPKIXPublicKey(rsaKey); err != nil {
			return nil, err
		}
		return rsaKey, nil
	case KeyTypeECDSA_SHA2_P256, KeyTypeECDSA_SHA2_P256_COMPAT: // handle "ecdsa" too as python-tuf/sslib keys are using it for keytype instead of https://theupdateframework.github.io/specification/latest/index.html#keytype-ecdsa-sha2-nistp256
		publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(k.Value.PublicKey))
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid ecdsa public key")
		}
		// done for verification - ref. https://github.com/theupdateframework/go-tuf/pull/357
		if _, err := x509.MarshalPKIXPublicKey(ecdsaKey); err != nil {
			return nil, err
		}
		return ecdsaKey, nil
	case KeyTypeEd25519:
		publicKey, err := hex.DecodeString(k.Value.PublicKey)
		if err != nil {
			return nil, err
		}
		ed25519Key := ed25519.PublicKey(publicKey)
		// done for verification - ref. https://github.com/theupdateframework/go-tuf/pull/357
		if _, err := x509.MarshalPKIXPublicKey(ed25519Key); err != nil {
			return nil, err
		}
		return ed25519Key, nil
	case KeyTypeMLDSA:
		block, _ := pem.Decode([]byte(k.Value.PublicKey))
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM block containing public key")
		}
		if block.Type != "PUBLIC KEY" {
			return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
		}
		publicKey, err := mldsax509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		mldsaKey, ok := publicKey.(*mldsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid mldsa public key")
		}
		switch k.Scheme {
		case KeySchemeMLDSA44:
			if mldsaKey.Parameters() != mldsa.MLDSA44() {
				return nil, fmt.Errorf("ML-DSA key parameters mismatch for scheme %s", k.Scheme)
			}
		case KeySchemeMLDSA65:
			if mldsaKey.Parameters() != mldsa.MLDSA65() {
				return nil, fmt.Errorf("ML-DSA key parameters mismatch for scheme %s", k.Scheme)
			}
		case KeySchemeMLDSA87:
			if mldsaKey.Parameters() != mldsa.MLDSA87() {
				return nil, fmt.Errorf("ML-DSA key parameters mismatch for scheme %s", k.Scheme)
			}
		default:
			return nil, fmt.Errorf("unsupported ML-DSA scheme: %s", k.Scheme)
		}
		return mldsaKey, nil
	}
	return nil, fmt.Errorf("unsupported public key type")
}

// KeyFromPublicKey generate metadata type Key from crypto.PublicKey
func KeyFromPublicKey(k crypto.PublicKey) (*Key, error) {
	key := &Key{}
	switch k := k.(type) {
	case *rsa.PublicKey:
		key.Type = KeyTypeRSASSA_PSS_SHA256
		key.Scheme = KeySchemeRSASSA_PSS_SHA256
		pemKey, err := cryptoutils.MarshalPublicKeyToPEM(k)
		if err != nil {
			return nil, err
		}
		key.Value.PublicKey = string(pemKey)
	case *ecdsa.PublicKey:
		key.Type = KeyTypeECDSA_SHA2_P256
		key.Scheme = KeySchemeECDSA_SHA2_P256
		pemKey, err := cryptoutils.MarshalPublicKeyToPEM(k)
		if err != nil {
			return nil, err
		}
		key.Value.PublicKey = string(pemKey)
	case ed25519.PublicKey:
		key.Type = KeyTypeEd25519
		key.Scheme = KeySchemeEd25519
		key.Value.PublicKey = hex.EncodeToString(k)
	case *mldsa.PublicKey:
		key.Type = KeyTypeMLDSA
		switch k.Parameters() {
		case mldsa.MLDSA44():
			key.Scheme = KeySchemeMLDSA44
		case mldsa.MLDSA65():
			key.Scheme = KeySchemeMLDSA65
		case mldsa.MLDSA87():
			key.Scheme = KeySchemeMLDSA87
		default:
			return nil, fmt.Errorf("unsupported mldsa parameters")
		}
		derBytes, err := mldsax509.MarshalPKIXPublicKey(k)
		if err != nil {
			return nil, err
		}
		pemKey := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: derBytes})
		key.Value.PublicKey = string(pemKey)
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
	return key, nil
}

// ID returns the keyID value for the given Key, or an error if the key
// cannot be canonically encoded.
func (k *Key) ID() (string, error) {
	// the identifier is a hexdigest of the SHA-256 hash of the canonical form of the key
	if k.id == "" {
		data, err := cjson.EncodeCanonical(k)
		if err != nil {
			return "", fmt.Errorf("error creating key ID: %w", err)
		}
		digest := sha256.Sum256(data)
		k.id = hex.EncodeToString(digest[:])
	}
	return k.id, nil
}

// extractMLDSAVersion extracts the version byte from a TUF ML-DSA scheme.
// e.g. "ml-dsa-44/1" -> 1
func extractMLDSAVersion(scheme string) (byte, error) {
	parts := strings.Split(scheme, "/")
	if len(parts) != 2 || !strings.HasPrefix(parts[0], "ml-dsa-") {
		return 0, fmt.Errorf("invalid ML-DSA scheme format: %s", scheme)
	}
	v, err := strconv.Atoi(parts[1])
	if err != nil || v < 1 || v > 255 {
		return 0, fmt.Errorf("invalid ML-DSA version in scheme: %s", scheme)
	}
	return byte(v), nil
}
