// Copyright 2022-2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

package metadata

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"golang.org/x/exp/slices"
)

const (
	KeyTypeEd25519             = "ed25519"
	KeyTypeECDSA_SHA2_P256     = "ecdsa-sha2-nistp256"
	KeyTypeRSASSA_PSS_SHA256   = "rsa"
	KeySchemeEd25519           = "ed25519"
	KeySchemeECDSA_SHA2_P256   = "ecdsa-sha2-nistp256"
	KeySchemeRSASSA_PSS_SHA256 = "rsassa-pss-sha256"
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
		if _, err := x509.MarshalPKIXPublicKey(rsaKey); err != nil {
			return nil, err
		}
		return rsaKey, nil
	case KeyTypeECDSA_SHA2_P256:
		publicKey, err := cryptoutils.UnmarshalPEMToPublicKey([]byte(k.Value.PublicKey))
		if err != nil {
			return nil, err
		}
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("invalid ecdsa public key")
		}
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
		if _, err := x509.MarshalPKIXPublicKey(ed25519Key); err != nil {
			return nil, err
		}
		return ed25519Key, nil
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
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
	return key, nil
}

// AddKey adds new signing key for delegated role "role"
// keyID: Identifier of the key to be added for “role“.
// key: Signing key to be added for “role“.
// role: Name of the role, for which “key“ is added.
func (signed *RootType) AddKey(key *Key, role string) error {
	// verify role is present
	if _, ok := signed.Roles[role]; !ok {
		return fmt.Errorf("role %s doesn't exist", role)
	}
	// add keyID to role
	if !slices.Contains(signed.Roles[role].KeyIDs, key.ID()) {
		signed.Roles[role].KeyIDs = append(signed.Roles[role].KeyIDs, key.ID())
	}
	// update Keys
	signed.Keys[key.ID()] = key
	return nil
}

// RevokeKey revoke key from “role“ and updates the Keys store.
// keyID: Identifier of the key to be removed for “role“.
// role: Name of the role, for which a signing key is removed.
func (signed *RootType) RevokeKey(keyID, role string) error {
	// verify role is present
	if _, ok := signed.Roles[role]; !ok {
		return fmt.Errorf("role %s doesn't exist", role)
	}
	// verify keyID is present for given role
	if !slices.Contains(signed.Roles[role].KeyIDs, keyID) {
		return fmt.Errorf("key with id %s is not used by %s", keyID, role)
	}
	// remove keyID from role
	filteredKeyIDs := []string{}
	for _, k := range signed.Roles[role].KeyIDs {
		if k != keyID {
			filteredKeyIDs = append(filteredKeyIDs, k)
		}
	}
	// overwrite the old keyID slice
	signed.Roles[role].KeyIDs = filteredKeyIDs
	// check if keyID is used by other roles too
	for _, r := range signed.Roles {
		if slices.Contains(r.KeyIDs, keyID) {
			return nil
		}
	}
	// delete the keyID from Keys if it's not used anywhere else
	delete(signed.Keys, keyID)
	return nil
}

// AddKey adds new signing key for delegated role "role"
// key: Signing key to be added for “role“.
// role: Name of the role, for which “key“ is added.
func (signed *TargetsType) AddKey(key *Key, role string) error {
	// check if Delegations are even present
	if signed.Delegations == nil {
		return fmt.Errorf("delegated role %s doesn't exist", role)
	}
	// loop through all delegated roles
	for i, d := range signed.Delegations.Roles {
		// if role is found
		if d.Name == role {
			// add key if keyID is not already part of keyIDs for that role
			if !slices.Contains(d.KeyIDs, key.ID()) {
				signed.Delegations.Roles[i].KeyIDs = append(signed.Delegations.Roles[i].KeyIDs, key.ID())
				signed.Delegations.Keys[key.ID()] = key
				return nil
			}
			return fmt.Errorf("delegated role %s already has keyID %s", role, key.ID())
		}
	}
	return fmt.Errorf("delegated role %s doesn't exist", role)
}

// RevokeKey revokes key from delegated role "role" and updates the delegations key store
// keyID: Identifier of the key to be removed for “role“.
// role: Name of the role, for which a signing key is removed.
func (signed *TargetsType) RevokeKey(keyID string, role string) error {
	// check if Delegations are even present
	if signed.Delegations == nil {
		return fmt.Errorf("delegated role %s doesn't exist", role)
	}
	// loop through all delegated roles
	for i, d := range signed.Delegations.Roles {
		// if role is found
		if d.Name == role {
			// check if keyID is present in keyIDs for that role
			if !slices.Contains(d.KeyIDs, keyID) {
				return fmt.Errorf("key with id %s is not used by %s", keyID, role)
			}
			// remove keyID from role
			filteredKeyIDs := []string{}
			for _, k := range signed.Delegations.Roles[i].KeyIDs {
				if k != keyID {
					filteredKeyIDs = append(filteredKeyIDs, k)
				}
			}
			// overwrite the old keyID slice
			signed.Delegations.Roles[i].KeyIDs = filteredKeyIDs
			break
		}
	}
	// check if keyID is used by other roles too
	for _, r := range signed.Delegations.Roles {
		if slices.Contains(r.KeyIDs, keyID) {
			return nil
		}
	}
	// delete the keyID from Keys if it's not used anywhere else
	delete(signed.Delegations.Keys, keyID)
	return nil
}

// ID returns the keyID value for the given Key
func (k *Key) ID() string {
	k.idOnce.Do(func() {
		data, err := cjson.EncodeCanonical(k)
		if err != nil {
			panic(fmt.Errorf("error creating key ID: %w", err))
		}
		digest := sha256.Sum256(data)
		k.id = hex.EncodeToString(digest[:])
	})
	return k.id
}
