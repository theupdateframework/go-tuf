package metadata

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"golang.org/x/exp/slices"
)

const (
	// MaxJSONKeySize defines the maximum length of a JSON payload.
	MaxJSONKeySize = 512 * 1024 // 512Kb
	KeyIDLength    = sha256.Size * 2

	KeyTypeEd25519           KeyType = "ed25519"
	KeyTypeECDSA_SHA2_P256   KeyType = "ecdsa-sha2-nistp256"
	KeyTypeRSASSA_PSS_SHA256 KeyType = "rsa"

	KeySchemeEd25519           KeyScheme = "ed25519"
	KeySchemeECDSA_SHA2_P256   KeyScheme = "ecdsa-sha2-nistp256"
	KeySchemeRSASSA_PSS_SHA256 KeyScheme = "rsassa-pss-sha256"
)

type helperED25519 struct {
	PublicKey HexBytes `json:"public"`
}
type helperRSAECDSA struct {
	PublicKey crypto.PublicKey `json:"public"`
}

// ToPublicKey generate crypto.PublicKey from metadata type Key
func (k *Key) ToPublicKey() (crypto.PublicKey, error) {
	switch k.Type {
	case KeyTypeRSASSA_PSS_SHA256:
		return k.toPublicKeyRSA()
	case KeyTypeECDSA_SHA2_P256:
		return k.toPublicKeyECDSA()
	case KeyTypeEd25519:
		return k.toPublicKeyED25519()
	}
	return nil, fmt.Errorf("unsupported public key type")
}

// KeyFromPublicKey generate metadata type Key from crypto.PublicKey
func KeyFromPublicKey(k crypto.PublicKey) (*Key, error) {
	var b []byte
	var err error
	key := &Key{}
	switch k := k.(type) {
	case *rsa.PublicKey:
		key.Type = KeyTypeRSASSA_PSS_SHA256
		key.Scheme = KeySchemeRSASSA_PSS_SHA256
		// pemKey, err := cryptoutils.MarshalPublicKeyToPEM(k)
		s := &helperRSAECDSA{
			PublicKey: k,
			// PublicKey: string(pemKey),
		}
		b, err = json.Marshal(s)
		if err != nil {
			return nil, err
		}
	case *ecdsa.PublicKey:
		key.Type = KeyTypeECDSA_SHA2_P256
		key.Scheme = KeySchemeECDSA_SHA2_P256
		// pemKey, err := cryptoutils.MarshalPublicKeyToPEM(k)
		s := &helperRSAECDSA{
			PublicKey: k,
			// PublicKey: string(pemKey),
		}
		b, err = json.Marshal(s)
		if err != nil {
			return nil, err
		}
	case ed25519.PublicKey:
		key.Type = KeyTypeEd25519
		key.Scheme = KeySchemeEd25519
		s := &helperED25519{
			PublicKey: []byte(k),
		}
		b, err = json.Marshal(s)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported public key type")
	}
	key.Value = b
	return key, nil
}

// AddKey adds new signing key for delegated role "role"
// keyID: Identifier of the key to be added for “role“.
// key: Signing key to be added for “role“.
// role: Name of the role, for which “key“ is added.
func (signed *RootType) AddKey(key *Key, role string) error {
	// verify role is present
	if _, ok := signed.Roles[role]; !ok {
		return fmt.Errorf("Role %s doesn't exist", role)
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
		return fmt.Errorf("Role %s doesn't exist", role)
	}
	// verify keyID is present for given role
	if !slices.Contains(signed.Roles[role].KeyIDs, keyID) {
		return fmt.Errorf("Key with id %s is not used by %s", keyID, role)
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
				return fmt.Errorf("Key with id %s is not used by %s", keyID, role)
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

func (k *Key) toPublicKeyED25519() (crypto.PublicKey, error) {
	// Prepare decoder limited to 512Kb
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(k.Value), MaxJSONKeySize))
	s := &helperED25519{}
	// Unmarshal key value
	if err := dec.Decode(s); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("the public key is truncated or too large: %w", err)
		}
		return nil, err
	}
	if n := len(s.PublicKey); n != ed25519.PublicKeySize {
		return nil, fmt.Errorf("unexpected public key length for ed25519 key, expected %d, got %d", ed25519.PublicKeySize, n)
	}
	ed25519Key := ed25519.PublicKey(s.PublicKey)
	if _, err := x509.MarshalPKIXPublicKey(ed25519Key); err != nil {
		return nil, fmt.Errorf("marshalling to PKIX key: invalid public key")
	}
	return ed25519Key, nil
}

func (k *Key) toPublicKeyECDSA() (crypto.PublicKey, error) {
	// Prepare decoder limited to 512Kb
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(k.Value), MaxJSONKeySize))
	s := &helperRSAECDSA{}
	// Unmarshal key value
	if err := dec.Decode(s); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("the public key is truncated or too large: %w", err)
		}
		return nil, err
	}
	ecdsaKey, ok := s.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}

	if _, err := x509.MarshalPKIXPublicKey(ecdsaKey); err != nil {
		return nil, fmt.Errorf("marshalling to PKIX key: invalid public key")
	}
	return ecdsaKey, nil
}

func (k *Key) toPublicKeyRSA() (crypto.PublicKey, error) {
	// Prepare decoder limited to 512Kb
	dec := json.NewDecoder(io.LimitReader(bytes.NewReader(k.Value), MaxJSONKeySize))
	s := &helperRSAECDSA{}
	// Unmarshal key value
	if err := dec.Decode(s); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, fmt.Errorf("the public key is truncated or too large: %w", err)
		}
		return nil, err
	}
	rsaKey, ok := s.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("invalid public key")
	}

	if _, err := x509.MarshalPKIXPublicKey(rsaKey); err != nil {
		return nil, fmt.Errorf("marshalling to PKIX key: invalid public key")
	}
	return rsaKey, nil
}

// ID returns the keyID value for the given Key
func (k *Key) ID() string {
	k.idOnce.Do(func() {
		data, err := cjson.EncodeCanonical(k)
		if err != nil {
			panic(fmt.Errorf("tuf: error creating key ID: %w", err))
		}
		digest := sha256.Sum256(data)
		k.id = hex.EncodeToString(digest[:])
	})
	return k.id
}
