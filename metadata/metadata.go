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
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

// Root return new metadata instance of type Root
func Root(expires ...time.Time) *Metadata[RootType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	// populate Roles
	roles := map[string]*Role{}
	for _, r := range []string{ROOT, SNAPSHOT, TARGETS, TIMESTAMP} {
		roles[r] = &Role{
			KeyIDs:    []string{},
			Threshold: 1,
		}
	}
	log.Debugf("Created a metadata of type %s", ROOT)
	return &Metadata[RootType]{
		Signed: RootType{
			Type:               ROOT,
			SpecVersion:        SPECIFICATION_VERSION,
			Version:            1,
			Expires:            expires[0],
			Keys:               map[string]*Key{},
			Roles:              roles,
			ConsistentSnapshot: true,
		},
		Signatures: []Signature{},
	}
}

// Snapshot return new metadata instance of type Snapshot
func Snapshot(expires ...time.Time) *Metadata[SnapshotType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	log.Debugf("Created a metadata of type %s", SNAPSHOT)
	return &Metadata[SnapshotType]{
		Signed: SnapshotType{
			Type:        SNAPSHOT,
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Meta: map[string]*MetaFiles{
				"targets.json": {
					Version: 1,
				},
			},
		},
		Signatures: []Signature{},
	}
}

// Timestamp return new metadata instance of type Timestamp
func Timestamp(expires ...time.Time) *Metadata[TimestampType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	log.Debugf("Created a metadata of type %s", TIMESTAMP)
	return &Metadata[TimestampType]{
		Signed: TimestampType{
			Type:        TIMESTAMP,
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Meta: map[string]*MetaFiles{
				"snapshot.json": {
					Version: 1,
				},
			},
		},
		Signatures: []Signature{},
	}
}

// Targets return new metadata instance of type Targets
func Targets(expires ...time.Time) *Metadata[TargetsType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	log.Debugf("Created a metadata of type %s", TARGETS)
	return &Metadata[TargetsType]{
		Signed: TargetsType{
			Type:        TARGETS,
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Targets:     map[string]*TargetFiles{},
		},
		Signatures: []Signature{},
	}
}

// TargetFile return new metadata instance of type TargetFiles
func TargetFile() *TargetFiles {
	return &TargetFiles{
		Length: 0,
		Hashes: Hashes{},
	}
}

// MetaFile return new metadata instance of type MetaFile
func MetaFile(version int64) *MetaFiles {
	if version < 1 {
		// attempting to set incorrect version
		log.Debugf("Attempting to set incorrect version of %d for MetaFile", version)
		version = 1
	}
	return &MetaFiles{
		Length:  0,
		Hashes:  Hashes{},
		Version: version,
	}
}

// FromFile load metadata from file
func (meta *Metadata[T]) FromFile(name string) (*Metadata[T], error) {
	in, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	m, err := fromBytes[T](data)
	if err != nil {
		return nil, err
	}
	*meta = *m
	log.Debugf("Loaded metadata from file %s", name)
	return meta, nil
}

// FromBytes deserialize metadata from bytes
func (meta *Metadata[T]) FromBytes(data []byte) (*Metadata[T], error) {
	m, err := fromBytes[T](data)
	if err != nil {
		return nil, err
	}
	*meta = *m
	log.Debug("Loaded metadata from bytes")
	return meta, nil
}

// ToBytes serialize metadata to bytes
func (meta *Metadata[T]) ToBytes(pretty bool) ([]byte, error) {
	log.Debug("Writing metadata to bytes")
	if pretty {
		return json.MarshalIndent(*meta, "", "\t")
	}
	return json.Marshal(*meta)
}

// ToFile save metadata to file
func (meta *Metadata[T]) ToFile(name string, pretty bool) error {
	log.Debugf("Writing metadata to file %s", name)
	data, err := meta.ToBytes(pretty)
	if err != nil {
		return err
	}
	return os.WriteFile(name, data, 0644)
}

// Sign create signature over Signed and assign it to Signatures
func (meta *Metadata[T]) Sign(signer signature.Signer) (*Signature, error) {
	// encode the Signed part to canonical JSON so signatures are consistent
	payload, err := cjson.EncodeCanonical(meta.Signed)
	if err != nil {
		return nil, err
	}
	// sign the Signed part
	sb, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return nil, ErrUnsignedMetadata{Msg: "problem signing metadata"}
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
	// build signature
	sig := &Signature{
		KeyID:     key.ID(),
		Signature: sb,
	}
	// update the Signatures part
	meta.Signatures = append(meta.Signatures, *sig)
	// return the new signature
	log.Infof("Signed metadata with key ID: %s", key.ID())
	return sig, nil
}

// VerifyDelegate verifies that delegatedMetadata is signed with the required
// threshold of keys for the delegated role delegatedRole
func (meta *Metadata[T]) VerifyDelegate(delegatedRole string, delegatedMetadata any) error {
	i := any(meta)
	signingKeys := map[string]bool{}
	var keys map[string]*Key
	var roleKeyIDs []string
	var roleThreshold int

	log.Debugf("Verifying %s", delegatedRole)

	// collect keys, keyIDs and threshold based on delegator type
	switch i := i.(type) {
	// Root delegator
	case *Metadata[RootType]:
		keys = i.Signed.Keys
		if role, ok := (*i).Signed.Roles[delegatedRole]; ok {
			roleKeyIDs = role.KeyIDs
			roleThreshold = role.Threshold
		} else {
			// the delegated role was not found, no need to proceed
			return ErrValue{Msg: fmt.Sprintf("no delegation found for %s", delegatedRole)}
		}
	// Targets delegator
	case *Metadata[TargetsType]:
		if i.Signed.Delegations == nil {
			return ErrValue{Msg: "no delegations found"}
		}
		keys = i.Signed.Delegations.Keys
		if i.Signed.Delegations.Roles != nil {
			found := false
			for _, v := range i.Signed.Delegations.Roles {
				if v.Name == delegatedRole {
					found = true
					roleKeyIDs = v.KeyIDs
					roleThreshold = v.Threshold
					break
				}
			}
			// the delegated role was not found, no need to proceed
			if !found {
				return ErrValue{Msg: fmt.Sprintf("no delegation found for %s", delegatedRole)}
			}
		} else if i.Signed.Delegations.SuccinctRoles != nil {
			roleKeyIDs = i.Signed.Delegations.SuccinctRoles.KeyIDs
			roleThreshold = i.Signed.Delegations.SuccinctRoles.Threshold
		}
	default:
		return ErrType{Msg: "call is valid only on delegator metadata (should be either root or targets)"}
	}
	// if there are no keyIDs for that role it means there's no delegation found
	if len(roleKeyIDs) == 0 {
		return ErrValue{Msg: fmt.Sprintf("no delegation found for %s", delegatedRole)}
	}
	// loop through each role keyID
	for _, keyID := range roleKeyIDs {
		key, ok := keys[keyID]
		if !ok {
			return ErrValue{Msg: fmt.Sprintf("key with ID %s not found in %s keyids", keyID, delegatedRole)}
		}
		sign := Signature{}
		var payload []byte
		// convert to a PublicKey type
		publicKey, err := key.ToPublicKey()
		if err != nil {
			return err
		}
		// use corresponding hash function for key type
		hash := crypto.Hash(0)
		if key.Type != KeyTypeEd25519 {
			hash = crypto.SHA256
		}
		// load a verifier based on that key
		verifier, err := signature.LoadVerifier(publicKey, hash)
		if err != nil {
			return err
		}
		// collect the signature for that key and build the payload we'll verify
		// based on the Signed part of the delegated metadata
		switch d := delegatedMetadata.(type) {
		case *Metadata[RootType]:
			for _, signature := range d.Signatures {
				if signature.KeyID == keyID {
					sign = signature
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		case *Metadata[SnapshotType]:
			for _, signature := range d.Signatures {
				if signature.KeyID == keyID {
					sign = signature
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		case *Metadata[TimestampType]:
			for _, signature := range d.Signatures {
				if signature.KeyID == keyID {
					sign = signature
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		case *Metadata[TargetsType]:
			for _, signature := range d.Signatures {
				if signature.KeyID == keyID {
					sign = signature
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		default:
			return ErrType{Msg: "unknown delegated metadata type"}
		}
		// verify if the signature for that payload corresponds to the given key
		if err := verifier.VerifySignature(bytes.NewReader(sign.Signature), bytes.NewReader(payload)); err != nil {
			// failed to verify the metadata with that key ID
			log.Debugf("Failed to verify %s with key ID %s", delegatedRole, keyID)
		} else {
			// save the verified keyID only if verification passed
			signingKeys[keyID] = true
			log.Debugf("Verified %s with key ID %s", delegatedRole, keyID)
		}
	}
	// check if the amount of valid signatures is enough
	if len(signingKeys) < roleThreshold {
		log.Infof("Verifying %s failed, not enough signatures, got %d, want %d", delegatedRole, len(signingKeys), roleThreshold)
		return ErrUnsignedMetadata{Msg: fmt.Sprintf("Verifying %s failed, not enough signatures, got %d, want %d", delegatedRole, len(signingKeys), roleThreshold)}
	}
	log.Infof("Verified %s successfully", delegatedRole)
	return nil
}

// IsExpired returns true if metadata is expired.
// It checks if referenceTime is after Signed.Expires
func (signed *RootType) IsExpired(referenceTime time.Time) bool {
	return referenceTime.After(signed.Expires)
}

// IsExpired returns true if metadata is expired.
// It checks if referenceTime is after Signed.Expires
func (signed *SnapshotType) IsExpired(referenceTime time.Time) bool {
	return referenceTime.After(signed.Expires)
}

// IsExpired returns true if metadata is expired.
// It checks if referenceTime is after Signed.Expires
func (signed *TimestampType) IsExpired(referenceTime time.Time) bool {
	return referenceTime.After(signed.Expires)
}

// IsExpired returns true if metadata is expired.
// It checks if referenceTime is after Signed.Expires
func (signed *TargetsType) IsExpired(referenceTime time.Time) bool {
	return referenceTime.After(signed.Expires)
}

// VerifyLengthHashes checks whether the MetaFiles data matches its corresponding
// length and hashes
func (f *MetaFiles) VerifyLengthHashes(data []byte) error {
	// hashes and length are optional for MetaFiles
	if len(f.Hashes) > 0 {
		err := verifyHashes(data, f.Hashes)
		if err != nil {
			return err
		}
	}
	if f.Length != 0 {
		err := verifyLength(data, f.Length)
		if err != nil {
			return err
		}
	}
	return nil
}

// VerifyLengthHashes checks whether the TargetFiles data matches its corresponding
// length and hashes
func (f *TargetFiles) VerifyLengthHashes(data []byte) error {
	err := verifyHashes(data, f.Hashes)
	if err != nil {
		return err
	}
	err = verifyLength(data, f.Length)
	if err != nil {
		return err
	}
	return nil
}

// FromFile generate TargetFiles from file
func (t *TargetFiles) FromFile(localPath string, hashes ...string) (*TargetFiles, error) {
	log.Debugf("Generating target file from file %s", localPath)
	// open file
	in, err := os.Open(localPath)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	// read file
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return t.FromBytes(localPath, data, hashes...)
}

// FromBytes generate TargetFiles from bytes
func (t *TargetFiles) FromBytes(localPath string, data []byte, hashes ...string) (*TargetFiles, error) {
	log.Debugf("Generating target file from bytes %s", localPath)
	var hasher hash.Hash
	targetFile := &TargetFiles{
		Hashes: map[string]HexBytes{},
	}
	// use default hash algorithm if not set
	if len(hashes) == 0 {
		hashes = []string{"sha256"}
	}
	// calculate length
	len, err := io.Copy(io.Discard, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	targetFile.Length = len
	for _, v := range hashes {
		switch v {
		case "sha256":
			hasher = sha256.New()
		case "sha512":
			hasher = sha512.New()
		default:
			return nil, ErrValue{Msg: fmt.Sprintf("failed generating TargetFile - unsupported hashing algorithm - %s", v)}
		}
		_, err := hasher.Write(data)
		if err != nil {
			return nil, err
		}
		targetFile.Hashes[v] = hasher.Sum(nil)
	}
	targetFile.Path = localPath
	return targetFile, nil
}

// ClearSignatures clears Signatures
func (meta *Metadata[T]) ClearSignatures() {
	log.Debug("Cleared signatures")
	meta.Signatures = []Signature{}
}

// IsDelegatedPath determines whether the given "targetFilepath" is in one of
// the paths that "DelegatedRole" is trusted to provide
func (role *DelegatedRole) IsDelegatedPath(targetFilepath string) (bool, error) {
	if len(role.Paths) > 0 {
		// standard delegations
		for _, pathPattern := range role.Paths {
			return filepath.Match(pathPattern, targetFilepath)
		}
	} else if len(role.PathHashPrefixes) > 0 {
		// hash bin delegations - calculate the hash of the filepath to determine in which bin to find the target.
		targetFilepathHash := sha256.Sum256([]byte(targetFilepath))
		for _, pathHashPrefix := range role.PathHashPrefixes {
			if strings.HasPrefix(string(targetFilepathHash[:]), pathHashPrefix) {
				return true, nil
			}
		}
	}
	return false, nil
}

// GetRolesForTarget return the names and terminating status of all
// delegated roles who are responsible for targetFilepath
func (role *Delegations) GetRolesForTarget(targetFilepath string) map[string]bool {
	res := map[string]bool{}
	// standard delegations
	if role.Roles != nil {
		for _, r := range role.Roles {
			ok, err := r.IsDelegatedPath(targetFilepath)
			if err == nil && ok {
				res[r.Name] = r.Terminating
			}
		}
	} else if role.SuccinctRoles != nil {
		// SuccinctRoles delegations
		res = role.SuccinctRoles.GetRolesForTarget(targetFilepath)
	}
	return res
}

// GetRolesForTarget calculate the name of the delegated role responsible for "targetFilepath".
// The target at path "targetFilepath" is assigned to a bin by casting
// the left-most "BitLength" of bits of the file path hash digest to
// int, using it as bin index between 0 and “2**BitLength - 1“.
func (role *SuccinctRoles) GetRolesForTarget(targetFilepath string) map[string]bool {
	// calculate the suffixLen value based on the total number of bins in
	// hex. If bit_length = 10 then numberOfBins = 1024 or bin names will
	// have a suffix between "000" and "3ff" in hex and suffixLen will be 3
	// meaning the third bin will have a suffix of "003"
	numberOfBins := math.Pow(2, float64(role.BitLength))
	// suffixLen is calculated based on "numberOfBins - 1" as the name
	// of the last bin contains the number "numberOfBins -1" as a suffix.
	suffixLen := len(strconv.FormatInt(int64(numberOfBins-1), 16))

	targetFilepathHash := sha256.Sum256([]byte(targetFilepath))
	// we can't ever need more than 4 bytes (32 bits)
	hashBytes := targetFilepathHash[:4]

	// right shift hash bytes, so that we only have the leftmost
	// bit_length bits that we care about
	shiftValue := 32 - role.BitLength
	binNumber := binary.BigEndian.Uint32(hashBytes) >> shiftValue
	// add zero padding if necessary and cast to hex the suffix
	suffix := fmt.Sprintf("%0*x", suffixLen, binNumber)
	// we consider all succinct_roles as terminating.
	// for more information read TAP 15.
	return map[string]bool{fmt.Sprintf("%s-%s", role.NamePrefix, suffix): true}
}

// GetRoles returns the names of all different delegated roles
func (role *SuccinctRoles) GetRoles() []string {
	res := []string{}
	numberOfBins := int(math.Pow(2, float64(role.BitLength)))
	suffixLen := len(strconv.FormatInt(int64(numberOfBins-1), 16))

	for binNumber := 0; binNumber < numberOfBins; binNumber++ {
		suffix := fmt.Sprintf("%0*x", suffixLen, binNumber)
		res = append(res, fmt.Sprintf("%s-%s", role.NamePrefix, suffix))
	}
	return res
}

// IsDelegatedRole returns whether the given roleName is in one of
// the delegated roles that “SuccinctRoles“ represents
func (role *SuccinctRoles) IsDelegatedRole(roleName string) bool {
	numberOfBins := int64(math.Pow(2, float64(role.BitLength)))
	suffixLen := len(strconv.FormatInt(int64(numberOfBins-1), 16))

	expectedPrefix := fmt.Sprintf("%s-", role.NamePrefix)

	// check if the roleName prefix is what we would expect
	if !strings.HasPrefix(roleName, expectedPrefix) {
		return false
	}

	// check if the roleName suffix length is what we would expect
	suffix := roleName[len(expectedPrefix):]
	if len(suffix) != suffixLen {
		return false
	}

	// make sure suffix is hex value and get bin number
	value, err := strconv.ParseInt(suffix, 16, 64)
	if err != nil {
		return false
	}

	// check if the bin we calculated is indeed within the range of what we support
	return (value >= 0) && (value < numberOfBins)
}

// fromBytes return a *Metadata[T] object from bytes and verifies
// that the data corresponds to the caller struct type
func fromBytes[T Roles](data []byte) (*Metadata[T], error) {
	meta := &Metadata[T]{}
	// verify that the type we used to create the object is the same as the type of the metadata file
	if err := checkType[T](data); err != nil {
		return nil, err
	}
	// if all is okay, unmarshal meta to the desired Metadata[T] type
	if err := json.Unmarshal(data, meta); err != nil {
		return nil, err
	}
	// Make sure signature key IDs are unique
	if err := checkUniqueSignatures(*meta); err != nil {
		return nil, err
	}
	return meta, nil
}

// checkUniqueSignatures verifies if the signature key IDs are unique for that metadata
func checkUniqueSignatures[T Roles](meta Metadata[T]) error {
	signatures := []string{}
	for _, sig := range meta.Signatures {
		if slices.Contains(signatures, sig.KeyID) {
			return ErrValue{Msg: fmt.Sprintf("multiple signatures found for key ID %s", sig.KeyID)}
		}
		signatures = append(signatures, sig.KeyID)
	}
	return nil
}

// checkType verifies if the generic type used to create the object is the same as the type of the metadata file in bytes
func checkType[T Roles](data []byte) error {
	var m map[string]any
	i := any(new(T))
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	signedType := m["signed"].(map[string]any)["_type"].(string)
	switch i.(type) {
	case *RootType:
		if ROOT != signedType {
			return ErrValue{Msg: fmt.Sprintf("expected metadata type %s, got - %s", ROOT, signedType)}
		}
	case *SnapshotType:
		if SNAPSHOT != signedType {
			return ErrValue{Msg: fmt.Sprintf("expected metadata type %s, got - %s", SNAPSHOT, signedType)}
		}
	case *TimestampType:
		if TIMESTAMP != signedType {
			return ErrValue{Msg: fmt.Sprintf("expected metadata type %s, got - %s", TIMESTAMP, signedType)}
		}
	case *TargetsType:
		if TARGETS != signedType {
			return ErrValue{Msg: fmt.Sprintf("expected metadata type %s, got - %s", TARGETS, signedType)}
		}
	default:
		return ErrValue{Msg: fmt.Sprintf("unrecognized metadata type - %s", signedType)}
	}
	// all okay
	return nil
}

// verifyLength verifies if the passed data has the corresponding length
func verifyLength(data []byte, length int64) error {
	len, err := io.Copy(io.Discard, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if length != len {
		return ErrLengthOrHashMismatch{Msg: fmt.Sprintf("length verification failed - expected %d, got %d", length, len)}
	}
	return nil
}

// verifyHashes verifies if the hash of the passed data corresponds to it
func verifyHashes(data []byte, hashes Hashes) error {
	var hasher hash.Hash
	for k, v := range hashes {
		switch k {
		case "sha256":
			hasher = sha256.New()
		case "sha512":
			hasher = sha512.New()
		default:
			return ErrLengthOrHashMismatch{Msg: fmt.Sprintf("hash verification failed - unknown hashing algorithm - %s", k)}
		}
		hasher.Write(data)
		if hex.EncodeToString(v) != hex.EncodeToString(hasher.Sum(nil)) {
			return ErrLengthOrHashMismatch{Msg: fmt.Sprintf("hash verification failed - mismatch for algorithm %s", k)}
		}
	}
	return nil
}

// AddKey adds new signing key for delegated role "role"
// keyID: Identifier of the key to be added for “role“.
// key: Signing key to be added for “role“.
// role: Name of the role, for which “key“ is added.
func (signed *RootType) AddKey(key *Key, role string) error {
	// verify role is present
	if _, ok := signed.Roles[role]; !ok {
		return ErrValue{Msg: fmt.Sprintf("role %s doesn't exist", role)}
	}
	// add keyID to role
	if !slices.Contains(signed.Roles[role].KeyIDs, key.ID()) {
		signed.Roles[role].KeyIDs = append(signed.Roles[role].KeyIDs, key.ID())
	}
	// update Keys
	signed.Keys[key.ID()] = key // TODO: should we check if we don't accidentally override an existing keyID with another key value?
	return nil
}

// RevokeKey revoke key from “role“ and updates the Keys store.
// keyID: Identifier of the key to be removed for “role“.
// role: Name of the role, for which a signing key is removed.
func (signed *RootType) RevokeKey(keyID, role string) error {
	// verify role is present
	if _, ok := signed.Roles[role]; !ok {
		return ErrValue{Msg: fmt.Sprintf("role %s doesn't exist", role)}
	}
	// verify keyID is present for given role
	if !slices.Contains(signed.Roles[role].KeyIDs, keyID) {
		return ErrValue{Msg: fmt.Sprintf("key with id %s is not used by %s", keyID, role)}
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
// If SuccinctRoles is used then the "role" argument can be ignored.
func (signed *TargetsType) AddKey(key *Key, role string) error {
	// check if Delegations are even present
	if signed.Delegations == nil {
		return ErrValue{Msg: fmt.Sprintf("delegated role %s doesn't exist", role)}
	}
	// standard delegated roles
	if signed.Delegations.Roles != nil {
		// loop through all delegated roles
		for i, d := range signed.Delegations.Roles {
			// if role is found
			if d.Name == role {
				// add key if keyID is not already part of keyIDs for that role
				if !slices.Contains(d.KeyIDs, key.ID()) {
					signed.Delegations.Roles[i].KeyIDs = append(signed.Delegations.Roles[i].KeyIDs, key.ID())
					signed.Delegations.Keys[key.ID()] = key // TODO: should we check if we don't accidentally override an existing keyID with another key value?
					return nil
				}
				log.Debugf("Delegated role %s already has keyID %s", role, key.ID())
			}
		}
	} else if signed.Delegations.SuccinctRoles != nil {
		// add key if keyID is not already part of keyIDs for the SuccinctRoles role
		if !slices.Contains(signed.Delegations.SuccinctRoles.KeyIDs, key.ID()) {
			signed.Delegations.SuccinctRoles.KeyIDs = append(signed.Delegations.SuccinctRoles.KeyIDs, key.ID())
			signed.Delegations.Keys[key.ID()] = key // TODO: should we check if we don't accidentally override an existing keyID with another key value?
			return nil
		}
		log.Debugf("SuccinctRoles role already has keyID %s", key.ID())

	}
	return ErrValue{Msg: fmt.Sprintf("delegated role %s doesn't exist", role)}
}

// RevokeKey revokes key from delegated role "role" and updates the delegations key store
// keyID: Identifier of the key to be removed for “role“.
// role: Name of the role, for which a signing key is removed.
func (signed *TargetsType) RevokeKey(keyID string, role string) error {
	// check if Delegations are even present
	if signed.Delegations == nil {
		return ErrValue{Msg: fmt.Sprintf("delegated role %s doesn't exist", role)}
	}
	// standard delegated roles
	if signed.Delegations.Roles != nil {
		// loop through all delegated roles
		for i, d := range signed.Delegations.Roles {
			// if role is found
			if d.Name == role {
				// check if keyID is present in keyIDs for that role
				if !slices.Contains(d.KeyIDs, keyID) {
					return ErrValue{Msg: fmt.Sprintf("key with id %s is not used by %s", keyID, role)}
				}
				// remove keyID from role
				filteredKeyIDs := []string{}
				for _, k := range signed.Delegations.Roles[i].KeyIDs {
					if k != keyID {
						filteredKeyIDs = append(filteredKeyIDs, k)
					}
				}
				// overwrite the old keyID slice for that role
				signed.Delegations.Roles[i].KeyIDs = filteredKeyIDs
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
		}
		// we haven't found the delegated role
		return ErrValue{Msg: fmt.Sprintf("delegated role %s doesn't exist", role)}
	} else if signed.Delegations.SuccinctRoles != nil {
		// check if keyID is used by SuccinctRoles role
		if !slices.Contains(signed.Delegations.SuccinctRoles.KeyIDs, keyID) {
			return ErrValue{Msg: fmt.Sprintf("key with id %s is not used by SuccinctRoles", keyID)}
		}
		// remove keyID from the SuccinctRoles role
		filteredKeyIDs := []string{}
		for _, k := range signed.Delegations.SuccinctRoles.KeyIDs {
			if k != keyID {
				filteredKeyIDs = append(filteredKeyIDs, k)
			}
		}
		// overwrite the old keyID slice for SuccinctRoles role
		signed.Delegations.SuccinctRoles.KeyIDs = filteredKeyIDs

		// delete the keyID from Keys since it can not be used anywhere else
		delete(signed.Delegations.Keys, keyID)
		return nil
	}
	return ErrValue{Msg: fmt.Sprintf("delegated role %s doesn't exist", role)}
}

func (b *HexBytes) UnmarshalJSON(data []byte) error {
	if len(data) < 2 || len(data)%2 != 0 || data[0] != '"' || data[len(data)-1] != '"' {
		return errors.New("tuf: invalid JSON hex bytes")
	}
	res := make([]byte, hex.DecodedLen(len(data)-2))
	_, err := hex.Decode(res, data[1:len(data)-1])
	if err != nil {
		return err
	}
	*b = res
	return nil
}

func (b HexBytes) MarshalJSON() ([]byte, error) {
	res := make([]byte, hex.EncodedLen(len(b))+2)
	res[0] = '"'
	res[len(res)-1] = '"'
	hex.Encode(res[1:], b)
	return res, nil
}

func (b HexBytes) String() string {
	return hex.EncodeToString(b)
}

func (signed RootType) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(signed.UnrecognizedFields) != 0 {
		copyMapValues(signed.UnrecognizedFields, dict)
	}
	dict["_type"] = signed.Type
	dict["spec_version"] = signed.SpecVersion
	dict["consistent_snapshot"] = signed.ConsistentSnapshot
	dict["version"] = signed.Version
	dict["expires"] = signed.Expires
	dict["keys"] = signed.Keys
	dict["roles"] = signed.Roles
	return json.Marshal(dict)
}

func (signed *RootType) UnmarshalJSON(data []byte) error {
	type Alias RootType
	var s Alias
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*signed = RootType(s)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "_type")
	delete(dict, "spec_version")
	delete(dict, "consistent_snapshot")
	delete(dict, "version")
	delete(dict, "expires")
	delete(dict, "keys")
	delete(dict, "roles")
	signed.UnrecognizedFields = dict
	return nil
}

func (signed SnapshotType) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(signed.UnrecognizedFields) != 0 {
		copyMapValues(signed.UnrecognizedFields, dict)
	}
	dict["_type"] = signed.Type
	dict["spec_version"] = signed.SpecVersion
	dict["version"] = signed.Version
	dict["expires"] = signed.Expires
	dict["meta"] = signed.Meta
	return json.Marshal(dict)
}

func (signed *SnapshotType) UnmarshalJSON(data []byte) error {
	type Alias SnapshotType
	var s Alias
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*signed = SnapshotType(s)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "_type")
	delete(dict, "spec_version")
	delete(dict, "version")
	delete(dict, "expires")
	delete(dict, "meta")
	signed.UnrecognizedFields = dict
	return nil
}

func (signed TimestampType) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(signed.UnrecognizedFields) != 0 {
		copyMapValues(signed.UnrecognizedFields, dict)
	}
	dict["_type"] = signed.Type
	dict["spec_version"] = signed.SpecVersion
	dict["version"] = signed.Version
	dict["expires"] = signed.Expires
	dict["meta"] = signed.Meta
	return json.Marshal(dict)
}

func (signed *TimestampType) UnmarshalJSON(data []byte) error {
	type Alias TimestampType
	var s Alias
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*signed = TimestampType(s)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "_type")
	delete(dict, "spec_version")
	delete(dict, "version")
	delete(dict, "expires")
	delete(dict, "meta")
	signed.UnrecognizedFields = dict
	return nil
}

func (signed TargetsType) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(signed.UnrecognizedFields) != 0 {
		copyMapValues(signed.UnrecognizedFields, dict)
	}
	dict["_type"] = signed.Type
	dict["spec_version"] = signed.SpecVersion
	dict["version"] = signed.Version
	dict["expires"] = signed.Expires
	dict["targets"] = signed.Targets
	if signed.Delegations != nil {
		dict["delegations"] = signed.Delegations
	}
	return json.Marshal(dict)
}

func (signed *TargetsType) UnmarshalJSON(data []byte) error {
	type Alias TargetsType
	var s Alias
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*signed = TargetsType(s)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "_type")
	delete(dict, "spec_version")
	delete(dict, "version")
	delete(dict, "expires")
	delete(dict, "targets")
	delete(dict, "delegations")
	signed.UnrecognizedFields = dict
	return nil
}

func (signed *MetaFiles) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(signed.UnrecognizedFields) != 0 {
		copyMapValues(signed.UnrecognizedFields, dict)
	}
	// length and hashes are optional
	if signed.Length != 0 {
		dict["length"] = signed.Length
	}
	if len(signed.Hashes) != 0 {
		dict["hashes"] = signed.Hashes
	}
	dict["version"] = signed.Version
	return json.Marshal(dict)
}

func (signed *MetaFiles) UnmarshalJSON(data []byte) error {
	type Alias MetaFiles
	var s Alias
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*signed = MetaFiles(s)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "length")
	delete(dict, "hashes")
	delete(dict, "version")
	signed.UnrecognizedFields = dict
	return nil
}

func (signed *TargetFiles) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(signed.UnrecognizedFields) != 0 {
		copyMapValues(signed.UnrecognizedFields, dict)
	}
	dict["length"] = signed.Length
	dict["hashes"] = signed.Hashes
	if signed.Custom != nil {
		dict["custom"] = signed.Custom
	}
	return json.Marshal(dict)
}

func (signed *TargetFiles) UnmarshalJSON(data []byte) error {
	type Alias TargetFiles
	var s Alias
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	*signed = TargetFiles(s)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "length")
	delete(dict, "hashes")
	delete(dict, "custom")
	signed.UnrecognizedFields = dict
	return nil
}

func (key *Key) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(key.UnrecognizedFields) != 0 {
		copyMapValues(key.UnrecognizedFields, dict)
	}
	dict["keytype"] = key.Type
	dict["scheme"] = key.Scheme
	dict["keyval"] = key.Value
	return json.Marshal(dict)
}

func (key *Key) UnmarshalJSON(data []byte) error {
	type Alias Key
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	// nolint
	*key = Key(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "keytype")
	delete(dict, "scheme")
	delete(dict, "keyval")
	key.UnrecognizedFields = dict
	return nil
}

func (meta *Metadata[T]) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(meta.UnrecognizedFields) != 0 {
		copyMapValues(meta.UnrecognizedFields, dict)
	}
	dict["signed"] = meta.Signed
	dict["signatures"] = meta.Signatures
	return json.Marshal(dict)
}

func (meta *Metadata[T]) UnmarshalJSON(data []byte) error {
	tmp := any(new(T))
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	switch tmp.(type) {
	case *RootType:
		dict := struct {
			Signed     RootType    `json:"signed"`
			Signatures []Signature `json:"signatures"`
		}{}
		if err := json.Unmarshal(data, &dict); err != nil {
			return err
		}
		var i interface{} = dict.Signed
		meta.Signed = i.(T)
		meta.Signatures = dict.Signatures
	case *SnapshotType:
		dict := struct {
			Signed     SnapshotType `json:"signed"`
			Signatures []Signature  `json:"signatures"`
		}{}
		if err := json.Unmarshal(data, &dict); err != nil {
			return err
		}
		var i interface{} = dict.Signed
		meta.Signed = i.(T)
		meta.Signatures = dict.Signatures
	case *TimestampType:
		dict := struct {
			Signed     TimestampType `json:"signed"`
			Signatures []Signature   `json:"signatures"`
		}{}
		if err := json.Unmarshal(data, &dict); err != nil {
			return err
		}
		var i interface{} = dict.Signed
		meta.Signed = i.(T)
		meta.Signatures = dict.Signatures
	case *TargetsType:
		dict := struct {
			Signed     TargetsType `json:"signed"`
			Signatures []Signature `json:"signatures"`
		}{}
		if err := json.Unmarshal(data, &dict); err != nil {
			return err
		}
		var i interface{} = dict.Signed
		meta.Signed = i.(T)
		meta.Signatures = dict.Signatures
	default:
		return ErrValue{Msg: "unrecognized metadata type"}
	}
	delete(m, "signed")
	delete(m, "signatures")
	meta.UnrecognizedFields = m
	return nil
}

func (s Signature) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(s.UnrecognizedFields) != 0 {
		copyMapValues(s.UnrecognizedFields, dict)
	}
	dict["keyid"] = s.KeyID
	dict["sig"] = s.Signature
	return json.Marshal(dict)
}

func (s *Signature) UnmarshalJSON(data []byte) error {
	type Alias Signature
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*s = Signature(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "keyid")
	delete(dict, "sig")
	s.UnrecognizedFields = dict
	return nil
}

func (kv KeyVal) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(kv.UnrecognizedFields) != 0 {
		copyMapValues(kv.UnrecognizedFields, dict)
	}
	dict["public"] = kv.PublicKey
	return json.Marshal(dict)
}

func (kv *KeyVal) UnmarshalJSON(data []byte) error {
	type Alias KeyVal
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*kv = KeyVal(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "public")
	kv.UnrecognizedFields = dict
	return nil
}

func (role *Role) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(role.UnrecognizedFields) != 0 {
		copyMapValues(role.UnrecognizedFields, dict)
	}
	dict["keyids"] = role.KeyIDs
	dict["threshold"] = role.Threshold
	return json.Marshal(dict)
}

func (role *Role) UnmarshalJSON(data []byte) error {
	type Alias Role
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*role = Role(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "keyids")
	delete(dict, "threshold")
	role.UnrecognizedFields = dict
	return nil
}

func (d *Delegations) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(d.UnrecognizedFields) != 0 {
		copyMapValues(d.UnrecognizedFields, dict)
	}
	// only one is allowed
	dict["keys"] = d.Keys
	if d.Roles != nil {
		dict["roles"] = d.Roles
	} else if d.SuccinctRoles != nil {
		dict["succinct_roles"] = d.SuccinctRoles
	}
	return json.Marshal(dict)
}

func (d *Delegations) UnmarshalJSON(data []byte) error {
	type Alias Delegations
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*d = Delegations(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "keys")
	delete(dict, "roles")
	delete(dict, "succinct_roles")
	d.UnrecognizedFields = dict
	return nil
}

func (role DelegatedRole) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(role.UnrecognizedFields) != 0 {
		copyMapValues(role.UnrecognizedFields, dict)
	}
	dict["name"] = role.Name
	dict["keyids"] = role.KeyIDs
	dict["threshold"] = role.Threshold
	dict["terminating"] = role.Terminating
	// make sure we have only one of the two (per spec)
	if role.Paths != nil && role.PathHashPrefixes != nil {
		return nil, ErrValue{Msg: "failed to marshal: not allowed to have both \"paths\" and \"path_hash_prefixes\" present"}
	}
	if role.Paths != nil {
		dict["paths"] = role.Paths
	} else if role.PathHashPrefixes != nil {
		dict["path_hash_prefixes"] = role.PathHashPrefixes
	}
	return json.Marshal(dict)
}

func (role *DelegatedRole) UnmarshalJSON(data []byte) error {
	type Alias DelegatedRole
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*role = DelegatedRole(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "name")
	delete(dict, "keyids")
	delete(dict, "threshold")
	delete(dict, "terminating")
	delete(dict, "paths")
	delete(dict, "path_hash_prefixes")
	role.UnrecognizedFields = dict
	return nil
}

func (role *SuccinctRoles) MarshalJSON() ([]byte, error) {
	dict := map[string]any{}
	if len(role.UnrecognizedFields) != 0 {
		copyMapValues(role.UnrecognizedFields, dict)
	}
	dict["keyids"] = role.KeyIDs
	dict["threshold"] = role.Threshold
	dict["bit_length"] = role.BitLength
	dict["name_prefix"] = role.NamePrefix
	return json.Marshal(dict)
}

func (role *SuccinctRoles) UnmarshalJSON(data []byte) error {
	type Alias SuccinctRoles
	var a Alias
	if err := json.Unmarshal(data, &a); err != nil {
		return err
	}
	*role = SuccinctRoles(a)

	var dict map[string]any
	if err := json.Unmarshal(data, &dict); err != nil {
		return err
	}
	delete(dict, "keyids")
	delete(dict, "threshold")
	delete(dict, "bit_length")
	delete(dict, "name_prefix")
	role.UnrecognizedFields = dict
	return nil
}

// copyMapValues copies the values of the src map to dst
func copyMapValues(src, dst map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}
