// Copyright 2022 VMware, Inc.
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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
)

// Root create new metadata instance of type Root
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
	log.Debugf("Created a metadata of type %s expiring at %s", ROOT, expires[0])
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

// Snapshot create new metadata instance of type Snapshot
func Snapshot(expires ...time.Time) *Metadata[SnapshotType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	log.Debugf("Created a metadata of type %s expiring at %s", SNAPSHOT, expires[0])
	return &Metadata[SnapshotType]{
		Signed: SnapshotType{
			Type:        SNAPSHOT,
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Meta: map[string]MetaFiles{
				"targets.json": {
					Version: 1,
				},
			},
		},
		Signatures: []Signature{},
	}
}

// Timestamp create new metadata instance of type Timestamp
func Timestamp(expires ...time.Time) *Metadata[TimestampType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	log.Debugf("Created a metadata of type %s expiring at %s", TIMESTAMP, expires[0])
	return &Metadata[TimestampType]{
		Signed: TimestampType{
			Type:        TIMESTAMP,
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Meta: map[string]MetaFiles{
				"snapshot.json": {
					Version: 1,
				},
			},
		},
		Signatures: []Signature{},
	}
}

// Targets create new metadata instance of type Targets
func Targets(expires ...time.Time) *Metadata[TargetsType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	log.Debugf("Created a metadata of type %s expiring at %s", TARGETS, expires[0])
	return &Metadata[TargetsType]{
		Signed: TargetsType{
			Type:        TARGETS,
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Targets:     map[string]TargetFiles{},
		},
		Signatures: []Signature{},
	}
}

// TargetFile create new metadata instance of type TargetFiles
func TargetFile() *TargetFiles {
	return &TargetFiles{
		Length: 0,
		Hashes: Hashes{},
	}
}

// MetaFile create new metadata instance of type MetaFile
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
	// build signature
	sig := &Signature{
		KeyID:     key.ID(),
		Signature: sb,
	}
	// update the Signatures part
	meta.Signatures = append(meta.Signatures, *sig)
	// return the new signature
	log.Debugf("Signed metadata with key ID: %s", key.ID())
	return sig, nil
}

// VerifyDelegate verifies that “delegated_metadata“ is signed with the required
// threshold of keys for the delegated role “delegated_role“
func (meta *Metadata[T]) VerifyDelegate(delegated_role string, delegated_metadata any) error {
	var keys map[string]*Key
	var roleKeyIDs []string
	var roleThreshold int
	signing_keys := map[string]bool{}
	i := any(meta)
	log.Debugf("Verifying %s", delegated_role)
	// collect keys, keyIDs and threshold based on delegator type
	switch i := i.(type) {
	case *Metadata[RootType]:
		keys = i.Signed.Keys
		if role, ok := (*i).Signed.Roles[delegated_role]; ok {
			roleKeyIDs = role.KeyIDs
			roleThreshold = role.Threshold
		} else {
			return fmt.Errorf("no delegation found for %s", delegated_role)
		}
	case *Metadata[TargetsType]:
		keys = i.Signed.Delegations.Keys
		for _, v := range i.Signed.Delegations.Roles {
			if v.Name == delegated_role {
				roleKeyIDs = v.KeyIDs
				roleThreshold = v.Threshold
				break
			}
		}
	default:
		return fmt.Errorf("call is valid only on delegator metadata (root or targets)")
	}
	// if there are no keyIDs for that role it means there's no delegation found
	if len(roleKeyIDs) == 0 {
		return fmt.Errorf("no delegation found for %s", delegated_role)
	}
	// loop through each role keyID
	for _, v := range roleKeyIDs {
		sign := Signature{}
		payload := []byte{}
		// convert to a PublicKey type
		key, err := keys[v].ToPublicKey()
		if err != nil {
			return err
		}
		// use corresponding hash function for key type
		hash := crypto.Hash(0)
		if keys[v].Type != KeyTypeEd25519 {
			hash = crypto.SHA256
		}
		// load a verifier based on that key
		verifier, err := signature.LoadVerifier(key, hash)
		if err != nil {
			return err
		}
		// collect the signature for that key and build the payload we'll verify
		// based on the Signed part of the delegated metadata
		switch d := delegated_metadata.(type) {
		case *Metadata[RootType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		case *Metadata[SnapshotType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		case *Metadata[TimestampType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		case *Metadata[TargetsType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				return err
			}
		default:
			log.Debugf("unknown delegated metadata type")
		}
		// verify if the signature for that payload corresponds to the given key
		if err := verifier.VerifySignature(bytes.NewReader(sign.Signature), bytes.NewReader(payload)); err == nil {
			// save the verified keyID only if verification passed
			signing_keys[v] = true
			log.Debugf("Verified %s with key ID %s", delegated_role, v)
		}
	}
	// check if the amount of valid signatures is enough
	if len(signing_keys) < roleThreshold {
		log.Debugf("Verifying %s failed, not enough signatures, got %d, want %d", delegated_role, len(signing_keys), roleThreshold)
		return fmt.Errorf("verifying %s failed", delegated_role)

	}
	log.Debugf("Verified %s successfully", delegated_role)
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

// FromFile generates TargetFiles from file
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

// FromBytes generates TargetFiles from bytes
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
			return nil, fmt.Errorf("hash calculation failed - unknown hashing algorithm - %s", v)
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
	log.Debugf("Cleared signatures")
	meta.Signatures = []Signature{}
}

// IsDelegatedPath determines whether the given "targetFilepath" is in one of
// the paths that "DelegatedRole" is trusted to provide
func (role *DelegatedRole) IsDelegatedPath(targetFilepath string) (bool, error) {
	if len(role.PathHashPrefixes) > 0 {
		// TODO
		return false, nil
	} else if len(role.Paths) > 0 {
		for _, pathPattern := range role.Paths {
			return filepath.Match(targetFilepath, pathPattern)
		}
	}
	return false, nil
}

// GetRolesForTarget returns names and terminating status of all
// delegated roles who are responsible for targetFilepath
func (role *Delegations) GetRolesForTarget(targetFilepath string) map[string]bool {
	res := map[string]bool{}
	if len(role.Roles) > 0 {
		for _, r := range role.Roles {
			ok, err := r.IsDelegatedPath(targetFilepath)
			if err == nil && ok {
				res[r.Name] = r.Terminating
			}
		}
	}
	return res
}

// fromBytes returns *Metadata[T] object from bytes and verifies
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

// Verifies if the signature key IDs are unique for that metadata
func checkUniqueSignatures[T Roles](meta Metadata[T]) error {
	signatures := []string{}
	for _, sig := range meta.Signatures {
		if slices.Contains(signatures, sig.KeyID) {
			return fmt.Errorf("multiple signatures found for key ID %s", sig.KeyID)
		}
		signatures = append(signatures, sig.KeyID)
	}
	return nil
}

// Verifies if the Generic type used to create the object is the same as the type of the metadata file in bytes
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
			return fmt.Errorf("expected type %s, got - %s", ROOT, signedType)
		}
	case *SnapshotType:
		if SNAPSHOT != signedType {
			return fmt.Errorf("expected type %s, got - %s", SNAPSHOT, signedType)
		}
	case *TimestampType:
		if TIMESTAMP != signedType {
			return fmt.Errorf("expected type %s, got - %s", TIMESTAMP, signedType)
		}
	case *TargetsType:
		if TARGETS != signedType {
			return fmt.Errorf("expected type %s, got - %s", TARGETS, signedType)
		}
	default:
		return fmt.Errorf("unrecognized metadata type - %s", signedType)
	}
	// all okay
	return nil
}

func verifyLength(data []byte, length int64) error {
	len, err := io.Copy(io.Discard, bytes.NewReader(data))
	if err != nil {
		return err
	}
	if length != len {
		return fmt.Errorf("length verification failed - expected %d, got %d", length, len)
	}
	return nil
}

func verifyHashes(data []byte, hashes Hashes) error {
	var hasher hash.Hash
	for k, v := range hashes {
		switch k {
		case "sha256":
			hasher = sha256.New()
		case "sha512":
			hasher = sha512.New()
		default:
			return fmt.Errorf("hash verification failed - unknown hashing algorithm - %s", k)
		}
		hasher.Write(data)
		if hex.EncodeToString(v) != hex.EncodeToString(hasher.Sum(nil)) {
			return fmt.Errorf("hash verification failed - mismatch for algorithm %s", k)
		}
	}
	return nil
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

func PathHexDigest(s string) string {
	b := sha256.Sum256([]byte(s))
	return hex.EncodeToString(b[:])
}
