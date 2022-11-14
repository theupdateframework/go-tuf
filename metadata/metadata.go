package metadata

import (
	"bytes"
	"crypto"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
)

// Root create new metadata instance of type Root
func Root(expires ...time.Time) *Metadata[RootType] {
	// expire now if there's nothing set
	if len(expires) == 0 {
		expires = []time.Time{time.Now().UTC()}
	}
	roles := map[string]*Role{}
	for _, r := range []string{ROOT, SNAPSHOT, TARGETS, TIMESTAMP} {
		roles[r] = &Role{
			KeyIDs:    []string{},
			Threshold: 1,
		}
	}
	return &Metadata[RootType]{
		Signed: RootType{
			Type:               "root",
			SpecVersion:        SPECIFICATION_VERSION,
			Version:            1,
			Expires:            expires[0],
			Keys:               map[string]*Key{},
			Roles:              roles,
			ConsistentSnapshot: false,
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
	return &Metadata[SnapshotType]{
		Signed: SnapshotType{
			Type:        "snapshot",
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
	return &Metadata[TimestampType]{
		Signed: TimestampType{
			Type:        "timestamp",
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
	return &Metadata[TargetsType]{
		Signed: TargetsType{
			Type:        "targets",
			SpecVersion: SPECIFICATION_VERSION,
			Version:     1,
			Expires:     expires[0],
			Targets:     map[string]TargetFiles{},
			Delegations: &Delegations{
				Keys:  map[string]*Key{},
				Roles: []DelegatedRole{},
			},
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
	return &MetaFiles{
		Length:  0,
		Hashes:  Hashes{},
		Version: version,
	}
}

// FromFile load metadata from file
func (meta *Metadata[T]) FromFile(name string) (*Metadata[T], error) {
	m, err := fromFile[T](name)
	if err != nil {
		return nil, fmt.Errorf("error generating metadata from bytes - %s", name)
	}
	*meta = *m
	return meta, nil
}

// FromBytes deserialize metadata from bytes
func (meta *Metadata[T]) FromBytes(bytes []byte) (*Metadata[T], error) {
	m, err := fromBytes[T](bytes)
	if err != nil {
		return nil, err
	}
	*meta = *m
	return meta, nil
}

// ToBytes serialize metadata to bytes
func (meta *Metadata[T]) ToBytes(pretty bool) ([]byte, error) {
	if pretty {
		return json.MarshalIndent(*meta, "", "\t")
	}
	return json.Marshal(*meta)
}

// ToFile save metadata to file
func (meta *Metadata[T]) ToFile(name string, pretty bool) error {
	bytes, err := meta.ToBytes(pretty)
	if err != nil {
		return fmt.Errorf("failed serializing metadata")
	}
	return ioutil.WriteFile(name, bytes, 0644)
}

// Sign create signature over Signed and assign it to Signatures
func (meta *Metadata[T]) Sign(signer signature.Signer) (*Signature, error) {
	// encode the Signed part to canonical JSON so signatures are consistent
	payload, err := cjson.EncodeCanonical(meta.Signed)
	if err != nil {
		return nil, fmt.Errorf("failed to encode Signed in canonical format during Sign()")
	}
	// sign the Signed part
	sb, err := signer.SignMessage(bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to Sign(), returned signature should not be nil")
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
	return sig, nil
}

// VerifyDelegate verifies that “delegated_metadata“ is signed with the required
// threshold of keys for the delegated role “delegated_role“
func (meta *Metadata[T]) VerifyDelegate(delegated_role string, delegated_metadata any) error {
	var keys map[string]*Key
	var roleKeyIDs []string
	var roleThreshold int
	var sign Signature
	var payload []byte
	signing_keys := map[string]bool{}
	i := any(meta)
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
		fmt.Println("no delegation found for", delegated_role)
		return fmt.Errorf("no delegation found for %s", delegated_role)
	}
	// loop through each role keyID
	for _, v := range roleKeyIDs {
		// convert to a PublicKey type
		key, err := keys[v].ToPublicKey()
		if err != nil {
			fmt.Println("failed to generate crypto.PublicKey from Key")
			return err
		}
		// load a verifier based on that key
		verifier, err := signature.LoadVerifier(key, crypto.Hash(0))
		if err != nil {
			fmt.Println("failed to load verifier")
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
				fmt.Println("failed to encode Signed in canonical format during verify")
			}
		case *Metadata[SnapshotType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				fmt.Println("failed to encode Signed in canonical format during verify")
			}
		case *Metadata[TimestampType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				fmt.Println("failed to encode Signed in canonical format during verify")
			}
		case *Metadata[TargetsType]:
			for _, s := range d.Signatures {
				if s.KeyID == v {
					sign = s
				}
			}
			payload, err = cjson.EncodeCanonical(d.Signed)
			if err != nil {
				fmt.Println("failed to encode Signed in canonical format during verify")
			}
		default:
			fmt.Println("unknown delegated metadata type")
		}
		// verify if the signature for that payload corresponds to the given key
		if err := verifier.VerifySignature(bytes.NewReader(sign.Signature), bytes.NewReader(payload)); err == nil {
			// save the verified keyID only if there's no err value
			signing_keys[v] = true
		}
	}
	// check if the amount of valid signatures is enough
	if len(signing_keys) < roleThreshold {
		return fmt.Errorf("signature verification failed, not enough signatures")
	}
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

// VerifyLengthHashes checks whether the data matches its corresponding
// length and hashes
func (f *MetaFiles) VerifyLengthHashes(data []byte) error {
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
func (t *TargetFiles) FromFile(targetPath, localPath string) (*TargetFiles, error) {
	return &TargetFiles{}, nil
}

// ClearSignatures clears the Signatures
func (meta *Metadata[T]) ClearSignatures() {
	meta.Signatures = []Signature{}
}
