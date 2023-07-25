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
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var testRootBytes = []byte("{\"signatures\":[{\"keyid\":\"roothash\",\"sig\":\"1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee\"}],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"keys\":{\"roothash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubrootval\"},\"scheme\":\"ed25519\"},\"snapshothash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubsval\"},\"scheme\":\"ed25519\"},\"targetshash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubtrval\"},\"scheme\":\"ed25519\"},\"timestamphash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubtmval\"},\"scheme\":\"ed25519\"}},\"roles\":{\"root\":{\"keyids\":[\"roothash\"],\"threshold\":1},\"snapshot\":{\"keyids\":[\"snapshothash\"],\"threshold\":1},\"targets\":{\"keyids\":[\"targetshash\"],\"threshold\":1},\"timestamp\":{\"keyids\":[\"timestamphash\"],\"threshold\":1}},\"spec_version\":\"1.0.31\",\"version\":1}}")

const TEST_REPOSITORY_DATA = "../testutils/repository_data/repository/metadata"

var fixedExpire = time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

func getSignatureByKeyID(signatures []Signature, keyID string) HexBytes {
	for _, sig := range signatures {
		if sig.KeyID == keyID {
			return sig.Signature
		}
	}
	return []byte{}
}

func TestDefaultValuesRoot(t *testing.T) {
	// without setting expiration
	meta := Root()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Root(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, ROOT, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Threshold and KeyIDs for Roles
	for _, role := range []string{ROOT, SNAPSHOT, TARGETS, TIMESTAMP} {
		assert.Equal(t, 1, meta.Signed.Roles[role].Threshold)
		assert.Equal(t, []string{}, meta.Signed.Roles[role].KeyIDs)
	}

	// Keys
	assert.Equal(t, map[string]*Key{}, meta.Signed.Keys)

	// Consistent snapshot
	assert.True(t, meta.Signed.ConsistentSnapshot)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestDefaultValuesSnapshot(t *testing.T) {
	// without setting expiration
	meta := Snapshot()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Snapshot(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, SNAPSHOT, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Targets meta
	assert.Equal(t, map[string]*MetaFiles{"targets.json": {Version: 1}}, meta.Signed.Meta)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestDefaultValuesTimestamp(t *testing.T) {
	// without setting expiration
	meta := Timestamp()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Timestamp(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, TIMESTAMP, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Snapshot meta
	assert.Equal(t, map[string]*MetaFiles{"snapshot.json": {Version: 1}}, meta.Signed.Meta)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestDefaultValuesTargets(t *testing.T) {
	// without setting expiration
	meta := Targets()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Targets(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire, meta.Signed.Expires)

	// Type
	assert.Equal(t, TARGETS, meta.Signed.Type)

	// SpecVersion
	assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)

	// Version
	assert.Equal(t, int64(1), meta.Signed.Version)

	// Target files
	assert.Equal(t, map[string]*TargetFiles{}, meta.Signed.Targets)

	// Signatures
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestDefaultValuesTargetFile(t *testing.T) {
	targetFile := TargetFile()
	assert.NotNil(t, targetFile)
	assert.Equal(t, int64(0), targetFile.Length)
	assert.Equal(t, Hashes{}, targetFile.Hashes)
}

func TestMetaFileDefaultValues(t *testing.T) {
	version := int64(0)
	metaFile := MetaFile(version)
	assert.NotNil(t, metaFile)
	assert.Equal(t, int64(0), metaFile.Length)
	assert.Equal(t, Hashes{}, metaFile.Hashes)
	assert.Equal(t, int64(1), metaFile.Version)

	version = int64(-1)
	metaFile = MetaFile(version)
	assert.NotNil(t, metaFile)
	assert.Equal(t, int64(0), metaFile.Length)
	assert.Equal(t, Hashes{}, metaFile.Hashes)
	assert.Equal(t, int64(1), metaFile.Version)

	version = int64(1)
	metaFile = MetaFile(version)
	assert.NotNil(t, metaFile)
	assert.Equal(t, int64(0), metaFile.Length)
	assert.Equal(t, Hashes{}, metaFile.Hashes)
	assert.Equal(t, int64(1), metaFile.Version)

	version = int64(2)
	metaFile = MetaFile(version)
	assert.NotNil(t, metaFile)
	assert.Equal(t, int64(0), metaFile.Length)
	assert.Equal(t, Hashes{}, metaFile.Hashes)
	assert.Equal(t, int64(2), metaFile.Version)
}

func TestIsDelegatedPath(t *testing.T) {
	type pathMatch struct {
		Pattern    []string
		TargetPath string
		Expected   bool
	}
	// As per - https://theupdateframework.github.io/specification/latest/#pathpattern
	matches := []pathMatch{
		// a PATHPATTERN of "targets/*.tgz" would match file paths "targets/foo.tgz" and "targets/bar.tgz", but not "targets/foo.txt".
		{
			Pattern:    []string{"targets/*.tgz"},
			TargetPath: "targets/foo.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"targets/*.tgz"},
			TargetPath: "targets/bar.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"targets/*.tgz"},
			TargetPath: "targets/foo.txt",
			Expected:   false,
		},
		// a PATHPATTERN of "foo-version-?.tgz" matches "foo-version-2.tgz" and "foo-version-a.tgz", but not "foo-version-alpha.tgz".
		{
			Pattern:    []string{"foo-version-?.tgz"},
			TargetPath: "foo-version-2.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"foo-version-?.tgz"},
			TargetPath: "foo-version-a.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"foo-version-?.tgz"},
			TargetPath: "foo-version-alpha.tgz",
			Expected:   false,
		},
		// a PATHPATTERN of "*.tgz" would match "foo.tgz" and "bar.tgz", but not "targets/foo.tgz"
		{
			Pattern:    []string{"*.tgz"},
			TargetPath: "foo.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"*.tgz"},
			TargetPath: "bar.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"*.tgz"},
			TargetPath: "targets/foo.tgz",
			Expected:   false,
		},
		// a PATHPATTERN of "foo.tgz" would match only "foo.tgz"
		{
			Pattern:    []string{"foo.tgz"},
			TargetPath: "foo.tgz",
			Expected:   true,
		},
		{
			Pattern:    []string{"foo.tgz"},
			TargetPath: "foosy.tgz",
			Expected:   false,
		},
	}
	for _, match := range matches {
		role := &DelegatedRole{
			Paths: match.Pattern,
		}
		ok, err := role.IsDelegatedPath(match.TargetPath)
		assert.Equal(t, match.Expected, ok)
		assert.Nil(t, err)
	}
}

func TestClearSignatures(t *testing.T) {
	meta := Root()
	// verify signatures is empty
	assert.Equal(t, []Signature{}, meta.Signatures)
	// create a signature
	sig := &Signature{
		KeyID:     "keyid",
		Signature: HexBytes{},
	}
	// update the Signatures part
	meta.Signatures = append(meta.Signatures, *sig)
	// verify signatures is not empty
	assert.NotEqual(t, []Signature{}, meta.Signatures)
	// clear signatures
	meta.ClearSignatures()
	// verify signatures is empty
	assert.Equal(t, []Signature{}, meta.Signatures)
}

func TestIsExpiredRoot(t *testing.T) {
	// without setting expiration
	meta := Root()
	assert.NotNil(t, meta)
	// ensure time passed
	time.Sleep(1 * time.Microsecond)
	assert.True(t, meta.Signed.IsExpired(time.Now().UTC()))

	// setting expiration in 2 days from now
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Root(expire)
	assert.NotNil(t, meta)
	assert.False(t, meta.Signed.IsExpired(time.Now().UTC()))
}

func TestIsExpiredSnapshot(t *testing.T) {
	// without setting expiration
	meta := Snapshot()
	assert.NotNil(t, meta)
	// ensure time passed
	time.Sleep(1 * time.Microsecond)
	assert.True(t, meta.Signed.IsExpired(time.Now().UTC()))

	// setting expiration in 2 days from now
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Snapshot(expire)
	assert.NotNil(t, meta)
	assert.False(t, meta.Signed.IsExpired(time.Now().UTC()))
}

func TestIsExpiredTimestamp(t *testing.T) {
	// without setting expiration
	meta := Timestamp()
	assert.NotNil(t, meta)
	// ensure time passed
	time.Sleep(1 * time.Microsecond)
	assert.True(t, meta.Signed.IsExpired(time.Now().UTC()))

	// setting expiration in 2 days from now
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Timestamp(expire)
	assert.NotNil(t, meta)
	assert.False(t, meta.Signed.IsExpired(time.Now().UTC()))
}

func TestIsExpiredTargets(t *testing.T) {
	// without setting expiration
	meta := Targets()
	assert.NotNil(t, meta)
	// ensure time passed
	time.Sleep(1 * time.Microsecond)
	assert.True(t, meta.Signed.IsExpired(time.Now().UTC()))

	// setting expiration in 2 days from now
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Targets(expire)
	assert.NotNil(t, meta)
	assert.False(t, meta.Signed.IsExpired(time.Now().UTC()))
}

func TestUnrecognizedFieldRolesSigned(t *testing.T) {
	// unrecognized field to test
	// added to the Signed portion of each role type
	testUnrecognizedField := map[string]any{"test": "true"}

	root := Root(fixedExpire)
	root.Signed.UnrecognizedFields = testUnrecognizedField
	rootJSON, err := root.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"keys\":{},\"roles\":{\"root\":{\"keyids\":[],\"threshold\":1},\"snapshot\":{\"keyids\":[],\"threshold\":1},\"targets\":{\"keyids\":[],\"threshold\":1},\"timestamp\":{\"keyids\":[],\"threshold\":1}},\"spec_version\":\"1.0.31\",\"test\":\"true\",\"version\":1}}"), rootJSON)

	targets := Targets(fixedExpire)
	targets.Signed.UnrecognizedFields = testUnrecognizedField
	targetsJSON, err := targets.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"targets\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"spec_version\":\"1.0.31\",\"targets\":{},\"test\":\"true\",\"version\":1}}"), targetsJSON)

	snapshot := Snapshot(fixedExpire)
	snapshot.Signed.UnrecognizedFields = testUnrecognizedField
	snapshotJSON, err := snapshot.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"snapshot\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"meta\":{\"targets.json\":{\"version\":1}},\"spec_version\":\"1.0.31\",\"test\":\"true\",\"version\":1}}"), snapshotJSON)

	timestamp := Timestamp(fixedExpire)
	timestamp.Signed.UnrecognizedFields = testUnrecognizedField
	timestampJSON, err := timestamp.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"timestamp\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"meta\":{\"snapshot.json\":{\"version\":1}},\"spec_version\":\"1.0.31\",\"test\":\"true\",\"version\":1}}"), timestampJSON)
}
func TestUnrecognizedFieldGenericMetadata(t *testing.T) {
	// fixed expire
	expire := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

	// unrecognized field to test
	// added to the generic metadata type
	testUnrecognizedField := map[string]any{"test": "true"}

	root := Root(expire)
	root.UnrecognizedFields = testUnrecognizedField
	rootJSON, err := root.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"keys\":{},\"roles\":{\"root\":{\"keyids\":[],\"threshold\":1},\"snapshot\":{\"keyids\":[],\"threshold\":1},\"targets\":{\"keyids\":[],\"threshold\":1},\"timestamp\":{\"keyids\":[],\"threshold\":1}},\"spec_version\":\"1.0.31\",\"version\":1},\"test\":\"true\"}"), rootJSON)
}
func TestTargetFilesCustomField(t *testing.T) {
	// custom JSON to test
	testCustomJSON := json.RawMessage([]byte(`{"test":true}`))

	// create a targets metadata
	targets := Targets(fixedExpire)
	assert.NotNil(t, targets)

	// create a targetfile with the custom JSON
	targetFile := TargetFile()
	targetFile.Custom = &testCustomJSON

	// add the targetfile to targets metadata
	targets.Signed.Targets["testTarget"] = targetFile
	targetsJSON, err := targets.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"targets\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"spec_version\":\"1.0.31\",\"targets\":{\"testTarget\":{\"custom\":{\"test\":true},\"hashes\":{},\"length\":0}},\"version\":1}}"), targetsJSON)
}

func TestFromBytes(t *testing.T) {
	root := Root(fixedExpire)
	assert.Equal(t, fixedExpire, root.Signed.Expires)

	_, err := root.FromBytes(testRootBytes)
	assert.NoError(t, err)

	assert.Equal(t, fixedExpire, root.Signed.Expires)
	assert.Equal(t, fixedExpire, root.Signed.Expires)
	assert.Equal(t, ROOT, root.Signed.Type)
	assert.True(t, root.Signed.ConsistentSnapshot)

	assert.Equal(t, 4, len(root.Signed.Keys))
	assert.Contains(t, root.Signed.Roles, ROOT)
	assert.Equal(t, 1, root.Signed.Roles[ROOT].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[ROOT].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[ROOT].KeyIDs[0])
	assert.Equal(t, "roothash", root.Signed.Roles[ROOT].KeyIDs[0])

	assert.Contains(t, root.Signed.Roles, SNAPSHOT)
	assert.Equal(t, 1, root.Signed.Roles[SNAPSHOT].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[SNAPSHOT].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[SNAPSHOT].KeyIDs[0])
	assert.Equal(t, "snapshothash", root.Signed.Roles[SNAPSHOT].KeyIDs[0])

	assert.Contains(t, root.Signed.Roles, TARGETS)
	assert.Equal(t, 1, root.Signed.Roles[TARGETS].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[TARGETS].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[TARGETS].KeyIDs[0])
	assert.Equal(t, "targetshash", root.Signed.Roles[TARGETS].KeyIDs[0])

	assert.Contains(t, root.Signed.Roles, TIMESTAMP)
	assert.Equal(t, 1, root.Signed.Roles[TIMESTAMP].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[TIMESTAMP].KeyIDs[0])
	assert.Equal(t, "timestamphash", root.Signed.Roles[TIMESTAMP].KeyIDs[0])

	assert.Equal(t, int64(1), root.Signed.Version)
	assert.NotEmpty(t, root.Signatures)
	assert.Equal(t, "roothash", root.Signatures[0].KeyID)
	data := []byte("some data")
	h32 := sha256.Sum256(data)
	h := h32[:]
	assert.Equal(t, HexBytes(h), root.Signatures[0].Signature)
}

func TestToByte(t *testing.T) {
	rootBytesExpireStr := "2030-08-15T14:30:45.0000001Z"
	rootBytesExpire, err := time.Parse(time.RFC3339, rootBytesExpireStr)
	assert.NoError(t, err)

	root := Root(rootBytesExpire)
	root.Signed.Keys["roothash"] = &Key{Type: "ed25519", Value: KeyVal{PublicKey: "pubrootval"}, Scheme: "ed25519"}
	root.Signed.Keys["snapshothash"] = &Key{Type: "ed25519", Value: KeyVal{PublicKey: "pubsval"}, Scheme: "ed25519"}
	root.Signed.Keys["targetshash"] = &Key{Type: "ed25519", Value: KeyVal{PublicKey: "pubtrval"}, Scheme: "ed25519"}
	root.Signed.Keys["timestamphash"] = &Key{Type: "ed25519", Value: KeyVal{PublicKey: "pubtmval"}, Scheme: "ed25519"}
	root.Signed.Roles[ROOT] = &Role{
		Threshold: 1,
		KeyIDs:    []string{"roothash"},
	}
	root.Signed.Roles[SNAPSHOT] = &Role{
		Threshold: 1,
		KeyIDs:    []string{"snapshothash"},
	}
	root.Signed.Roles[TARGETS] = &Role{
		Threshold: 1,
		KeyIDs:    []string{"targetshash"},
	}
	root.Signed.Roles[TIMESTAMP] = &Role{
		Threshold: 1,
		KeyIDs:    []string{"timestamphash"},
	}

	data := []byte("some data")
	h32 := sha256.Sum256(data)
	h := h32[:]
	hash := map[string]HexBytes{"ed25519": h}
	root.Signatures = append(root.Signatures, Signature{KeyID: "roothash", Signature: hash["ed25519"]})
	rootBytes, err := root.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, string(testRootBytes), string(rootBytes))
}

func TestFromFile(t *testing.T) {
	root := Root(fixedExpire)
	_, err := root.FromFile(fmt.Sprintf("%s/1.root.json", TEST_REPOSITORY_DATA))
	assert.NoError(t, err)

	assert.Equal(t, fixedExpire, root.Signed.Expires)
	assert.Equal(t, fixedExpire, root.Signed.Expires)
	assert.Equal(t, ROOT, root.Signed.Type)
	assert.True(t, root.Signed.ConsistentSnapshot)
	assert.Equal(t, 4, len(root.Signed.Keys))

	assert.Contains(t, root.Signed.Roles, ROOT)
	assert.Equal(t, 1, root.Signed.Roles[ROOT].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[ROOT].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[ROOT].KeyIDs[0])
	assert.Equal(t, "d5fa855fce82db75ec64283e828cc90517df5edf5cdc57e7958a890d6556f5b7", root.Signed.Roles[ROOT].KeyIDs[0])

	assert.Contains(t, root.Signed.Roles, SNAPSHOT)
	assert.Equal(t, 1, root.Signed.Roles[SNAPSHOT].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[SNAPSHOT].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[SNAPSHOT].KeyIDs[0])
	assert.Equal(t, "700464ea12f4cb5f06a7512c75b73c0b6eeb2cd42854b085eed5b3c993607cba", root.Signed.Roles[SNAPSHOT].KeyIDs[0])

	assert.Contains(t, root.Signed.Roles, TARGETS)
	assert.Equal(t, 1, root.Signed.Roles[TARGETS].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[TARGETS].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[TARGETS].KeyIDs[0])
	assert.Equal(t, "409fb816e403e0c00646665eac21cb8adfab8e318272ca7589b2d1fc0bccb255", root.Signed.Roles[TARGETS].KeyIDs[0])

	assert.Contains(t, root.Signed.Roles, TIMESTAMP)
	assert.Equal(t, 1, root.Signed.Roles[TIMESTAMP].Threshold)
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	assert.Contains(t, root.Signed.Keys, root.Signed.Roles[TIMESTAMP].KeyIDs[0])
	assert.Equal(t, "0a5842e65e9c8c428354f40708435de6793ac379a275effe40d6358be2de835c", root.Signed.Roles[TIMESTAMP].KeyIDs[0])

	assert.Equal(t, SPECIFICATION_VERSION, root.Signed.SpecVersion)
	assert.Contains(t, root.Signed.UnrecognizedFields, "test")
	assert.Equal(t, "true", root.Signed.UnrecognizedFields["test"])

	assert.Equal(t, int64(1), root.Signed.Version)
	assert.NotEmpty(t, root.Signatures)
	assert.Equal(t, "d5fa855fce82db75ec64283e828cc90517df5edf5cdc57e7958a890d6556f5b7", root.Signatures[0].KeyID)

}

func TestToFile(t *testing.T) {
	tmp := os.TempDir()
	tmpDir, err := os.MkdirTemp(tmp, "0750")
	assert.NoError(t, err)

	fileName := fmt.Sprintf("%s/1.root.json", tmpDir)
	assert.NoFileExists(t, fileName)
	root, err := Root().FromBytes(testRootBytes)
	assert.NoError(t, err)

	err = root.ToFile(fileName, false)
	assert.NoError(t, err)

	assert.FileExists(t, fileName)
	data, err := os.ReadFile(fileName)
	assert.NoError(t, err)
	assert.Equal(t, string(testRootBytes), string(data))

	err = os.RemoveAll(tmpDir)
	assert.NoError(t, err)
	assert.NoFileExists(t, fileName)

}

func TestVerifyDelegate(t *testing.T) {
	root := Root(fixedExpire)
	err := root.VerifyDelegate("test", root)
	assert.EqualError(t, err, "value error: no delegation found for test")

	targets := Targets(fixedExpire)
	err = targets.VerifyDelegate("test", targets)
	assert.EqualError(t, err, "value error: no delegations found")

	key, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	delegateeKey, _ := KeyFromPublicKey(key)
	delegations := &Delegations{
		Keys: map[string]*Key{
			delegateeKey.ID(): delegateeKey,
		},
		Roles: []DelegatedRole{
			{
				Name:   "test",
				KeyIDs: []string{delegateeKey.ID()},
			},
		},
	}
	targets.Signed.Delegations = delegations
	err = targets.VerifyDelegate("test", root)
	assert.NoError(t, err)
	err = targets.VerifyDelegate("test", targets)
	assert.NoError(t, err)

	err = targets.VerifyDelegate("non-existing", root)
	assert.EqualError(t, err, "value error: no delegation found for non-existing")
	err = targets.VerifyDelegate("non-existing", targets)
	assert.EqualError(t, err, "value error: no delegation found for non-existing")

	targets.Signed.Delegations.Roles[0].Threshold = 1
	err = targets.VerifyDelegate("test", targets)
	assert.Errorf(t, err, "Verifying test failed, not enough signatures, got %d, want %d", 0, 1)

	delegations.Keys["incorrectkey"] = delegations.Keys[delegateeKey.ID()]
	delete(delegations.Keys, delegateeKey.ID())
	err = targets.VerifyDelegate("test", root)
	assert.Errorf(t, err, "key with ID %s not found in test keyids", delegateeKey.ID())

	timestamp := Timestamp(fixedExpire)
	err = timestamp.VerifyDelegate("test", timestamp)
	assert.EqualError(t, err, "type error: call is valid only on delegator metadata (should be either root or targets)")

	snapshot := Snapshot(fixedExpire)
	err = snapshot.VerifyDelegate("test", snapshot)
	assert.EqualError(t, err, "type error: call is valid only on delegator metadata (should be either root or targets)")
}

func TestVerifyLengthHashesTargetFiles(t *testing.T) {
	targetFiles := TargetFile()
	targetFiles.Hashes = map[string]HexBytes{}

	data := []byte{}
	err := targetFiles.VerifyLengthHashes(data)
	assert.NoError(t, err)

	data = []byte("some data")
	err = targetFiles.VerifyLengthHashes(data)
	assert.Error(t, err, "length/hash verification error: length verification failed - expected 0, got 9")

	h32 := sha256.Sum256(data)
	h := h32[:]
	targetFiles.Hashes["sha256"] = h
	targetFiles.Length = int64(len(data))
	err = targetFiles.VerifyLengthHashes(data)
	assert.NoError(t, err)

	targetFiles.Hashes = map[string]HexBytes{"unknownAlg": data}
	err = targetFiles.VerifyLengthHashes(data)
	assert.Error(t, err, "length/hash verification error: hash verification failed - unknown hashing algorithm - unknownArg")

	targetFiles.Hashes = map[string]HexBytes{"sha256": data}
	err = targetFiles.VerifyLengthHashes(data)
	assert.Error(t, err, "length/hash verification error: hash verification failed - mismatch for algorithm sha256")
}

func TestVerifyLengthHashesMetaFiles(t *testing.T) {
	version := int64(0)
	metaFile := MetaFile(version)
	data := []byte("some data")
	metaFile.Hashes = map[string]HexBytes{"unknownAlg": data}
	err := metaFile.VerifyLengthHashes(data)
	assert.Error(t, err, "length/hash verification error: hash verification failed - unknown hashing algorithm - unknownArg")

	metaFile.Hashes = map[string]HexBytes{"sha256": data}
	err = metaFile.VerifyLengthHashes(data)
	assert.Error(t, err, "length/hash verification error: hash verification failed - mismatch for algorithm sha256")

	h32 := sha256.Sum256(data)
	h := h32[:]
	metaFile.Hashes = map[string]HexBytes{"sha256": h}
	err = metaFile.VerifyLengthHashes(data)
	assert.NoError(t, err)

	incorrectData := []byte("another data")
	err = metaFile.VerifyLengthHashes(incorrectData)
	assert.Error(t, err, "length/hash verification error: length verification failed - expected 0, got 9")
}
