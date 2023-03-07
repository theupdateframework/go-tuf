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
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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

func TestUnrecognizedField(t *testing.T) {
	// fixed expire
	expire := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

	// unrecognized field to test
	testUnrecognizedField := map[string]any{"test": "true"}

	root := Root(expire)
	root.Signed.UnrecognizedFields = testUnrecognizedField
	rootJSON, err := root.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"keys\":{},\"roles\":{\"root\":{\"keyids\":[],\"threshold\":1},\"snapshot\":{\"keyids\":[],\"threshold\":1},\"targets\":{\"keyids\":[],\"threshold\":1},\"timestamp\":{\"keyids\":[],\"threshold\":1}},\"spec_version\":\"1.0.31\",\"test\":\"true\",\"version\":1},\"signatures\":[]}"), rootJSON)

	targets := Targets(expire)
	targets.Signed.UnrecognizedFields = testUnrecognizedField
	targetsJSON, err := targets.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signed\":{\"_type\":\"targets\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"spec_version\":\"1.0.31\",\"targets\":{},\"test\":\"true\",\"version\":1},\"signatures\":[]}"), targetsJSON)

	snapshot := Snapshot(expire)
	snapshot.Signed.UnrecognizedFields = testUnrecognizedField
	snapshotJSON, err := snapshot.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signed\":{\"_type\":\"snapshot\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"meta\":{\"targets.json\":{\"version\":1}},\"spec_version\":\"1.0.31\",\"test\":\"true\",\"version\":1},\"signatures\":[]}"), snapshotJSON)

	timestamp := Timestamp(expire)
	timestamp.Signed.UnrecognizedFields = testUnrecognizedField
	timestampJSON, err := timestamp.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signed\":{\"_type\":\"timestamp\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"meta\":{\"snapshot.json\":{\"version\":1}},\"spec_version\":\"1.0.31\",\"test\":\"true\",\"version\":1},\"signatures\":[]}"), timestampJSON)
}

func TestTargetFilesCustomdField(t *testing.T) {
	// fixed expire
	expire := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

	// custom JSON to test
	testCustomJSON := json.RawMessage([]byte(`{"test":true}`))

	// create a targets metadata
	targets := Targets(expire)
	assert.NotNil(t, targets)

	// create a targetfile with the custom JSON
	targetFile := TargetFile()
	targetFile.Custom = &testCustomJSON

	// add the targetfile to targets metadata
	targets.Signed.Targets["testTarget"] = targetFile
	targetsJSON, err := targets.ToBytes(false)
	assert.NoError(t, err)
	fmt.Println(string(targetsJSON))
	assert.Equal(t, []byte("{\"signed\":{\"_type\":\"targets\",\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"spec_version\":\"1.0.31\",\"targets\":{\"testTarget\":{\"custom\":{\"test\":true},\"hashes\":{},\"length\":0}},\"version\":1},\"signatures\":[]}"), targetsJSON)
}
