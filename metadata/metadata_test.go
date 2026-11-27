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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/rsapss"
)

func TestMetadataCreation(t *testing.T) {
	fixedExpire := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

	tests := []struct {
		name         string
		createFunc   func() any
		expectedType string
		// fixed marks the cases built with fixedExpire, whose expiry must be
		// stored unchanged.
		fixed bool
	}{
		{
			name:         "Root creation with default expiry",
			createFunc:   func() any { return Root() },
			expectedType: ROOT,
		},
		{
			name:         "Root creation with fixed expiry",
			createFunc:   func() any { return Root(fixedExpire) },
			expectedType: ROOT,
			fixed:        true,
		},
		{
			name:         "Targets creation with default expiry",
			createFunc:   func() any { return Targets() },
			expectedType: TARGETS,
		},
		{
			name:         "Targets creation with fixed expiry",
			createFunc:   func() any { return Targets(fixedExpire) },
			expectedType: TARGETS,
			fixed:        true,
		},
		{
			name:         "Snapshot creation with default expiry",
			createFunc:   func() any { return Snapshot() },
			expectedType: SNAPSHOT,
		},
		{
			name:         "Snapshot creation with fixed expiry",
			createFunc:   func() any { return Snapshot(fixedExpire) },
			expectedType: SNAPSHOT,
			fixed:        true,
		},
		{
			name:         "Timestamp creation with default expiry",
			createFunc:   func() any { return Timestamp() },
			expectedType: TIMESTAMP,
		},
		{
			name:         "Timestamp creation with fixed expiry",
			createFunc:   func() any { return Timestamp(fixedExpire) },
			expectedType: TIMESTAMP,
			fixed:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.createFunc()
			assert.NotNil(t, result)

			var expires time.Time
			switch meta := result.(type) {
			case *Metadata[RootType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Keys)
				assert.NotNil(t, meta.Signed.Roles)
				expires = meta.Signed.Expires
			case *Metadata[TargetsType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Targets)
				expires = meta.Signed.Expires
			case *Metadata[SnapshotType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Meta)
				expires = meta.Signed.Expires
			case *Metadata[TimestampType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Meta)
				expires = meta.Signed.Expires
			}
			if tt.fixed {
				assert.Equal(t, fixedExpire.Truncate(time.Second), expires)
			}
		})
	}
}

func TestMetadataFromBytes(t *testing.T) {
	validRoot := helpers.CreateTestRootJSON(t)
	validTargets := helpers.CreateTestTargetsJSON(t)
	validSnapshot := helpers.CreateTestSnapshotJSON(t)
	validTimestamp := helpers.CreateTestTimestampJSON(t)
	invalidData := helpers.CreateInvalidJSON()

	tests := []struct {
		name         string
		metadataType string
		data         []byte
		wantErr      bool
		errorMsg     string
	}{
		{
			name:         "Valid Root from bytes",
			metadataType: ROOT,
			data:         validRoot,
		},
		{
			name:         "Valid Targets from bytes",
			metadataType: TARGETS,
			data:         validTargets,
		},
		{
			name:         "Valid Snapshot from bytes",
			metadataType: SNAPSHOT,
			data:         validSnapshot,
		},
		{
			name:         "Valid Timestamp from bytes",
			metadataType: TIMESTAMP,
			data:         validTimestamp,
		},
		{
			name:         "Empty data",
			metadataType: ROOT,
			data:         invalidData["empty"],
			wantErr:      true,
			errorMsg:     "unexpected end of JSON input",
		},
		{
			name:         "Invalid JSON",
			metadataType: ROOT,
			data:         invalidData["invalid_json"],
			wantErr:      true,
			errorMsg:     "invalid character",
		},
		{
			name:         "Missing signed field",
			metadataType: ROOT,
			data:         invalidData["missing_signed"],
			wantErr:      true,
		},
		{
			name:         "Wrong metadata type",
			metadataType: ROOT,
			data:         invalidData["wrong_type"],
			wantErr:      true,
			errorMsg:     "expected metadata type root",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			switch tt.metadataType {
			case ROOT:
				_, err = Root().FromBytes(tt.data)
			case TARGETS:
				_, err = Targets().FromBytes(tt.data)
			case SNAPSHOT:
				_, err = Snapshot().FromBytes(tt.data)
			case TIMESTAMP:
				_, err = Timestamp().FromBytes(tt.data)
			}

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestMetadataFromFile(t *testing.T) {
	testDir := t.TempDir()

	validRoot := helpers.CreateTestRootJSON(t)
	validTargets := helpers.CreateTestTargetsJSON(t)

	rootFile := helpers.WriteTestFile(t, testDir, "root.json", validRoot)
	targetsFile := helpers.WriteTestFile(t, testDir, "targets.json", validTargets)
	helpers.WriteTestFile(t, testDir, "invalid.json", []byte("{invalid json}"))

	tests := []struct {
		name         string
		metadataType string
		filePath     string
		wantErr      bool
		errorMsg     string
	}{
		{
			name:         "Valid Root from file",
			metadataType: ROOT,
			filePath:     rootFile,
		},
		{
			name:         "Valid Targets from file",
			metadataType: TARGETS,
			filePath:     targetsFile,
		},
		{
			name:         "Non-existent file",
			metadataType: ROOT,
			filePath:     filepath.Join(testDir, "nonexistent.json"),
			wantErr:      true,
		},
		{
			name:         "Invalid JSON file",
			metadataType: ROOT,
			filePath:     filepath.Join(testDir, "invalid.json"),
			wantErr:      true,
			errorMsg:     "invalid character",
		},
		{
			name:         "Wrong metadata type in file",
			metadataType: TARGETS,
			filePath:     rootFile,
			wantErr:      true,
			errorMsg:     "expected metadata type targets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			switch tt.metadataType {
			case ROOT:
				_, err = Root().FromFile(tt.filePath)
			case TARGETS:
				_, err = Targets().FromFile(tt.filePath)
			case SNAPSHOT:
				_, err = Snapshot().FromFile(tt.filePath)
			case TIMESTAMP:
				_, err = Timestamp().FromFile(tt.filePath)
			}

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestMetadataToBytes(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name     string
		metadata any
		pretty   bool
	}{
		{name: "Root to bytes compact", metadata: Root(expiry), pretty: false},
		{name: "Root to bytes pretty", metadata: Root(expiry), pretty: true},
		{name: "Targets to bytes pretty", metadata: Targets(expiry), pretty: true},
		{name: "Snapshot to bytes pretty", metadata: Snapshot(expiry), pretty: true},
		{name: "Timestamp to bytes pretty", metadata: Timestamp(expiry), pretty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				data []byte
				err  error
			)
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				data, err = meta.ToBytes(tt.pretty)
			case *Metadata[TargetsType]:
				data, err = meta.ToBytes(tt.pretty)
			case *Metadata[SnapshotType]:
				data, err = meta.ToBytes(tt.pretty)
			case *Metadata[TimestampType]:
				data, err = meta.ToBytes(tt.pretty)
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			// Verify the output is valid JSON.
			var jsonData any
			assert.NoError(t, json.Unmarshal(data, &jsonData))

			// Only pretty output is indented across multiple lines.
			assert.Equal(t, tt.pretty, bytes.Contains(data, []byte("\n")))
		})
	}
}

func TestMetadataToFile(t *testing.T) {
	testDir := t.TempDir()
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name     string
		metadata any
		filename string
		pretty   bool
	}{
		{name: "Root to file pretty", metadata: Root(expiry), filename: "root.json", pretty: true},
		{name: "Targets to file compact", metadata: Targets(expiry), filename: "targets.json", pretty: false},
		{name: "Snapshot to file pretty", metadata: Snapshot(expiry), filename: "snapshot.json", pretty: true},
		{name: "Timestamp to file pretty", metadata: Timestamp(expiry), filename: "timestamp.json", pretty: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(testDir, tt.filename)
			var err error
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				err = meta.ToFile(path, tt.pretty)
			case *Metadata[TargetsType]:
				err = meta.ToFile(path, tt.pretty)
			case *Metadata[SnapshotType]:
				err = meta.ToFile(path, tt.pretty)
			case *Metadata[TimestampType]:
				err = meta.ToFile(path, tt.pretty)
			}

			assert.NoError(t, err)

			// Verify the file contains valid JSON.
			raw, err := os.ReadFile(path)
			assert.NoError(t, err)
			var jsonData any
			assert.NoError(t, json.Unmarshal(raw, &jsonData))

			// Only pretty output is indented across multiple lines.
			assert.Equal(t, tt.pretty, bytes.Contains(raw, []byte("\n")))
		})
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	testDir := t.TempDir()
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name     string
		metadata any
		filename string
	}{
		{name: "Root roundtrip", metadata: Root(expiry), filename: "root.json"},
		{name: "Targets roundtrip", metadata: Targets(expiry), filename: "targets.json"},
		{name: "Snapshot roundtrip", metadata: Snapshot(expiry), filename: "snapshot.json"},
		{name: "Timestamp roundtrip", metadata: Timestamp(expiry), filename: "timestamp.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(testDir, tt.filename)

			// The expiry differs from the constructors' default, so the
			// serialised forms only match if FromFile loaded what ToFile
			// wrote.
			var want, got []byte
			var err error
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, loadErr := Root().FromFile(path)
				assert.NoError(t, loadErr)
				assert.True(t, meta.Signed.Expires.Equal(loaded.Signed.Expires))
				want, err = meta.ToBytes(false)
				assert.NoError(t, err)
				got, err = loaded.ToBytes(false)

			case *Metadata[TargetsType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, loadErr := Targets().FromFile(path)
				assert.NoError(t, loadErr)
				assert.True(t, meta.Signed.Expires.Equal(loaded.Signed.Expires))
				want, err = meta.ToBytes(false)
				assert.NoError(t, err)
				got, err = loaded.ToBytes(false)

			case *Metadata[SnapshotType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, loadErr := Snapshot().FromFile(path)
				assert.NoError(t, loadErr)
				assert.True(t, meta.Signed.Expires.Equal(loaded.Signed.Expires))
				want, err = meta.ToBytes(false)
				assert.NoError(t, err)
				got, err = loaded.ToBytes(false)

			case *Metadata[TimestampType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, loadErr := Timestamp().FromFile(path)
				assert.NoError(t, loadErr)
				assert.True(t, meta.Signed.Expires.Equal(loaded.Signed.Expires))
				want, err = meta.ToBytes(false)
				assert.NoError(t, err)
				got, err = loaded.ToBytes(false)
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, want)
			assert.Equal(t, string(want), string(got))
		})
	}
}

func TestMetadataExpiration(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	tests := []struct {
		name      string
		metadata  any
		isExpired bool
	}{
		{name: "Root not expired", metadata: Root(future), isExpired: false},
		{name: "Root expired", metadata: Root(past), isExpired: true},
		{name: "Targets not expired", metadata: Targets(future), isExpired: false},
		{name: "Targets expired", metadata: Targets(past), isExpired: true},
		{name: "Snapshot not expired", metadata: Snapshot(future), isExpired: false},
		{name: "Snapshot expired", metadata: Snapshot(past), isExpired: true},
		{name: "Timestamp not expired", metadata: Timestamp(future), isExpired: false},
		{name: "Timestamp expired", metadata: Timestamp(past), isExpired: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var expired bool
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				expired = meta.Signed.IsExpired(now)
			case *Metadata[TargetsType]:
				expired = meta.Signed.IsExpired(now)
			case *Metadata[SnapshotType]:
				expired = meta.Signed.IsExpired(now)
			case *Metadata[TimestampType]:
				expired = meta.Signed.IsExpired(now)
			}
			assert.Equal(t, tt.isExpired, expired)
		})
	}
}

var testRootBytes = []byte("{\"signatures\":[{\"keyid\":\"roothash\",\"sig\":\"1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee\"}],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"keys\":{\"roothash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubrootval\"},\"scheme\":\"ed25519\"},\"snapshothash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubsval\"},\"scheme\":\"ed25519\"},\"targetshash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubtrval\"},\"scheme\":\"ed25519\"},\"timestamphash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubtmval\"},\"scheme\":\"ed25519\"}},\"roles\":{\"root\":{\"keyids\":[\"roothash\"],\"threshold\":1},\"snapshot\":{\"keyids\":[\"snapshothash\"],\"threshold\":1},\"targets\":{\"keyids\":[\"targetshash\"],\"threshold\":1},\"timestamp\":{\"keyids\":[\"timestamphash\"],\"threshold\":1}},\"spec_version\":\"" + SPECIFICATION_VERSION + "\",\"version\":1}}")

const TEST_REPOSITORY_DATA = "../internal/testutils/repository_data/repository/metadata"

var fixedExpire = time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

// the constructors truncate expires to second precision per the TUF spec, so
// anything that has been through Root/Snapshot/Targets/Timestamp carries this.
var fixedExpireTruncated = fixedExpire.Truncate(time.Second)

func getSignatureByKeyID(signatures []Signature, keyID string) (HexBytes, int) {
	for i, sig := range signatures {
		if sig.KeyID == keyID {
			return sig.Signature, i
		}
	}
	return []byte{}, 0
}

func TestDefaultValuesRoot(t *testing.T) {
	// without setting expiration
	meta := Root()
	assert.NotNil(t, meta)
	assert.GreaterOrEqual(t, []time.Time{time.Now().UTC()}[0], meta.Signed.Expires)

	// setting expiration
	// the constructors truncate expires to second precision, per the TUF spec
	expire := time.Now().AddDate(0, 0, 2).UTC()
	meta = Root(expire)
	assert.NotNil(t, meta)
	assert.Equal(t, expire.Truncate(time.Second), meta.Signed.Expires)

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
	assert.Equal(t, expire.Truncate(time.Second), meta.Signed.Expires)

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
	assert.Equal(t, expire.Truncate(time.Second), meta.Signed.Expires)

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
	assert.Equal(t, expire.Truncate(time.Second), meta.Signed.Expires)

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

func TestIsDelegatedPathInvalidPattern(t *testing.T) {
	// A malformed glob (unterminated character class) must surface an error
	// rather than being silently treated as a non-match, so callers can tell
	// "does not match" apart from "invalid pattern".
	role := &DelegatedRole{
		Paths: []string{"targets/["},
	}
	ok, err := role.IsDelegatedPath("targets/anything")
	assert.False(t, ok)
	assert.ErrorIs(t, err, path.ErrBadPattern)
}

func TestDelegatedRoleRejectsPathsWithPathHashPrefixes(t *testing.T) {
	// A delegated role selects targets by path or by path hash prefix, never
	// both. Such a role must be rejected on parse rather than accepted with
	// "paths" silently taking precedence.
	const role = `{"name":"r","keyids":[],"threshold":1,"terminating":false,%s}`
	const targets = `{"signatures":[],"signed":{"_type":"targets","spec_version":"1.0.31","version":1,` +
		`"expires":"2030-01-01T00:00:00Z","targets":{},"delegations":{"keys":{},"roles":[%s]}}}`

	tests := []struct {
		name    string
		fields  string
		wantErr bool
	}{
		{name: "paths only", fields: `"paths":["a/*"]`},
		{name: "path hash prefixes only", fields: `"path_hash_prefixes":["ab"]`},
		{name: "paths with null path hash prefixes", fields: `"paths":["a/*"],"path_hash_prefixes":null`},
		{name: "both", fields: `"paths":["a/*"],"path_hash_prefixes":["ab"]`, wantErr: true},
		{name: "both empty", fields: `"paths":[],"path_hash_prefixes":[]`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			roleJSON := fmt.Sprintf(role, tt.fields)

			var parsed DelegatedRole
			roleErr := json.Unmarshal([]byte(roleJSON), &parsed)
			// The same role inside targets metadata, as a client receives it.
			_, targetsErr := Targets().FromBytes(fmt.Appendf(nil, targets, roleJSON))

			for _, err := range []error{roleErr, targetsErr} {
				if !tt.wantErr {
					assert.NoError(t, err)
					continue
				}
				assert.ErrorIs(t, err, &ErrValue{})
				assert.ErrorContains(t, err, `not allowed to have both "paths" and "path_hash_prefixes" present`)
			}
		})
	}
}

func TestGetRolesForTargetInvalidPattern(t *testing.T) {
	// An invalid pattern must not hide a role whose other patterns match.
	delegations := &Delegations{
		Roles: []DelegatedRole{
			{Name: "first", Paths: []string{"foo/[bad", "foo/*"}, Terminating: true},
			{Name: "second", Paths: []string{"*/*"}},
		},
	}
	expected := []RoleResult{
		{Name: "first", Terminating: true},
		{Name: "second", Terminating: false},
	}
	assert.Equal(t, expected, delegations.GetRolesForTarget("foo/x"))

	ok, err := delegations.Roles[0].IsDelegatedPath("foo/x")
	assert.True(t, ok)
	assert.NoError(t, err)

	// Without a matching pattern the error is still reported, regardless of order.
	role := &DelegatedRole{Paths: []string{"foo/[bad", "foo/y"}}
	ok, err = role.IsDelegatedPath("foo/x")
	assert.False(t, ok)
	assert.ErrorIs(t, err, path.ErrBadPattern)
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

// TestIsExpiredTable verifies that each top-level role's default-constructed
// metadata is already expired and that a future-dated expiry makes it not
// expired. Replaces the per-role TestIsExpiredRoot/Snapshot/Timestamp/Targets.
func TestIsExpiredTable(t *testing.T) {
	// The closure constructs both metadata copies (default + future-dated) and
	// reports whether each is expired relative to a freshly-sampled "now". The
	// short sleep guarantees the no-arg constructor's "expires == time.Now()"
	// is reliably in the past by the time IsExpired is asked.
	tests := []struct {
		name     string
		expirers func(expire time.Time) (defaultExpired, futureExpired bool)
	}{
		{
			name: "root",
			expirers: func(expire time.Time) (bool, bool) {
				def := Root()
				time.Sleep(1 * time.Microsecond)
				future := Root(expire)
				now := time.Now().UTC()
				return def.Signed.IsExpired(now), future.Signed.IsExpired(now)
			},
		},
		{
			name: "snapshot",
			expirers: func(expire time.Time) (bool, bool) {
				def := Snapshot()
				time.Sleep(1 * time.Microsecond)
				future := Snapshot(expire)
				now := time.Now().UTC()
				return def.Signed.IsExpired(now), future.Signed.IsExpired(now)
			},
		},
		{
			name: "timestamp",
			expirers: func(expire time.Time) (bool, bool) {
				def := Timestamp()
				time.Sleep(1 * time.Microsecond)
				future := Timestamp(expire)
				now := time.Now().UTC()
				return def.Signed.IsExpired(now), future.Signed.IsExpired(now)
			},
		},
		{
			name: "targets",
			expirers: func(expire time.Time) (bool, bool) {
				def := Targets()
				time.Sleep(1 * time.Microsecond)
				future := Targets(expire)
				now := time.Now().UTC()
				return def.Signed.IsExpired(now), future.Signed.IsExpired(now)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expire := time.Now().AddDate(0, 0, 2).UTC()
			defaultExpired, futureExpired := tt.expirers(expire)
			assert.True(t, defaultExpired, "default-constructed metadata should be expired")
			assert.False(t, futureExpired, "metadata with future expiry should not be expired")
		})
	}
}

func TestSignReplacesSignatureFromSameKey(t *testing.T) {
	root := Root(fixedExpire)
	root.Signed.Roles[ROOT].Threshold = 2
	signers := []signature.Signer{}
	for range 2 {
		_, private, err := ed25519.GenerateKey(nil)
		assert.NoError(t, err)
		key, err := KeyFromPublicKey(private.Public())
		assert.NoError(t, err)
		assert.NoError(t, root.Signed.AddKey(key, ROOT))
		signer, err := signature.LoadSigner(private, crypto.Hash(0))
		assert.NoError(t, err)
		signers = append(signers, signer)
	}

	oldSigA, err := root.Sign(signers[0])
	assert.NoError(t, err)
	oldSigB, err := root.Sign(signers[1])
	assert.NoError(t, err)

	// signing again after a change replaces the signature at its position
	root.Signed.Version++
	sigA, err := root.Sign(signers[0])
	assert.NoError(t, err)
	assert.NotEqual(t, oldSigA.Signature, sigA.Signature)
	assert.Equal(t, []Signature{*sigA, *oldSigB}, root.Signatures)
	sigB, err := root.Sign(signers[1])
	assert.NoError(t, err)
	assert.Equal(t, []Signature{*sigA, *sigB}, root.Signatures)
	assert.NoError(t, root.VerifyDelegate(ROOT, root))

	// the signed metadata can be loaded again
	data, err := root.ToBytes(false)
	assert.NoError(t, err)
	_, err = Root().FromBytes(data)
	assert.NoError(t, err)

	// duplicates that are already present are dropped as well, otherwise a
	// stale one could be picked over the new signature
	root.Signed.Version++
	root.Signatures = append(root.Signatures, *sigA)
	newSigA, err := root.Sign(signers[0])
	assert.NoError(t, err)
	newSigB, err := root.Sign(signers[1])
	assert.NoError(t, err)
	assert.Equal(t, []Signature{*newSigA, *newSigB}, root.Signatures)
	assert.NoError(t, root.VerifyDelegate(ROOT, root))
}

func TestSignRejectsSignatureThatDoesNotVerify(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	rsaPSS, err := signature.LoadRSAPSSSigner(rsaKey, crypto.SHA256, &rsa.PSSOptions{Hash: crypto.SHA256})
	assert.NoError(t, err)
	// LoadSigner returns a PKCS #1 v1.5 signer for RSA keys, while the key
	// is published with the rsassa-pss-sha256 scheme
	rsaPKCS1v15, err := signature.LoadSigner(rsaKey, crypto.SHA256)
	assert.NoError(t, err)
	ecdsaSHA256, err := signature.LoadSigner(ecdsaKey, crypto.SHA256)
	assert.NoError(t, err)
	// the key is published with the ecdsa-sha2-nistp256 scheme, i.e. SHA-256
	ecdsaSHA384, err := signature.LoadSigner(ecdsaKey, crypto.SHA384)
	assert.NoError(t, err)

	for name, tc := range map[string]struct {
		signer   signature.Signer
		verifies bool
	}{
		"rsa pss":      {rsaPSS, true},
		"rsa pkcs1v15": {rsaPKCS1v15, false},
		"ecdsa sha256": {ecdsaSHA256, true},
		"ecdsa sha384": {ecdsaSHA384, false},
	} {
		t.Run(name, func(t *testing.T) {
			root := Root(fixedExpire)
			sig, err := root.Sign(tc.signer)
			if tc.verifies {
				assert.NoError(t, err)
				assert.Equal(t, []Signature{*sig}, root.Signatures)
				return
			}
			assert.ErrorIs(t, err, &ErrUnsignedMetadata{})
			assert.ErrorContains(t, err, "does not verify")
			assert.Nil(t, sig)
			assert.Empty(t, root.Signatures)
		})
	}
}

func TestUnrecognizedFieldRolesSigned(t *testing.T) {
	// unrecognized field to test
	// added to the Signed portion of each role type
	testUnrecognizedField := map[string]any{"test": "true"}

	root := Root(fixedExpire)
	root.Signed.UnrecognizedFields = testUnrecognizedField
	rootJSON, err := root.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45Z\",\"keys\":{},\"roles\":{\"root\":{\"keyids\":[],\"threshold\":1},\"snapshot\":{\"keyids\":[],\"threshold\":1},\"targets\":{\"keyids\":[],\"threshold\":1},\"timestamp\":{\"keyids\":[],\"threshold\":1}},\"spec_version\":\""+SPECIFICATION_VERSION+"\",\"test\":\"true\",\"version\":1}}"), rootJSON)

	targets := Targets(fixedExpire)
	targets.Signed.UnrecognizedFields = testUnrecognizedField
	targetsJSON, err := targets.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"targets\",\"expires\":\"2030-08-15T14:30:45Z\",\"spec_version\":\""+SPECIFICATION_VERSION+"\",\"targets\":{},\"test\":\"true\",\"version\":1}}"), targetsJSON)

	snapshot := Snapshot(fixedExpire)
	snapshot.Signed.UnrecognizedFields = testUnrecognizedField
	snapshotJSON, err := snapshot.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"snapshot\",\"expires\":\"2030-08-15T14:30:45Z\",\"meta\":{\"targets.json\":{\"version\":1}},\"spec_version\":\""+SPECIFICATION_VERSION+"\",\"test\":\"true\",\"version\":1}}"), snapshotJSON)

	timestamp := Timestamp(fixedExpire)
	timestamp.Signed.UnrecognizedFields = testUnrecognizedField
	timestampJSON, err := timestamp.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"timestamp\",\"expires\":\"2030-08-15T14:30:45Z\",\"meta\":{\"snapshot.json\":{\"version\":1}},\"spec_version\":\""+SPECIFICATION_VERSION+"\",\"test\":\"true\",\"version\":1}}"), timestampJSON)
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
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45Z\",\"keys\":{},\"roles\":{\"root\":{\"keyids\":[],\"threshold\":1},\"snapshot\":{\"keyids\":[],\"threshold\":1},\"targets\":{\"keyids\":[],\"threshold\":1},\"timestamp\":{\"keyids\":[],\"threshold\":1}},\"spec_version\":\""+SPECIFICATION_VERSION+"\",\"version\":1},\"test\":\"true\"}"), rootJSON)
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
	assert.Equal(t, []byte("{\"signatures\":[],\"signed\":{\"_type\":\"targets\",\"expires\":\"2030-08-15T14:30:45Z\",\"spec_version\":\""+SPECIFICATION_VERSION+"\",\"targets\":{\"testTarget\":{\"custom\":{\"test\":true},\"hashes\":{},\"length\":0}},\"version\":1}}"), targetsJSON)
}

func TestFromBytes(t *testing.T) {
	root := Root(fixedExpire)
	assert.Equal(t, fixedExpireTruncated, root.Signed.Expires)

	_, err := root.FromBytes(testRootBytes)
	assert.NoError(t, err)

	// parsed metadata keeps the precision it was signed with, so this is the
	// untruncated fixture value rather than what the constructor would produce
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
	expectedRootBytes := bytes.ReplaceAll(testRootBytes, []byte(".0000001Z"), []byte("Z"))
	assert.Equal(t, expectedRootBytes, rootBytes)
}

func TestFromFile(t *testing.T) {
	root := Root(fixedExpire)
	_, err := root.FromFile(filepath.Join(TEST_REPOSITORY_DATA, "1.root.json"))
	assert.NoError(t, err)

	// parsed from disk, so the original precision is preserved
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

	// spec_version comes from the signed fixture, not from SPECIFICATION_VERSION
	assert.Equal(t, "1.0.31", root.Signed.SpecVersion)
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

	fileName := filepath.Join(tmpDir, "1.root.json")
	assert.NoFileExists(t, fileName)
	root, err := Root().FromBytes(testRootBytes)
	assert.NoError(t, err)

	err = root.ToFile(fileName, false)
	assert.NoError(t, err)

	assert.FileExists(t, fileName)
	data, err := os.ReadFile(fileName)
	assert.NoError(t, err)
	// This root was parsed from bytes rather than constructed, so its expires is
	// written back exactly as it arrived. Rewriting it here would change the
	// signed bytes and invalidate the signature over them.
	assert.Equal(t, testRootBytes, data)

	err = os.RemoveAll(tmpDir)
	assert.NoError(t, err)
	assert.NoFileExists(t, fileName)

}

func TestVerifyDelegate(t *testing.T) {
	root := Root(fixedExpire)
	err := root.VerifyDelegate("test", root)
	assert.EqualError(t, err, "value error: no delegation found for test")
	root.Signed.Roles["test"] = nil
	err = root.VerifyDelegate("test", root)
	assert.EqualError(t, err, "value error: no delegation found for test")
	root.Signed.Roles["test"] = &Role{KeyIDs: []string{"nil-key"}, Threshold: 1}
	root.Signed.Keys["nil-key"] = nil
	err = root.VerifyDelegate("test", root)
	assert.EqualError(t, err, "value error: key with ID nil-key not found in test keyids")

	targets := Targets(fixedExpire)
	err = targets.VerifyDelegate("test", targets)
	assert.EqualError(t, err, "value error: no delegations found")

	key, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	delegateeKey, _ := KeyFromPublicKey(key)
	delegateeKeyID, err := delegateeKey.ID()
	assert.NoError(t, err)
	delegations := &Delegations{
		Keys: map[string]*Key{
			delegateeKeyID: delegateeKey,
		},
		Roles: []DelegatedRole{
			{
				Name:      "test",
				KeyIDs:    []string{delegateeKeyID},
				Threshold: 1,
			},
		},
	}

	targets.Signed.Delegations = delegations
	err = targets.VerifyDelegate("root", targets)
	assert.Errorf(t, err, "Verifying test failed, not enough signatures, got %d, want %d", 0, 1)
	err = targets.VerifyDelegate("test", targets)
	assert.Errorf(t, err, "Verifying test failed, not enough signatures, got %d, want %d", 0, 1)

	err = targets.VerifyDelegate("non-existing", root)
	assert.EqualError(t, err, "value error: no delegation found for non-existing")
	err = targets.VerifyDelegate("non-existing", targets)
	assert.EqualError(t, err, "value error: no delegation found for non-existing")

	delegations.Keys["incorrectkey"] = delegations.Keys[delegateeKeyID]
	delete(delegations.Keys, delegateeKeyID)
	err = targets.VerifyDelegate("test", root)
	assert.Errorf(t, err, "key with ID %s not found in test keyids", delegateeKeyID)

	timestamp := Timestamp(fixedExpire)
	err = timestamp.VerifyDelegate("test", timestamp)
	assert.EqualError(t, err, "type error: call is valid only on delegator metadata (should be either root or targets)")

	snapshot := Snapshot(fixedExpire)
	err = snapshot.VerifyDelegate("test", snapshot)
	assert.EqualError(t, err, "type error: call is valid only on delegator metadata (should be either root or targets)")
}

func TestAddKeyRejectsNilKey(t *testing.T) {
	root := Root(fixedExpire)
	assert.EqualError(t, root.Signed.AddKey(nil, ROOT), "value error: key must not be nil")

	targets := Targets(fixedExpire)
	targets.Signed.Delegations = &Delegations{Keys: map[string]*Key{}}
	assert.EqualError(t, targets.Signed.AddKey(nil, "role"), "value error: key must not be nil")
}

func TestTargetsAddKeyWithoutDelegatedRole(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)
	key, err := KeyFromPublicKey(publicKey)
	assert.NoError(t, err)

	for _, tc := range []struct {
		name  string
		keys  map[string]*Key
		roles []DelegatedRole
	}{
		{"zero value delegations", nil, nil},
		{"initialized keys", map[string]*Key{}, nil},
		{"empty roles", map[string]*Key{}, []DelegatedRole{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets := Targets(fixedExpire)
			targets.Signed.Delegations = &Delegations{Keys: tc.keys, Roles: tc.roles}
			assert.EqualError(t, targets.Signed.AddKey(key, "missing"), "value error: delegated role missing doesn't exist")
			if tc.keys == nil {
				assert.Nil(t, targets.Signed.Delegations.Keys)
			} else {
				assert.Empty(t, targets.Signed.Delegations.Keys)
			}
		})
	}
}

func TestVerifyDelegateThreshold(t *testing.T) {
	root := Root(fixedExpire)
	err := root.VerifyDelegate("test", root)
	assert.EqualError(t, err, "value error: no delegation found for test")

	targets := Targets(fixedExpire)
	err = targets.VerifyDelegate("test", targets)
	assert.EqualError(t, err, "value error: no delegations found")

	key, _, err := ed25519.GenerateKey(nil)
	assert.NoError(t, err)

	delegateeKey, _ := KeyFromPublicKey(key)
	delegateeKeyID, err := delegateeKey.ID()
	assert.NoError(t, err)
	delegations := &Delegations{
		Keys: map[string]*Key{
			delegateeKeyID: delegateeKey,
		},
		Roles: []DelegatedRole{
			{
				Name:      "test",
				KeyIDs:    []string{delegateeKeyID},
				Threshold: 0,
			},
		},
	}
	targets.Signed.Delegations = delegations
	err = targets.VerifyDelegate("test", root)
	assert.ErrorIs(t, err, &ErrValue{})
	assert.EqualError(t, err, "value error: insufficient threshold (0) configured for test")
	err = targets.VerifyDelegate("test", targets)
	assert.ErrorIs(t, err, &ErrValue{})
	assert.EqualError(t, err, "value error: insufficient threshold (0) configured for test")
}

// Regression: one ECDSA public key registered under both
// KeyTypeECDSA_SHA2_P256 ("ecdsa") and KeyTypeECDSA_SHA2_P256_COMPAT
// ("ecdsa-sha2-nistp256") must count as a single threshold contribution.
// Canonical-JSON-based Key.ID() includes `keytype`, so the two records
// produce distinct keyIDs from one PEM; a keyID-keyed threshold map would
// accept a single private-key holder as satisfying threshold=2.
func TestVerifyDelegateDuplicateKeyTypeECDSA(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NoError(t, err)

	// keyA is what KeyFromPublicKey produces: Type=KeyTypeECDSA_SHA2_P256.
	keyA, err := KeyFromPublicKey(&privKey.PublicKey)
	assert.NoError(t, err)
	// keyB shares the same PEM under the COMPAT type string.
	keyB := &Key{
		Type:   KeyTypeECDSA_SHA2_P256_COMPAT,
		Scheme: keyA.Scheme,
		Value:  keyA.Value,
	}

	targets := Targets(fixedExpire)
	payload, err := cjson.EncodeCanonical(targets.Signed)
	assert.NoError(t, err)
	signer, err := signature.LoadSignerVerifier(privKey, crypto.SHA256)
	assert.NoError(t, err)
	sigBytes, err := signer.SignMessage(bytes.NewReader(payload))
	assert.NoError(t, err)

	assertDuplicatePublicKeyCountsOnce(t, keyA, keyB, targets, sigBytes)
}

// Regression: KeyFromPublicKey labelled every ECDSA key "ecdsa-sha2-nistp256".
// The scheme selects the verification digest and is part of the key ID, so a
// P-384 key could not be signed with through Sign and verified.
func TestECDSASchemeFollowsCurve(t *testing.T) {
	for _, tc := range []struct {
		curve  elliptic.Curve
		hash   crypto.Hash
		scheme string
	}{
		{elliptic.P256(), crypto.SHA256, KeySchemeECDSA_SHA2_P256},
		{elliptic.P384(), crypto.SHA384, KeySchemeECDSA_SHA2_P384},
	} {
		t.Run(tc.curve.Params().Name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			assert.NoError(t, err)

			key, err := KeyFromPublicKey(&privKey.PublicKey)
			assert.NoError(t, err)
			assert.Equal(t, KeyTypeECDSA_SHA2_P256, key.Type)
			assert.Equal(t, tc.scheme, key.Scheme)
			keyID, err := key.ID()
			assert.NoError(t, err)

			root := Root(fixedExpire)
			assert.NoError(t, root.Signed.AddKey(key, ROOT))

			signer, err := signature.LoadECDSASigner(privKey, tc.hash)
			assert.NoError(t, err)
			sig, err := root.Sign(signer)
			assert.NoError(t, err)
			assert.Equal(t, keyID, sig.KeyID)

			assert.NoError(t, root.VerifyDelegate(ROOT, root))
		})
	}
}

func TestECDSAUnsupportedCurveRejected(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P224(), elliptic.P521()} {
		t.Run(curve.Params().Name, func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(curve, rand.Reader)
			assert.NoError(t, err)

			_, err = KeyFromPublicKey(&privKey.PublicKey)
			assert.EqualError(t, err, "unsupported ecdsa curve "+curve.Params().Name+": only P-256 and P-384 are supported")

			signer, err := signature.LoadECDSASigner(privKey, crypto.SHA256)
			assert.NoError(t, err)
			root := Root(fixedExpire)
			_, err = root.Sign(signer)
			assert.ErrorContains(t, err, "unsupported ecdsa curve")
			assert.Empty(t, root.Signatures)
		})
	}

	_, err := KeyFromPublicKey(&ecdsa.PublicKey{})
	assert.EqualError(t, err, "unsupported ecdsa public key: no curve set")
}

// Migration: a root written before the scheme followed the curve lists a key
// that is not on P-256 under the "ecdsa-sha2-nistp256" scheme and the key ID
// that goes with it. Sign no longer writes that key ID, so the next root needs
// a signature built by hand for the old root, next to the one Sign writes for
// the new root.
func TestECDSALegacyRootKeyMigration(t *testing.T) {
	for _, tc := range []struct {
		name        string
		legacyCurve elliptic.Curve
		nextCurve   elliptic.Curve // nil keeps the legacy key
		nextHash    crypto.Hash
	}{
		{"P-384 key kept under its new key ID", elliptic.P384(), nil, crypto.SHA384},
		{"P-521 key replaced by a P-256 key", elliptic.P521(), elliptic.P256(), crypto.SHA256},
	} {
		t.Run(tc.name, func(t *testing.T) {
			legacyPriv, err := ecdsa.GenerateKey(tc.legacyCurve, rand.Reader)
			assert.NoError(t, err)
			legacyPEM, err := cryptoutils.MarshalPublicKeyToPEM(&legacyPriv.PublicKey)
			assert.NoError(t, err)
			legacyKey := &Key{
				Type:   KeyTypeECDSA_SHA2_P256,
				Scheme: KeySchemeECDSA_SHA2_P256,
				Value:  KeyVal{PublicKey: string(legacyPEM)},
			}
			legacyID, err := legacyKey.ID()
			assert.NoError(t, err)

			oldRoot := Root(fixedExpire)
			assert.NoError(t, oldRoot.Signed.AddKey(legacyKey, ROOT))

			nextPriv := legacyPriv
			if tc.nextCurve != nil {
				nextPriv, err = ecdsa.GenerateKey(tc.nextCurve, rand.Reader)
				assert.NoError(t, err)
			}
			nextKey, err := KeyFromPublicKey(&nextPriv.PublicKey)
			assert.NoError(t, err)
			nextID, err := nextKey.ID()
			assert.NoError(t, err)
			assert.NotEqual(t, legacyID, nextID)

			nextRoot := Root(fixedExpire)
			nextRoot.Signed.Version = 2
			assert.NoError(t, nextRoot.Signed.AddKey(nextKey, ROOT))

			nextSigner, err := signature.LoadECDSASigner(nextPriv, tc.nextHash)
			assert.NoError(t, err)
			nextSig, err := nextRoot.Sign(nextSigner)
			assert.NoError(t, err)
			assert.Equal(t, nextID, nextSig.KeyID)

			// the old root verifies the legacy key with SHA-256 under its old key ID
			payload, err := cjson.EncodeCanonical(nextRoot.Signed)
			assert.NoError(t, err)
			legacySigner, err := signature.LoadECDSASigner(legacyPriv, crypto.SHA256)
			assert.NoError(t, err)
			legacySigBytes, err := legacySigner.SignMessage(bytes.NewReader(payload))
			assert.NoError(t, err)
			legacySig := Signature{KeyID: legacyID, Signature: legacySigBytes}

			nextRoot.Signatures = []Signature{*nextSig, legacySig}
			assert.NoError(t, oldRoot.VerifyDelegate(ROOT, nextRoot))
			assert.NoError(t, nextRoot.VerifyDelegate(ROOT, nextRoot))

			nextRoot.Signatures = []Signature{*nextSig}
			assert.ErrorIs(t, oldRoot.VerifyDelegate(ROOT, nextRoot), &ErrUnsignedMetadata{})
			assert.NoError(t, nextRoot.VerifyDelegate(ROOT, nextRoot))

			nextRoot.Signatures = []Signature{legacySig}
			assert.NoError(t, oldRoot.VerifyDelegate(ROOT, nextRoot))
			assert.ErrorIs(t, nextRoot.VerifyDelegate(ROOT, nextRoot), &ErrUnsignedMetadata{})
		})
	}
}

// Regression: even without an alternate keytype, duplicate Ed25519 key records
// that resolve to the same public key must count as a single threshold
// contribution.
func TestVerifyDelegateDuplicatePublicKeyEd25519(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	keyA, err := KeyFromPublicKey(pubKey)
	assert.NoError(t, err)
	keyB := &Key{
		Type:   keyA.Type,
		Scheme: "ed25519-duplicate",
		Value:  keyA.Value,
	}

	targets := Targets(fixedExpire)
	payload, err := cjson.EncodeCanonical(targets.Signed)
	assert.NoError(t, err)
	signer, err := signature.LoadSignerVerifier(privKey, crypto.Hash(0))
	assert.NoError(t, err)
	sigBytes, err := signer.SignMessage(bytes.NewReader(payload))
	assert.NoError(t, err)

	assertDuplicatePublicKeyCountsOnce(t, keyA, keyB, targets, sigBytes)
}

// Regression: duplicate RSA key records that resolve to the same public key
// must count as a single threshold contribution.
func TestVerifyDelegateDuplicatePublicKeyRSA(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	keyA, err := KeyFromPublicKey(&privKey.PublicKey)
	assert.NoError(t, err)
	keyB := &Key{
		Type:   keyA.Type,
		Scheme: "rsassa-pss-sha256-duplicate",
		Value:  keyA.Value,
	}

	targets := Targets(fixedExpire)
	payload, err := cjson.EncodeCanonical(targets.Signed)
	assert.NoError(t, err)
	signer, err := signature.LoadRSAPSSSignerVerifier(privKey, crypto.SHA256, nil)
	assert.NoError(t, err)
	sigBytes, err := signer.SignMessage(bytes.NewReader(payload))
	assert.NoError(t, err)

	assertDuplicatePublicKeyCountsOnce(t, keyA, keyB, targets, sigBytes)
}

func assertDuplicatePublicKeyCountsOnce(t *testing.T, keyA, keyB *Key, targets *Metadata[TargetsType], sigBytes []byte) {
	t.Helper()

	keyIDA, err := keyA.ID()
	assert.NoError(t, err)
	keyIDB, err := keyB.ID()
	assert.NoError(t, err)
	assert.NotEqual(t, keyIDA, keyIDB, "test must exercise two keyIDs for one public key")

	targets.Signatures = []Signature{
		{KeyID: keyIDA, Signature: sigBytes},
		{KeyID: keyIDB, Signature: sigBytes},
	}

	root := Root(fixedExpire)
	root.Signed.Keys[keyIDA] = keyA
	root.Signed.Keys[keyIDB] = keyB
	root.Signed.Roles[TARGETS] = &Role{
		KeyIDs:    []string{keyIDA, keyIDB},
		Threshold: 2,
	}

	err = root.VerifyDelegate(TARGETS, targets)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{})
	assert.ErrorContains(t, err, "got 1, want 2")

	// Threshold of 1 still satisfied by the one underlying key.
	root.Signed.Roles[TARGETS].Threshold = 1
	err = root.VerifyDelegate(TARGETS, targets)
	assert.NoError(t, err)
}

func TestVerifyLengthHashesTargetFiles(t *testing.T) {
	targetFiles := TargetFile()
	targetFiles.Hashes = map[string]HexBytes{}

	// Per TUF spec, empty hashes must be rejected
	data := []byte{}
	err := targetFiles.VerifyLengthHashes(data)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hashes must not be empty")

	data = []byte("some data")

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

func TestToPublicKeyEd25519InvalidLength(t *testing.T) {
	// A valid-hex but wrong-length ed25519 public key must be rejected: a
	// non-32-byte key panics in ed25519.Verify during delegate verification.
	key := &Key{
		Type:   KeyTypeEd25519,
		Scheme: KeySchemeEd25519,
		Value:  KeyVal{PublicKey: "abcd"}, // decodes to 2 bytes
	}

	_, err := key.ToPublicKey()
	assert.ErrorContains(t, err, "invalid ed25519 public key length")

	// And it must not panic when reached through VerifyDelegate.
	root := Root(time.Now().AddDate(1, 0, 0).UTC())
	err = root.Signed.AddKey(key, ROOT)
	assert.NoError(t, err)
	assert.NotPanics(t, func() {
		err = root.VerifyDelegate(ROOT, root)
	})
	assert.Error(t, err)
}

func TestSignVerifyMLDSA(t *testing.T) {
	for _, params := range []mldsa.Parameters{
		mldsa.MLDSA44(),
		mldsa.MLDSA65(),
		mldsa.MLDSA87(),
	} {
		priv, err := mldsa.GenerateKey(params)
		assert.NoError(t, err)

		signer, err := signature.LoadSignerVerifier(priv, crypto.Hash(0))
		assert.NoError(t, err)

		targets := Targets(time.Now().Add(time.Hour))

		// Create delegation
		key, err := KeyFromPublicKey(priv.PublicKey())
		assert.NoError(t, err)
		keyID, err := key.ID()
		assert.NoError(t, err)

		root := Root(time.Now().Add(time.Hour))
		root.Signed.Keys[keyID] = key
		root.Signed.Roles[TARGETS] = &Role{
			KeyIDs:    []string{keyID},
			Threshold: 1,
		}

		sig, err := targets.Sign(signer)
		assert.NoError(t, err)
		assert.NotNil(t, sig)
		assert.Equal(t, keyID, sig.KeyID)

		err = root.VerifyDelegate(TARGETS, targets)
		assert.NoError(t, err)
	}
}

func TestMLDSAVerificationFailures(t *testing.T) {
	// 1. Test extractMLDSAVersion with invalid schemes directly
	invalidSchemes := []string{
		"ml-dsa-44",     // missing slash
		"ml-dsa-44/0",   // version 0 is invalid
		"ml-dsa-44/256", // version 256 is out of byte bounds
		"ml-dsa/1",      // invalid prefix
		"invalid",
	}
	for _, scheme := range invalidSchemes {
		_, err := extractMLDSAVersion(scheme)
		assert.Error(t, err, "expected error for scheme: %s", scheme)
	}

	// 2. Test ToPublicKey with invalid PEM
	invalidPEMKey := &Key{
		Type:   KeyTypeMLDSA,
		Scheme: KeySchemeMLDSA44,
		Value: KeyVal{
			PublicKey: "not a valid pem block",
		},
	}
	_, err := invalidPEMKey.ToPublicKey()
	assert.Error(t, err)

	// 3. Test KeyFromPublicKey with nil and uninitialized keys
	_, err = KeyFromPublicKey((*mldsa.PublicKey)(nil))
	assert.Error(t, err)

	_, err = KeyFromPublicKey(&mldsa.PublicKey{})
	assert.Error(t, err)

	// 4. Test VerifyDelegate with mutated signature
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	assert.NoError(t, err)
	signer, err := signature.LoadSignerVerifier(priv, crypto.Hash(0))
	assert.NoError(t, err)

	targets := Targets(time.Now().Add(time.Hour))
	key, err := KeyFromPublicKey(priv.PublicKey())
	assert.NoError(t, err)
	keyID, err := key.ID()
	assert.NoError(t, err)

	root := Root(time.Now().Add(time.Hour))
	root.Signed.Keys[keyID] = key
	root.Signed.Roles[TARGETS] = &Role{
		KeyIDs:    []string{keyID},
		Threshold: 1,
	}

	_, err = targets.Sign(signer)
	assert.NoError(t, err)

	// mutate the signature to make it invalid
	targets.Signatures[0].Signature[0] ^= 0xFF

	err = root.VerifyDelegate(TARGETS, targets)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not enough signatures")
}

func TestVerifyDelegateDuplicatePublicKeyMLDSA(t *testing.T) {
	priv, err := mldsa.GenerateKey(mldsa.MLDSA44())
	assert.NoError(t, err)

	keyA, err := KeyFromPublicKey(priv.PublicKey())
	assert.NoError(t, err)
	keyB := &Key{
		Type:               keyA.Type,
		Scheme:             keyA.Scheme,
		Value:              keyA.Value,
		UnrecognizedFields: map[string]any{"duplicate": true},
	}

	targets := Targets(fixedExpire)
	payload, err := cjson.EncodeCanonical(targets.Signed)
	assert.NoError(t, err)
	signer, err := signature.LoadSignerVerifier(priv, crypto.Hash(0))
	assert.NoError(t, err)

	payloadToSign, err := preparePayload(keyA, payload)
	assert.NoError(t, err)
	sigBytes, err := signer.SignMessage(bytes.NewReader(payloadToSign))
	assert.NoError(t, err)

	assertDuplicatePublicKeyCountsOnce(t, keyA, keyB, targets, sigBytes)
}

func TestMain(m *testing.M) {

	repoPath := "../internal/testutils/repository_data/repository/metadata"
	targetsPath := "../internal/testutils/repository_data/repository/targets"
	keystorePath := "../internal/testutils/repository_data/keystore"
	err := testutils.SetupTestDirs(repoPath, targetsPath, keystorePath)
	defer testutils.Cleanup()

	if err != nil {
		log.Error(err, "failed to setup test dirs")
		os.Exit(1)
	}
	m.Run()
}

func TestCheckTypeMalformedMetadata(t *testing.T) {
	// Test that malformed metadata returns errors instead of panicking
	testCases := []struct {
		name        string
		input       string
		expectedErr string
	}{
		{
			name:        "empty object",
			input:       "{}",
			expectedErr: "metadata 'signed' field is missing or not an object",
		},
		{
			name:        "signed is null",
			input:       `{"signed": null}`,
			expectedErr: "metadata 'signed' field is missing or not an object",
		},
		{
			name:        "signed is string",
			input:       `{"signed": "not_a_map"}`,
			expectedErr: "metadata 'signed' field is missing or not an object",
		},
		{
			name:        "signed is number",
			input:       `{"signed": 123}`,
			expectedErr: "metadata 'signed' field is missing or not an object",
		},
		{
			name:        "signed is array",
			input:       `{"signed": [1, 2, 3]}`,
			expectedErr: "metadata 'signed' field is missing or not an object",
		},
		{
			name:        "signed missing _type",
			input:       `{"signed": {}}`,
			expectedErr: "metadata '_type' field is missing or not a string",
		},
		{
			name:        "_type is null",
			input:       `{"signed": {"_type": null}}`,
			expectedErr: "metadata '_type' field is missing or not a string",
		},
		{
			name:        "_type is number",
			input:       `{"signed": {"_type": 123}}`,
			expectedErr: "metadata '_type' field is missing or not a string",
		},
		{
			name:        "_type is object",
			input:       `{"signed": {"_type": {}}}`,
			expectedErr: "metadata '_type' field is missing or not a string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test with all metadata types to ensure none panic
			_, err := Root().FromBytes([]byte(tc.input))
			assert.ErrorIs(t, err, &ErrValue{tc.expectedErr})

			_, err = Snapshot().FromBytes([]byte(tc.input))
			assert.ErrorIs(t, err, &ErrValue{tc.expectedErr})

			_, err = Targets().FromBytes([]byte(tc.input))
			assert.ErrorIs(t, err, &ErrValue{tc.expectedErr})

			_, err = Timestamp().FromBytes([]byte(tc.input))
			assert.ErrorIs(t, err, &ErrValue{tc.expectedErr})
		})
	}
}

func TestGenericRead(t *testing.T) {
	// Assert that it chokes correctly on an unknown metadata type
	badMetadata := "{\"signed\": {\"_type\": \"bad-metadata\"}}"
	_, err := Root().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - bad-metadata"})
	_, err = Snapshot().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - bad-metadata"})
	_, err = Targets().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - bad-metadata"})
	_, err = Timestamp().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - bad-metadata"})

	badMetadataPath := filepath.Join(testutils.RepoDir, "bad-metadata.json")
	err = os.WriteFile(badMetadataPath, []byte(badMetadata), 0644)
	assert.NoError(t, err)
	assert.FileExists(t, badMetadataPath)

	_, err = Root().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - bad-metadata"})
	_, err = Snapshot().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - bad-metadata"})
	_, err = Targets().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - bad-metadata"})
	_, err = Timestamp().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - bad-metadata"})

	err = os.RemoveAll(badMetadataPath)
	assert.NoError(t, err)
	assert.NoFileExists(t, badMetadataPath)
}

func TestGenericReadFromMismatchingRoles(t *testing.T) {
	// Test failing to load other roles from root metadata
	_, err := Snapshot().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - root"})
	_, err = Timestamp().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - root"})
	_, err = Targets().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - root"})

	// Test failing to load other roles from targets metadata
	_, err = Snapshot().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - targets"})
	_, err = Timestamp().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - targets"})
	_, err = Root().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - targets"})

	// Test failing to load other roles from timestamp metadata
	_, err = Snapshot().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - timestamp"})
	_, err = Targets().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - timestamp"})
	_, err = Root().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - timestamp"})

	// Test failing to load other roles from snapshot metadata
	_, err = Targets().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - snapshot"})
	_, err = Timestamp().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - snapshot"})
	_, err = Root().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - snapshot"})
}

func TestMDReadWriteFileExceptions(t *testing.T) {
	// Test writing to a file with bad filename
	badMetadataPath := filepath.Join(testutils.RepoDir, "bad-metadata.json")
	_, err := Root().FromFile(badMetadataPath)
	expectedErr := fs.PathError{
		Op:   "open",
		Path: badMetadataPath,
		Err:  fs.ErrNotExist,
	}
	assert.ErrorIs(t, err, expectedErr.Err)

	// Test serializing to a file with bad filename
	root := Root(fixedExpire)
	err = root.ToFile("", false)
	expectedErr = fs.PathError{
		Op:   "open",
		Path: "",
		Err:  fs.ErrNotExist,
	}
	assert.ErrorIs(t, err, expectedErr.Err)
}

func TestCompareFromBytesFromFileToBytes(t *testing.T) {
	rootPath := filepath.Join(testutils.RepoDir, "root.json")
	rootBytesWant, err := os.ReadFile(rootPath)
	assert.NoError(t, err)
	root, err := Root().FromFile(rootPath)
	assert.NoError(t, err)
	rootBytesActual, err := root.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(rootBytesWant), stripWhitespaces(rootBytesActual))

	targetsPath := filepath.Join(testutils.RepoDir, "targets.json")
	targetsBytesWant, err := os.ReadFile(targetsPath)
	assert.NoError(t, err)
	targets, err := Targets().FromFile(targetsPath)
	assert.NoError(t, err)
	targetsBytesActual, err := targets.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(targetsBytesWant), stripWhitespaces(targetsBytesActual))

	snapshotPath := filepath.Join(testutils.RepoDir, "snapshot.json")
	snapshotBytesWant, err := os.ReadFile(snapshotPath)
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromFile(snapshotPath)
	assert.NoError(t, err)
	snapshotBytesActual, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(snapshotBytesWant), stripWhitespaces(snapshotBytesActual))

	timestampPath := filepath.Join(testutils.RepoDir, "timestamp.json")
	timestampBytesWant, err := os.ReadFile(timestampPath)
	assert.NoError(t, err)
	timestamp, err := Timestamp().FromFile(timestampPath)
	assert.NoError(t, err)
	timestampBytesActual, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(timestampBytesWant), stripWhitespaces(timestampBytesActual))
}

// TestRoundtripFileTable verifies that each top-level role's metadata can
// be read from a fixture file, written back out, re-read, and reproduces
// identical bytes. Replaces the per-role TestRootReadWriteReadCompare,
// TestSnapshotReadWriteReadCompare, TestTargetsReadWriteReadCompare,
// TestTimestampReadWriteReadCompare.
func TestRoundtripFileTable(t *testing.T) {
	// roundtrip reads src, writes to dst, reads dst back, and returns the
	// canonical byte form of both copies for comparison.
	tests := []struct {
		name      string
		srcRel    string
		roundtrip func(src, dst string) (srcBytes, dstBytes []byte, err error)
	}{
		{
			name:   "root",
			srcRel: "root.json",
			roundtrip: func(src, dst string) ([]byte, []byte, error) {
				m, err := Root().FromFile(src)
				if err != nil {
					return nil, nil, err
				}
				if err := m.ToFile(dst, false); err != nil {
					return nil, nil, err
				}
				m2, err := Root().FromFile(dst)
				if err != nil {
					return nil, nil, err
				}
				a, err := m.ToBytes(false)
				if err != nil {
					return nil, nil, err
				}
				b, err := m2.ToBytes(false)
				return a, b, err
			},
		},
		{
			name:   "snapshot",
			srcRel: "snapshot.json",
			roundtrip: func(src, dst string) ([]byte, []byte, error) {
				m, err := Snapshot().FromFile(src)
				if err != nil {
					return nil, nil, err
				}
				if err := m.ToFile(dst, false); err != nil {
					return nil, nil, err
				}
				m2, err := Snapshot().FromFile(dst)
				if err != nil {
					return nil, nil, err
				}
				a, err := m.ToBytes(false)
				if err != nil {
					return nil, nil, err
				}
				b, err := m2.ToBytes(false)
				return a, b, err
			},
		},
		{
			name:   "targets",
			srcRel: "targets.json",
			roundtrip: func(src, dst string) ([]byte, []byte, error) {
				m, err := Targets().FromFile(src)
				if err != nil {
					return nil, nil, err
				}
				if err := m.ToFile(dst, false); err != nil {
					return nil, nil, err
				}
				m2, err := Targets().FromFile(dst)
				if err != nil {
					return nil, nil, err
				}
				a, err := m.ToBytes(false)
				if err != nil {
					return nil, nil, err
				}
				b, err := m2.ToBytes(false)
				return a, b, err
			},
		},
		{
			name:   "timestamp",
			srcRel: "timestamp.json",
			roundtrip: func(src, dst string) ([]byte, []byte, error) {
				m, err := Timestamp().FromFile(src)
				if err != nil {
					return nil, nil, err
				}
				if err := m.ToFile(dst, false); err != nil {
					return nil, nil, err
				}
				m2, err := Timestamp().FromFile(dst)
				if err != nil {
					return nil, nil, err
				}
				a, err := m.ToBytes(false)
				if err != nil {
					return nil, nil, err
				}
				b, err := m2.ToBytes(false)
				return a, b, err
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := filepath.Join(testutils.RepoDir, tt.srcRel)
			dst := src + ".tmp"
			t.Cleanup(func() { _ = os.RemoveAll(dst) })

			a, b, err := tt.roundtrip(src, dst)
			assert.NoError(t, err)
			assert.Equal(t, a, b)
		})
	}
}

func stripWhitespaces(b []byte) []byte {
	tmp := strings.ReplaceAll(string(b), " ", "")
	return []byte(strings.ReplaceAll(tmp, "\t", ""))
}

func TestToFromBytes(t *testing.T) {
	// ROOT
	rootPath := filepath.Join(testutils.RepoDir, "root.json")
	data, err := os.ReadFile(rootPath)
	assert.NoError(t, err)
	root, err := Root().FromBytes(data)
	assert.NoError(t, err)

	// Comparate that from_bytes/to_bytes doesn't change the content
	// for two cases for the serializer: noncompact and compact.

	// Case 1: test noncompact by overriding the default serializer.
	rootBytesWant, err := root.ToBytes(true)

	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(rootBytesWant), stripWhitespaces(data))

	// Case 2: test compact by using the default serializer.
	root2, err := Root().FromBytes(rootBytesWant)
	assert.NoError(t, err)
	rootBytesActual, err := root2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(rootBytesWant), stripWhitespaces(rootBytesActual))

	// SNAPSHOT
	data, err = os.ReadFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	snapshotBytesWant, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(data), stripWhitespaces(snapshotBytesWant))

	// Case 2: test compact by using the default serializer.
	snapshot2, err := Snapshot().FromBytes(snapshotBytesWant)
	assert.NoError(t, err)
	snapshotBytesActual, err := snapshot2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(snapshotBytesWant), stripWhitespaces(snapshotBytesActual))

	// TARGETS
	data, err = os.ReadFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	targets, err := Targets().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	targetsBytesWant, err := targets.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(data), stripWhitespaces(targetsBytesWant))

	// Case 2: test compact by using the default serializer.
	targets2, err := Targets().FromBytes(targetsBytesWant)
	assert.NoError(t, err)
	targetsBytesActual, err := targets2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(targetsBytesWant), stripWhitespaces(targetsBytesActual))

	// TIMESTAMP
	data, err = os.ReadFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.NoError(t, err)
	timestamp, err := Timestamp().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	timestampBytesWant, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(data), stripWhitespaces(timestampBytesWant))

	// Case 2: test compact by using the default serializer.
	timestamp2, err := Timestamp().FromBytes(timestampBytesWant)
	assert.NoError(t, err)
	timestampBytesActual, err := timestamp2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, stripWhitespaces(timestampBytesWant), stripWhitespaces(timestampBytesActual))
}

func TestSignVerify(t *testing.T) {
	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)

	// Locate the public keys we need from root
	assert.NotEmpty(t, root.Signed.Roles[TARGETS].KeyIDs)
	targetsKeyID := root.Signed.Roles[TARGETS].KeyIDs[0]
	assert.NotEmpty(t, root.Signed.Roles[SNAPSHOT].KeyIDs)
	snapshotKeyID := root.Signed.Roles[SNAPSHOT].KeyIDs[0]
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	timestampKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]

	// Load sample metadata (targets) and assert ...
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	sig, _ := getSignatureByKeyID(targets.Signatures, targetsKeyID)
	data, err := targets.Signed.MarshalJSON()
	assert.NoError(t, err)

	// ... it has a single existing signature,
	assert.Equal(t, 1, len(targets.Signatures))

	// ... which is valid for the correct key.
	targetsKey := root.Signed.Keys[targetsKeyID]
	targetsPublicKey, err := targetsKey.ToPublicKey()
	assert.NoError(t, err)
	targetsHash := crypto.SHA256
	targetsVerifier, err := signature.LoadRSAPSSVerifier(
		targetsPublicKey.(*rsa.PublicKey),
		targetsHash,
		&rsa.PSSOptions{Hash: targetsHash},
	)
	assert.NoError(t, err)
	err = targetsVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.NoError(t, err)

	// ... and invalid for an unrelated key
	snapshotKey := root.Signed.Keys[snapshotKeyID]
	snapshotPublicKey, err := snapshotKey.ToPublicKey()
	assert.NoError(t, err)
	snapshotHash := crypto.SHA256
	snapshotVerifier, err := signature.LoadRSAPSSVerifier(
		snapshotPublicKey.(*rsa.PublicKey),
		snapshotHash,
		&rsa.PSSOptions{Hash: snapshotHash},
	)
	assert.NoError(t, err)
	err = snapshotVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")

	// Append a new signature with the unrelated key and assert that ...
	signer, err := rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "snapshot_key"))
	assert.NoError(t, err)
	snapshotSig, err := targets.Sign(signer)
	assert.NoError(t, err)
	// ... there are now two signatures, and
	assert.Equal(t, 2, len(targets.Signatures))
	// ... both are valid for the corresponding keys.
	err = targetsVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.NoError(t, err)
	err = snapshotVerifier.VerifySignature(bytes.NewReader(snapshotSig.Signature), bytes.NewReader(data))
	assert.NoError(t, err)
	// ... the returned (appended) signature is for snapshot key
	assert.Equal(t, snapshotSig.KeyID, snapshotKeyID)

	// Clear all signatures and add a new signature with the unrelated key and assert that ...
	signer, err = rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "timestamp_key"))
	assert.NoError(t, err)
	targets.ClearSignatures()
	assert.Equal(t, 0, len(targets.Signatures))
	timestampSig, err := targets.Sign(signer)
	assert.NoError(t, err)
	// ... there now is only one signature,
	assert.Equal(t, 1, len(targets.Signatures))
	// ... valid for that key.
	timestampKey := root.Signed.Keys[timestampKeyID]
	timestampPublicKey, err := timestampKey.ToPublicKey()
	assert.NoError(t, err)
	timestampHash := crypto.SHA256
	timestampVerifier, err := signature.LoadRSAPSSVerifier(
		timestampPublicKey.(*rsa.PublicKey),
		timestampHash,
		&rsa.PSSOptions{Hash: timestampHash},
	)
	assert.NoError(t, err)

	err = timestampVerifier.VerifySignature(bytes.NewReader(timestampSig.Signature), bytes.NewReader(data))
	assert.NoError(t, err)
	err = targetsVerifier.VerifySignature(bytes.NewReader(timestampSig.Signature), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")
}

func TestKeyVerifyFailures(t *testing.T) {
	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)

	// Locate the timestamp public key we need from root
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	timestampKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]

	// Load sample metadata (timestamp)
	timestamp, err := Timestamp().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.NoError(t, err)

	timestampSig, _ := getSignatureByKeyID(timestamp.Signatures, timestampKeyID)
	data, err := timestamp.Signed.MarshalJSON()
	assert.NoError(t, err)

	// Test failure on unknown type
	// Originally this test should cover unknown scheme,
	// but in our case scheme changes do not affect any
	// further functionality
	timestampKey := root.Signed.Keys[timestampKeyID]
	ttype := timestampKey.Type
	timestampKey.Type = "foo"

	timestampPublicKey, err := timestampKey.ToPublicKey()
	assert.Error(t, err, "unsupported public key type")
	timestampHash := crypto.SHA256
	timestampVerifier, err := signature.LoadVerifier(timestampPublicKey, timestampHash)
	assert.Error(t, err, "unsupported public key type")
	assert.Nil(t, timestampVerifier)

	timestampKey.Type = ttype
	timestampPublicKey, err = timestampKey.ToPublicKey()
	assert.NoError(t, err)
	timestampHash = crypto.SHA256
	timestampVerifier, err = signature.LoadRSAPSSVerifier(
		timestampPublicKey.(*rsa.PublicKey),
		timestampHash,
		&rsa.PSSOptions{Hash: timestampHash},
	)
	assert.NoError(t, err)
	err = timestampVerifier.VerifySignature(bytes.NewReader(timestampSig), bytes.NewReader(data))
	assert.NoError(t, err)
	timestampKey.Type = ttype

	// Test failure on broken public key data
	public := timestampKey.Value.PublicKey
	timestampKey.Value.PublicKey = "ffff"
	timestampBrokenPublicKey, err := timestampKey.ToPublicKey()
	assert.ErrorContains(t, err, "PEM decoding failed")
	timestampHash = crypto.SHA256
	timestampNilVerifier, err := signature.LoadVerifier(timestampBrokenPublicKey, timestampHash)
	assert.ErrorContains(t, err, "unsupported public key type")
	assert.Nil(t, timestampNilVerifier)
	timestampKey.Value.PublicKey = public

	// Test failure with invalid signature
	sigData := []byte("foo")
	h32 := sha256.Sum256(sigData)
	incorrectTimestampSig := h32[:]
	err = timestampVerifier.VerifySignature(bytes.NewReader(incorrectTimestampSig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")

	// Test failure with valid but incorrect signature
	anotherSig := root.Signatures[0]
	h32 = sha256.Sum256([]byte(anotherSig.Signature.String()))
	incorrectValidTimestampSig := h32[:]
	err = timestampVerifier.VerifySignature(bytes.NewReader(incorrectValidTimestampSig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")
}

func TestMetadataSignedIsExpired(t *testing.T) {
	// Use of Snapshot is arbitrary, we're just testing the base class
	// features with real data
	snapshot, err := Snapshot().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	assert.Equal(t, time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC), snapshot.Signed.Expires)

	// Test IsExpired with reference time provided
	// In the Go implementation IsExpired tests >= rather than only >,
	// which results in snapshot.Signed.Expires IsExpired check
	// being false by default, so we skip the default assertion
	isExpired := snapshot.Signed.IsExpired(snapshot.Signed.Expires.Add(time.Microsecond))
	assert.True(t, isExpired)
	isExpired = snapshot.Signed.IsExpired(snapshot.Signed.Expires.Add(-time.Microsecond))
	assert.False(t, isExpired)
}

func TestMetadataVerifyDelegate(t *testing.T) {

	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	role1, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "role1.json"))
	assert.NoError(t, err)
	role2, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "role2.json"))
	assert.NoError(t, err)
	// Test the expected delegation tree
	err = root.VerifyDelegate(ROOT, root)
	assert.NoError(t, err)
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.NoError(t, err)
	err = root.VerifyDelegate(TARGETS, targets)
	assert.NoError(t, err)
	err = targets.VerifyDelegate("role1", role1)
	assert.NoError(t, err)
	err = role1.VerifyDelegate("role2", role2)
	assert.NoError(t, err)

	// Only root and targets can verify delegates
	err = snapshot.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrType{"call is valid only on delegator metadata (should be either root or targets)"})
	// Verify fails for roles that are not delegated by delegator
	err = root.VerifyDelegate("role1", role1)
	assert.ErrorIs(t, err, &ErrValue{"no delegation found for role1"})
	err = targets.VerifyDelegate(TARGETS, targets)
	assert.ErrorIs(t, err, &ErrValue{"no delegation found for targets"})
	// Verify fails when delegator has no delegations
	err = role2.VerifyDelegate("role1", role1)
	assert.ErrorIs(t, err, &ErrValue{"no delegations found"})

	// Verify fails when delegate content is modified
	expires := snapshot.Signed.Expires
	snapshot.Signed.Expires = snapshot.Signed.Expires.Add(time.Hour * 24)
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying snapshot failed, not enough signatures, got 0, want 1"})
	snapshot.Signed.Expires = expires

	// Verify fails with verification error
	// (in this case signature is malformed)
	keyID := root.Signed.Roles[SNAPSHOT].KeyIDs[0]
	goodSig, idx := getSignatureByKeyID(snapshot.Signatures, keyID)
	assert.NotEmpty(t, goodSig)
	snapshot.Signatures[idx].Signature = []byte("foo")
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying snapshot failed, not enough signatures, got 0, want 1"})
	snapshot.Signatures[idx].Signature = goodSig

	// Verify fails if roles keys do not sign the metadata
	err = root.VerifyDelegate(TIMESTAMP, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying timestamp failed, not enough signatures, got 0, want 1"})

	// Add a key to snapshot role, make sure the new sig fails to verify
	tsKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]
	err = root.Signed.AddKey(root.Signed.Keys[tsKeyID], SNAPSHOT)
	assert.NoError(t, err)
	newSig := Signature{
		KeyID:     tsKeyID,
		Signature: []byte(strings.Repeat("ff", 64)),
	}
	snapshot.Signatures = append(snapshot.Signatures, newSig)

	// Verify succeeds if threshold is reached even if some signatures
	// fail to verify
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.NoError(t, err)

	// Verify fails if threshold of signatures is not reached
	root.Signed.Roles[SNAPSHOT].Threshold = 2
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying snapshot failed, not enough signatures, got 1, want 2"})

	// Verify succeeds when we correct the new signature and reach the
	// threshold of 2 keys
	signer, err := rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "timestamp_key"))
	assert.NoError(t, err)
	_, err = snapshot.Sign(signer)
	assert.NoError(t, err)
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.NoError(t, err)
}

func TestVerifyDelegateDuplicateSignatureKeyIDs(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	key, err := KeyFromPublicKey(pub)
	assert.NoError(t, err)
	keyID, err := key.ID()
	assert.NoError(t, err)
	signer, err := signature.LoadSignerVerifier(priv, crypto.Hash(0))
	assert.NoError(t, err)

	root := Root(fixedExpire)
	for _, role := range []string{ROOT, SNAPSHOT, TIMESTAMP, TARGETS} {
		assert.NoError(t, root.Signed.AddKey(key, role))
	}

	validRootSig, err := root.Sign(signer)
	assert.NoError(t, err)
	snapshot := Snapshot(fixedExpire)
	validSnapshotSig, err := snapshot.Sign(signer)
	assert.NoError(t, err)
	timestamp := Timestamp(fixedExpire)
	validTimestampSig, err := timestamp.Sign(signer)
	assert.NoError(t, err)
	targets := Targets(fixedExpire)
	validTargetsSig, err := targets.Sign(signer)
	assert.NoError(t, err)

	badSig := Signature{KeyID: keyID, Signature: []byte("invalid")}

	for _, tc := range []struct {
		name string
		sigs []Signature
		want string
	}{
		{"identical valid signatures", []Signature{*validTargetsSig, *validTargetsSig}, keyID},
		{"invalid then valid for same keyID", []Signature{badSig, *validTargetsSig}, keyID},
		{"valid then invalid for same keyID", []Signature{*validTargetsSig, badSig}, keyID},
		{"duplicate unrelated keyID", []Signature{*validTargetsSig, {KeyID: "other", Signature: []byte("a")}, {KeyID: "other", Signature: []byte("b")}}, "other"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			targets.Signatures = tc.sigs
			err := root.VerifyDelegate(TARGETS, targets)
			assert.ErrorIs(t, err, &ErrValue{})
			assert.EqualError(t, err, fmt.Sprintf("value error: multiple signatures found for key ID %s", tc.want))
		})
	}

	// Verify all four top-level metadata types enforce signature keyID uniqueness.
	root.Signatures = []Signature{*validRootSig, *validRootSig}
	assert.ErrorIs(t, root.VerifyDelegate(ROOT, root), &ErrValue{})
	snapshot.Signatures = []Signature{*validSnapshotSig, *validSnapshotSig}
	assert.ErrorIs(t, root.VerifyDelegate(SNAPSHOT, snapshot), &ErrValue{})
	timestamp.Signatures = []Signature{*validTimestampSig, *validTimestampSig}
	assert.ErrorIs(t, root.VerifyDelegate(TIMESTAMP, timestamp), &ErrValue{})
}

func TestVerifyDelegateTypedNilMetadata(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)
	key, err := KeyFromPublicKey(pub)
	assert.NoError(t, err)

	root := Root(fixedExpire)
	for _, role := range []string{ROOT, SNAPSHOT, TIMESTAMP, TARGETS} {
		assert.NoError(t, root.Signed.AddKey(key, role))
	}

	for _, tc := range []struct {
		role string
		meta any
	}{
		{ROOT, (*Metadata[RootType])(nil)},
		{SNAPSHOT, (*Metadata[SnapshotType])(nil)},
		{TIMESTAMP, (*Metadata[TimestampType])(nil)},
		{TARGETS, (*Metadata[TargetsType])(nil)},
	} {
		t.Run(tc.role, func(t *testing.T) {
			err := root.VerifyDelegate(tc.role, tc.meta)
			assert.ErrorIs(t, err, &ErrValue{})
			assert.EqualError(t, err, "value error: delegated metadata must not be nil")
		})
	}

	err = root.VerifyDelegate(TARGETS, nil)
	assert.ErrorIs(t, err, &ErrType{})
}

func TestRootAddKeyAndRevokeKey(t *testing.T) {
	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)

	// Create a new key
	signer, err := signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "root_key2"), crypto.SHA256, cryptoutils.SkipPassword)
	assert.NoError(t, err)
	key, err := signer.PublicKey()
	assert.NoError(t, err)
	rootKey2, err := KeyFromPublicKey(key)
	assert.NoError(t, err)

	// Assert that root does not contain the new key
	assert.NotContains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.NotContains(t, root.Signed.Keys, rootKey2.id)

	// Add new root key
	err = root.Signed.AddKey(rootKey2, ROOT)
	assert.NoError(t, err)

	// Assert that key is added
	assert.Contains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.Contains(t, root.Signed.Keys, rootKey2.id)

	// Confirm that the newly added key does not break
	// the object serialization
	_, err = root.Signed.MarshalJSON()
	assert.NoError(t, err)

	// Try adding the same key again and assert its ignored.
	preAddKeyIDs := make([]string, len(root.Signed.Roles[ROOT].KeyIDs))
	copy(preAddKeyIDs, root.Signed.Roles[ROOT].KeyIDs)
	err = root.Signed.AddKey(rootKey2, ROOT)
	assert.NoError(t, err)
	assert.Equal(t, preAddKeyIDs, root.Signed.Roles[ROOT].KeyIDs)

	// Add the same key to targets role as well
	err = root.Signed.AddKey(rootKey2, TARGETS)
	assert.NoError(t, err)

	// Add the same key to a nonexistent role.
	err = root.Signed.AddKey(rootKey2, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"role nosuchrole doesn't exist"})

	// Remove the key from root role (targets role still uses it)
	err = root.Signed.RevokeKey(rootKey2.id, ROOT)
	assert.NoError(t, err)
	assert.NotContains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.Contains(t, root.Signed.Keys, rootKey2.id)

	// Remove the key from targets as well
	err = root.Signed.RevokeKey(rootKey2.id, TARGETS)
	assert.NoError(t, err)
	assert.NotContains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.NotContains(t, root.Signed.Keys, rootKey2.id)

	err = root.Signed.RevokeKey("nosuchkey", ROOT)
	assert.ErrorIs(t, err, &ErrValue{"key with id nosuchkey is not used by root"})
	err = root.Signed.RevokeKey(rootKey2.id, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"role nosuchrole doesn't exist"})
}

func TestTargetsKeyAPI(t *testing.T) {
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)

	delegatedRole := DelegatedRole{
		Name:        "role2",
		Paths:       []string{"fn3", "fn4"},
		KeyIDs:      []string{},
		Terminating: false,
		Threshold:   1,
	}
	targets.Signed.Delegations.Roles = append(targets.Signed.Delegations.Roles, delegatedRole)

	key := &Key{
		Type:   "ed25519",
		Value:  KeyVal{PublicKey: "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"},
		Scheme: "ed25519",
	}

	// Assert that delegated role "role1" does not contain the new key
	assert.Equal(t, "role1", targets.Signed.Delegations.Roles[0].Name)
	assert.NotContains(t, targets.Signed.Delegations.Roles[0].KeyIDs, key.id)
	err = targets.Signed.AddKey(key, "role1")
	assert.NoError(t, err)

	// Assert that the new key is added to the delegated role "role1"
	assert.Contains(t, targets.Signed.Delegations.Roles[0].KeyIDs, key.id)

	// Try adding the same key again and assert its ignored.
	pastKeyIDs := make([]string, len(targets.Signed.Delegations.Roles[0].KeyIDs))
	copy(pastKeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)
	err = targets.Signed.AddKey(key, "role1")
	assert.NoError(t, err)
	assert.Equal(t, pastKeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)

	// Try adding a key to a delegated role that doesn't exists
	err = targets.Signed.AddKey(key, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"delegated role nosuchrole doesn't exist"})

	//  Add the same key to "role2" as well
	err = targets.Signed.AddKey(key, "role2")
	assert.NoError(t, err)

	// Remove the key from "role1" role ("role2" still uses it)
	err = targets.Signed.RevokeKey(key.id, "role1")
	assert.NoError(t, err)

	// Assert that delegated role "role1" doesn't contain the key.
	assert.Equal(t, "role1", targets.Signed.Delegations.Roles[0].Name)
	assert.Equal(t, "role2", targets.Signed.Delegations.Roles[1].Name)
	assert.NotContains(t, targets.Signed.Delegations.Roles[0].KeyIDs, key.id)
	assert.Contains(t, targets.Signed.Delegations.Roles[1].KeyIDs, key.id)

	// Remove the key from "role2" as well
	err = targets.Signed.RevokeKey(key.id, "role2")
	assert.NoError(t, err)
	assert.NotContains(t, targets.Signed.Delegations.Roles[1].KeyIDs, key.id)

	// Try remove key not used by "role1"
	err = targets.Signed.RevokeKey(key.id, "role1")
	assert.ErrorIs(t, err, &ErrValue{fmt.Sprintf("key with id %s is not used by role1", key.id)})

	// Try removing a key from delegated role that doesn't exists
	err = targets.Signed.RevokeKey(key.id, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"delegated role nosuchrole doesn't exist"})

	// Remove delegations as a whole
	targets.Signed.Delegations = nil

	//Test that calling add_key and revoke_key throws an error
	// and that delegations is still None after each of the api calls
	err = targets.Signed.AddKey(key, "role1")
	assert.ErrorIs(t, err, &ErrValue{"delegated role role1 doesn't exist"})
	err = targets.Signed.RevokeKey(key.id, "role1")
	assert.ErrorIs(t, err, &ErrValue{"delegated role role1 doesn't exist"})
	assert.Nil(t, targets.Signed.Delegations)
}

func TestTargetsKeyAPIWithSuccinctRoles(t *testing.T) {
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)

	// Remove delegated roles
	assert.NotNil(t, targets.Signed.Delegations)
	assert.NotNil(t, targets.Signed.Delegations.Roles)
	targets.Signed.Delegations.Roles = nil
	targets.Signed.Delegations.Keys = map[string]*Key{}

	// Add succinct roles information
	targets.Signed.Delegations.SuccinctRoles = &SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  8,
		NamePrefix: "foo",
	}
	assert.Equal(t, 0, len(targets.Signed.Delegations.Keys))
	assert.Equal(t, 0, len(targets.Signed.Delegations.SuccinctRoles.KeyIDs))

	// Add a key to succinct_roles and verify it's saved.
	key := &Key{
		Type:   "ed25519",
		Value:  KeyVal{PublicKey: "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"},
		Scheme: "ed25519",
	}
	err = targets.Signed.AddKey(key, "foo")
	assert.NoError(t, err)
	assert.Contains(t, targets.Signed.Delegations.Keys, key.id)
	assert.Contains(t, targets.Signed.Delegations.SuccinctRoles.KeyIDs, key.id)
	assert.Equal(t, 1, len(targets.Signed.Delegations.Keys))

	// Try adding the same key again and verify that noting is added.
	err = targets.Signed.AddKey(key, "foo")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(targets.Signed.Delegations.Keys))

	// Remove the key and verify it's not stored anymore.
	err = targets.Signed.RevokeKey(key.id, "foo")
	assert.NoError(t, err)
	assert.NotContains(t, targets.Signed.Delegations.Keys, key.id)
	assert.NotContains(t, targets.Signed.Delegations.SuccinctRoles.KeyIDs, key.id)
	assert.Equal(t, 0, len(targets.Signed.Delegations.Keys))

	// Try removing it again.
	err = targets.Signed.RevokeKey(key.id, "foo")
	assert.ErrorIs(t, err, &ErrValue{fmt.Sprintf("key with id %s is not used by SuccinctRoles", key.id)})
}

func TestLengthAndHashValidation(t *testing.T) {
	// Test metadata files' hash and length verification.
	// Use timestamp to get a MetaFile object and snapshot
	// for untrusted metadata file to verify.

	timestamp, err := Timestamp().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.NoError(t, err)

	snapshotMetafile := timestamp.Signed.Meta["snapshot.json"]
	assert.NotNil(t, snapshotMetafile)

	snapshotData, err := os.ReadFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	h32 := sha256.Sum256(snapshotData)
	h := h32[:]
	snapshotMetafile.Hashes = map[string]HexBytes{
		"sha256": h,
	}
	snapshotMetafile.Length = int64(len(snapshotData))

	data, err := os.ReadFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.NoError(t, err)

	// test exceptions
	originalLength := snapshotMetafile.Length
	snapshotMetafile.Length = 2345
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{fmt.Sprintf("length verification failed - expected %d, got %d", 2345, originalLength)})

	snapshotMetafile.Length = originalLength
	originalHashSHA256 := snapshotMetafile.Hashes["sha256"]
	snapshotMetafile.Hashes["sha256"] = []byte("incorrecthash")
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - mismatch for algorithm sha256"})

	snapshotMetafile.Hashes["sha256"] = originalHashSHA256
	snapshotMetafile.Hashes["unsupported-alg"] = []byte("72c5cabeb3e8079545a5f4d2b067f8e35f18a0de3c2b00d3cb8d05919c19c72d")
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - unknown hashing algorithm - unsupported-alg"})

	// test optional length and hashes
	snapshotMetafile.Length = 0
	snapshotMetafile.Hashes = nil
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.NoError(t, err)

	// Test target files' hash and length verification
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	targetFile := targets.Signed.Targets["file1.txt"]
	targetFileData, err := os.ReadFile(filepath.Join(testutils.TargetsDir, targetFile.Path))
	assert.NoError(t, err)

	// test exceptions
	originalLength = targetFile.Length
	targetFile.Length = 2345
	err = targetFile.VerifyLengthHashes(targetFileData)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{fmt.Sprintf("length verification failed - expected %d, got %d", 2345, originalLength)})

	targetFile.Length = originalLength
	targetFile.Hashes["sha256"] = []byte("incorrecthash")
	err = targetFile.VerifyLengthHashes(targetFileData)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - mismatch for algorithm sha256"})
}

func TestTargetFileFromFile(t *testing.T) {
	// Test with an existing file and valid hash algorithm
	targetFilePath := filepath.Join(testutils.TargetsDir, "file1.txt")
	targetFileFromFile, err := TargetFile().FromFile(targetFilePath, "sha256")
	assert.NoError(t, err)
	targetFileData, err := os.ReadFile(targetFilePath)
	assert.NoError(t, err)
	err = targetFileFromFile.VerifyLengthHashes(targetFileData)
	assert.NoError(t, err)

	// Test with mismatching target file data
	mismatchingTargetFilePath := filepath.Join(testutils.TargetsDir, "file2.txt")
	mismatchingTargetFileData, err := os.ReadFile(mismatchingTargetFilePath)
	assert.NoError(t, err)
	err = targetFileFromFile.VerifyLengthHashes(mismatchingTargetFileData)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - mismatch for algorithm sha256"})

	// Test with an unsupported algorithm
	_, err = TargetFile().FromFile(targetFilePath, "123")
	assert.ErrorIs(t, err, &ErrValue{"failed generating TargetFile - unsupported hashing algorithm - 123"})
}

func TestTargetFileCustom(t *testing.T) {
	// Test creating TargetFile and accessing custom.
	targetFile := TargetFile()
	customJSON := json.RawMessage([]byte(`{"foo":"bar"}`))
	targetFile.Custom = &customJSON
	custom, err := targetFile.Custom.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, "{\"foo\":\"bar\"}", string(custom))
}

func TestTargetFileFromBytes(t *testing.T) {
	data := []byte("Inline test content")
	path := filepath.Join(testutils.TargetsDir, "file1.txt")

	// Test with a valid hash algorithm
	targetFileFromData, err := TargetFile().FromBytes(path, data, "sha256")
	assert.NoError(t, err)
	err = targetFileFromData.VerifyLengthHashes(data)
	assert.NoError(t, err)

	// Test with no algorithms specified
	targetFileFromDataWithNoAlg, err := TargetFile().FromBytes(path, data)
	assert.NoError(t, err)
	err = targetFileFromDataWithNoAlg.VerifyLengthHashes(data)
	assert.NoError(t, err)
}

func TestIsDelegatedRole(t *testing.T) {
	// Test path matches
	role := &DelegatedRole{
		Name:        "",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"a/path", "otherpath", "a/path", "*/?ath"},
	}
	nonMatching, err := role.IsDelegatedPath("a/non-matching-path")
	assert.NoError(t, err)
	assert.False(t, nonMatching)
	matching, err := role.IsDelegatedPath("a/path")
	assert.NoError(t, err)
	assert.True(t, matching)

	// Test path hash prefix matches: sha256 sum of "a/path" is 927b0ecf9...
	role = &DelegatedRole{
		Name:             "",
		KeyIDs:           []string{},
		Threshold:        1,
		Terminating:      false,
		PathHashPrefixes: []string{"927b0ecf9", "other prefix", "927b0ecf9", "927b0", "92"},
	}
	nonMatching, err = role.IsDelegatedPath("a/non-matching-path")
	assert.NoError(t, err)
	assert.False(t, nonMatching)
	matching, err = role.IsDelegatedPath("a/path")
	assert.NoError(t, err)
	assert.True(t, matching)
}

func TestIsDelegatedRoleInSuccinctRoles(t *testing.T) {
	succinctRoles := &SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  5,
		NamePrefix: "bin",
	}

	falseRoleNmaeExamples := []string{
		"foo",
		"bin-",
		"bin-s",
		"bin-0t",
		"bin-20",
		"bin-100",
	}
	for _, roleName := range falseRoleNmaeExamples {
		res := succinctRoles.IsDelegatedRole(roleName)
		assert.False(t, res)
	}

	// Delegated role name suffixes are in hex format.
	trueNameExamples := []string{"bin-00", "bin-0f", "bin-1f"}
	for _, roleName := range trueNameExamples {
		res := succinctRoles.IsDelegatedRole(roleName)
		assert.True(t, res)
	}
}

func TestGetRolesInSuccinctRoles(t *testing.T) {
	succinctRoles := &SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  16,
		NamePrefix: "bin",
	}
	// bin names are in hex format and 4 hex digits are enough to represent
	// all bins between 0 and 2^16 - 1 meaning suffix_len must be 4
	expectedSuffixLength := 4
	suffixLen, _ := succinctRoles.GetSuffixLen()
	assert.Equal(t, expectedSuffixLength, suffixLen)

	allRoles := succinctRoles.GetRoles()
	for binNumer, roleName := range allRoles {
		// This adds zero-padding if the bin_numer is represented by a hex
		// number with a length less than expected_suffix_length.
		expectedBinSuffix := fmt.Sprintf("%0"+strconv.Itoa(expectedSuffixLength)+"x", binNumer)
		assert.Equal(t, fmt.Sprintf("bin-%s", expectedBinSuffix), roleName)
	}
}

func TestSuccinctRolesBitLengthValidation(t *testing.T) {
	tests := []struct {
		name      string
		bitLength int
		wantErr   bool
	}{
		{"valid minimum", 1, false},
		{"valid typical", 8, false},
		{"valid maximum", 32, false},
		{"invalid zero", 0, true},
		{"invalid negative", -1, true},
		{"invalid too large", 33, true},
		{"invalid very large", 100, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData := fmt.Sprintf(`{
				"keyids": ["abc123"],
				"threshold": 1,
				"bit_length": %d,
				"name_prefix": "bin"
			}`, tt.bitLength)

			var role SuccinctRoles
			err := json.Unmarshal([]byte(jsonData), &role)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid bit_length")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.bitLength, role.BitLength)
			}
		})
	}
}

func TestFromBytesRejectsNullMapValues(t *testing.T) {
	testCases := []struct {
		name        string
		input       string
		parse       func([]byte) error
		expectedErr string
	}{
		{
			name:  "root key",
			input: `{"signed":{"_type":"root","spec_version":"1.0.31","version":1,"keys":{"keyid":null},"roles":{}}}`,
			parse: func(data []byte) error {
				_, err := Root().FromBytes(data)
				return err
			},
			expectedErr: `keys entry "keyid" is null`,
		},
		{
			name:  "root keys map",
			input: `{"signed":{"_type":"root","spec_version":"1.0.31","version":1,"keys":null,"roles":{}}}`,
			parse: func(data []byte) error {
				_, err := Root().FromBytes(data)
				return err
			},
			expectedErr: `keys must not be null`,
		},
		{
			name:  "root role",
			input: `{"signed":{"_type":"root","spec_version":"1.0.31","version":1,"keys":{},"roles":{"root":null}}}`,
			parse: func(data []byte) error {
				_, err := Root().FromBytes(data)
				return err
			},
			expectedErr: `roles entry "root" is null`,
		},
		{
			name:  "snapshot meta",
			input: `{"signed":{"_type":"snapshot","spec_version":"1.0.31","version":1,"meta":{"targets.json":null}}}`,
			parse: func(data []byte) error {
				_, err := Snapshot().FromBytes(data)
				return err
			},
			expectedErr: `meta entry "targets.json" is null`,
		},
		{
			name:  "timestamp meta",
			input: `{"signed":{"_type":"timestamp","spec_version":"1.0.31","version":1,"meta":{"snapshot.json":null}}}`,
			parse: func(data []byte) error {
				_, err := Timestamp().FromBytes(data)
				return err
			},
			expectedErr: `meta entry "snapshot.json" is null`,
		},
		{
			name:  "timestamp missing snapshot meta",
			input: `{"signed":{"_type":"timestamp","spec_version":"1.0.31","version":1,"meta":{}}}`,
			parse: func(data []byte) error {
				_, err := Timestamp().FromBytes(data)
				return err
			},
			expectedErr: `meta is missing required "snapshot.json" entry`,
		},
		{
			name:  "target file",
			input: `{"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"targets":{"file.txt":null}}}`,
			parse: func(data []byte) error {
				_, err := Targets().FromBytes(data)
				return err
			},
			expectedErr: `targets entry "file.txt" is null`,
		},
		{
			name:  "targets map",
			input: `{"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"targets":null}}`,
			parse: func(data []byte) error {
				_, err := Targets().FromBytes(data)
				return err
			},
			expectedErr: `targets must not be null`,
		},
		{
			name:  "delegation key",
			input: `{"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"targets":{},"delegations":{"keys":{"keyid":null}}}}`,
			parse: func(data []byte) error {
				_, err := Targets().FromBytes(data)
				return err
			},
			expectedErr: `delegation keys entry "keyid" is null`,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.EqualError(t, testCase.parse([]byte(testCase.input)), testCase.expectedErr)
		})
	}
}

func TestFromBytesMatchesFieldNamesExactly(t *testing.T) {
	// A name that differs from a known field only by case is an unrecognized field.
	const role = `{"keyids":[],"threshold":1}`
	const signed = `{"_type":"root","spec_version":"1.0.31","version":1,"Version":"x","keys":{},` +
		`"roles":{"root":{"keyids":["a"],"threshold":1,"KeyIDs":["b"]},` +
		`"snapshot":` + role + `,"targets":` + role + `,"timestamp":` + role + `}}`
	const other = `{"_type":"root","version":2,"keys":{},"roles":{}}`
	const longS = "\u017f"
	input := `{"signed":` + signed + `,"signatures":[],"Signed":` + other +
		`,"` + longS + `ignatures":[{"keyid":"k","sig":"00"}]}`

	root, err := Root().FromBytes([]byte(input))
	assert.NoError(t, err)
	assert.Equal(t, int64(1), root.Signed.Version)
	assert.Empty(t, root.Signatures)
	assert.Equal(t, []string{"a"}, root.Signed.Roles[ROOT].KeyIDs)

	assert.Contains(t, root.UnrecognizedFields, "Signed")
	assert.Contains(t, root.UnrecognizedFields, longS+"ignatures")
	assert.Equal(t, "x", root.Signed.UnrecognizedFields["Version"])
	assert.Contains(t, root.Signed.Roles[ROOT].UnrecognizedFields, "KeyIDs")
}

// reparseTopLevel writes one metadata file of each top-level type with the
// given spec_version and version, and returns the error from reading each one
// back, keyed by type.
func reparseTopLevel(t *testing.T, specVersion string, version int64) map[string]error {
	t.Helper()
	root, snapshot, timestamp, targets := Root(), Snapshot(), Timestamp(), Targets()
	root.Signed.SpecVersion, root.Signed.Version = specVersion, version
	snapshot.Signed.SpecVersion, snapshot.Signed.Version = specVersion, version
	timestamp.Signed.SpecVersion, timestamp.Signed.Version = specVersion, version
	targets.Signed.SpecVersion, targets.Signed.Version = specVersion, version

	errs := map[string]error{}
	data, err := root.ToBytes(false)
	assert.NoError(t, err)
	_, errs[ROOT] = Root().FromBytes(data)
	data, err = snapshot.ToBytes(false)
	assert.NoError(t, err)
	_, errs[SNAPSHOT] = Snapshot().FromBytes(data)
	data, err = timestamp.ToBytes(false)
	assert.NoError(t, err)
	_, errs[TIMESTAMP] = Timestamp().FromBytes(data)
	data, err = targets.ToBytes(false)
	assert.NoError(t, err)
	_, errs[TARGETS] = Targets().FromBytes(data)
	return errs
}

func TestFromBytesChecksSpecVersion(t *testing.T) {
	// Only the major version is compared. Both MAJOR.MINOR.PATCH and the
	// legacy MAJOR.MINOR are accepted: Sigstore's production root declares
	// "1.0".
	const failedToParse = "failed to parse spec_version"
	const unsupported = "unsupported spec_version"

	tests := []struct {
		specVersion string
		wantErr     string
	}{
		{specVersion: SPECIFICATION_VERSION},
		{specVersion: "1.0.31"},
		{specVersion: "1.0"},
		{specVersion: "1.0.0"},
		{specVersion: "1.99.999"},
		{specVersion: "1.00.031"},

		{specVersion: "2.0.0", wantErr: unsupported},
		{specVersion: "2.0", wantErr: unsupported},
		{specVersion: "0.9.0", wantErr: unsupported},
		{specVersion: "10.0.0", wantErr: unsupported},
		{specVersion: "01.0.0", wantErr: unsupported},

		{specVersion: "", wantErr: failedToParse},
		{specVersion: "banana", wantErr: failedToParse},
		{specVersion: "1", wantErr: failedToParse},
		{specVersion: "1.0.0.0", wantErr: failedToParse},
		{specVersion: "1.", wantErr: failedToParse},
		{specVersion: ".0", wantErr: failedToParse},
		{specVersion: "1..0", wantErr: failedToParse},
		{specVersion: "1.0.", wantErr: failedToParse},
		{specVersion: "1.x", wantErr: failedToParse},
		{specVersion: "1.0.0-rc1", wantErr: failedToParse},
		{specVersion: "1.0.0+build", wantErr: failedToParse},
		{specVersion: "v1.0.0", wantErr: failedToParse},
		{specVersion: "+1.0.0", wantErr: failedToParse},
		{specVersion: "1.-0", wantErr: failedToParse},
		{specVersion: " 1.0.0", wantErr: failedToParse},
		{specVersion: "1.0.0\n", wantErr: failedToParse},
		{specVersion: "1,0", wantErr: failedToParse},
		// Digits outside ASCII are not accepted.
		{specVersion: "1.\u0660", wantErr: failedToParse},
		{specVersion: "\uff11.0", wantErr: failedToParse},
	}
	for _, tt := range tests {
		t.Run(strconv.Quote(tt.specVersion), func(t *testing.T) {
			for role, err := range reparseTopLevel(t, tt.specVersion, 1) {
				if tt.wantErr == "" {
					assert.NoError(t, err, role)
					continue
				}
				assert.ErrorIs(t, err, &ErrValue{}, role)
				assert.ErrorContains(t, err, tt.wantErr, role)
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		_, err := Targets().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"targets",` +
			`"version":1,"expires":"2030-01-01T00:00:00Z","targets":{}}}`))
		assert.ErrorContains(t, err, failedToParse)
	})

	t.Run("many dots bounded allocation", func(t *testing.T) {
		manyDots := strings.Repeat(".", 1<<20)
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		err := checkSpecVersion(manyDots)
		runtime.ReadMemStats(&after)

		assert.ErrorIs(t, err, &ErrValue{})
		// Unbounded strings.Split on 1 MiB of dots allocates ~16 MiB for the
		// []string slice alone (~19 MiB total including error formatting).
		assert.Less(t, after.TotalAlloc-before.TotalAlloc, uint64(8<<20))
	})
}

func TestFromBytesReturnsErrDeserialization(t *testing.T) {
	assert.Equal(t, "deserialization error", (&ErrDeserialization{}).Error())

	tests := []struct {
		name      string
		parse     func() error
		wantValue bool
	}{
		{
			name: "invalid JSON",
			parse: func() error {
				_, err := Timestamp().FromBytes([]byte("{truncated"))
				return err
			},
		},
		{
			name: "wrong _type",
			parse: func() error {
				_, err := Timestamp().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"snapshot"}}`))
				return err
			},
			wantValue: true,
		},
		{
			name: "invalid spec_version",
			parse: func() error {
				_, err := Snapshot().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"snapshot",` +
					`"spec_version":"1.0.0.0","version":1,"expires":"2030-01-01T00:00:00Z","meta":{}}}`))
				return err
			},
			wantValue: true,
		},
		{
			name: "non-positive version",
			parse: func() error {
				_, err := Targets().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"targets",` +
					`"spec_version":"1.0.31","version":0,"expires":"2030-01-01T00:00:00Z","targets":{}}}`))
				return err
			},
			wantValue: true,
		},
		{
			name: "duplicate delegated role name",
			parse: func() error {
				_, err := Targets().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"targets",` +
					`"spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","targets":{},` +
					`"delegations":{"keys":{},"roles":[{"name":"r","keyids":[],"threshold":1},{"name":"r","keyids":[],"threshold":1}]}}}`))
				return err
			},
			wantValue: true,
		},
		{
			name: "duplicate signature key ID",
			parse: func() error {
				_, err := Targets().FromBytes([]byte(`{"signatures":[{"keyid":"k","sig":"00"},{"keyid":"k","sig":"00"}],` +
					`"signed":{"_type":"targets","spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","targets":{}}}`))
				return err
			},
			wantValue: true,
		},
		{
			name: "null map entry",
			parse: func() error {
				_, err := Targets().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"targets",` +
					`"spec_version":"1.0.31","version":1,"expires":"2030-01-01T00:00:00Z","targets":{"a":null}}}`))
				return err
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.parse()
			assert.ErrorIs(t, err, &ErrDeserialization{})
			assert.ErrorIs(t, err, &ErrRepository{})
			if tt.wantValue {
				assert.ErrorIs(t, err, &ErrValue{})
			} else {
				assert.NotErrorIs(t, err, &ErrValue{})
			}
		})
	}
}

func TestFromBytesChecksVersion(t *testing.T) {
	// The version of a metadata file is an integer greater than 0.
	tests := []struct {
		version int64
		wantErr bool
	}{
		{version: 1},
		{version: 2},
		{version: 9223372036854775807},
		{version: 0, wantErr: true},
		{version: -1, wantErr: true},
		{version: -9223372036854775808, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(strconv.FormatInt(tt.version, 10), func(t *testing.T) {
			for role, err := range reparseTopLevel(t, SPECIFICATION_VERSION, tt.version) {
				if !tt.wantErr {
					assert.NoError(t, err, role)
					continue
				}
				assert.ErrorIs(t, err, &ErrValue{}, role)
				assert.ErrorContains(t, err, fmt.Sprintf("version must be > 0, got %d", tt.version), role)
			}
		})
	}

	t.Run("missing", func(t *testing.T) {
		_, err := Targets().FromBytes([]byte(`{"signatures":[],"signed":{"_type":"targets",` +
			`"spec_version":"1.0.31","expires":"2030-01-01T00:00:00Z","targets":{}}}`))
		assert.ErrorContains(t, err, "version must be > 0, got 0")
	})
}

func TestRootFromBytesRequiresTopLevelRoles(t *testing.T) {
	// A root must specify the root, snapshot, timestamp and targets roles.
	// It may specify others, such as the optional mirrors role.
	reparse := func(edit func(roles map[string]*Role)) error {
		root := Root()
		edit(root.Signed.Roles)
		data, err := root.ToBytes(false)
		assert.NoError(t, err)
		_, err = Root().FromBytes(data)
		return err
	}

	assert.NoError(t, reparse(func(map[string]*Role) {}))
	assert.NoError(t, reparse(func(roles map[string]*Role) {
		roles["mirrors"] = &Role{KeyIDs: []string{}, Threshold: 1}
	}))

	for _, name := range TOP_LEVEL_ROLE_NAMES {
		wantErr := fmt.Sprintf("roles is missing required top-level role %q", name)

		t.Run("missing "+name, func(t *testing.T) {
			err := reparse(func(roles map[string]*Role) { delete(roles, name) })
			assert.ErrorIs(t, err, &ErrValue{})
			assert.ErrorContains(t, err, wantErr)
		})
		// Role names are case-sensitive, so this is another role.
		t.Run("renamed "+name, func(t *testing.T) {
			err := reparse(func(roles map[string]*Role) {
				roles[strings.ToUpper(name)] = roles[name]
				delete(roles, name)
			})
			assert.ErrorContains(t, err, wantErr)
		})
	}

	t.Run("no roles", func(t *testing.T) {
		assert.ErrorIs(t, reparse(func(roles map[string]*Role) { clear(roles) }), &ErrValue{})
	})
}

func TestDelegationsRejectDuplicateRoleNames(t *testing.T) {
	// The name of a delegated role must be unique in its delegations object.
	tests := []struct {
		name    string
		roles   []string
		wantErr string
	}{
		{name: "no roles", roles: []string{}},
		{name: "unique", roles: []string{"a", "b", "c"}},
		// Names are compared exactly.
		{name: "differ by case", roles: []string{"dup", "Dup"}},
		{name: "differ by whitespace", roles: []string{"dup", "dup "}},
		{name: "adjacent", roles: []string{"dup", "dup"}, wantErr: `duplicate delegated role name "dup"`},
		{name: "not adjacent", roles: []string{"dup", "a", "b", "dup"}, wantErr: `duplicate delegated role name "dup"`},
		{name: "empty names", roles: []string{"", ""}, wantErr: `duplicate delegated role name ""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delegations := &Delegations{Keys: map[string]*Key{}, Roles: []DelegatedRole{}}
			for i, name := range tt.roles {
				// The roles differ in everything but their name.
				delegations.Roles = append(delegations.Roles, DelegatedRole{
					Name:      name,
					KeyIDs:    []string{},
					Threshold: i + 1,
					Paths:     []string{fmt.Sprintf("%d/*", i)},
				})
			}
			targets := Targets()
			targets.Signed.Delegations = delegations

			delegationsJSON, err := json.Marshal(delegations)
			assert.NoError(t, err)
			var parsed Delegations
			delegationsErr := json.Unmarshal(delegationsJSON, &parsed)
			// The same delegations inside targets metadata, as a client receives them.
			data, err := targets.ToBytes(false)
			assert.NoError(t, err)
			_, targetsErr := Targets().FromBytes(data)

			for _, err := range []error{delegationsErr, targetsErr} {
				if tt.wantErr == "" {
					assert.NoError(t, err)
					continue
				}
				assert.ErrorIs(t, err, &ErrValue{})
				assert.ErrorContains(t, err, tt.wantErr)
			}
		})
	}
}
