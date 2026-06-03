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
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.createFunc()
			assert.NotNil(t, result)

			switch meta := result.(type) {
			case *Metadata[RootType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Keys)
				assert.NotNil(t, meta.Signed.Roles)
			case *Metadata[TargetsType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Targets)
			case *Metadata[SnapshotType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Meta)
			case *Metadata[TimestampType]:
				assert.Equal(t, tt.expectedType, meta.Signed.Type)
				assert.Equal(t, SPECIFICATION_VERSION, meta.Signed.SpecVersion)
				assert.Equal(t, int64(1), meta.Signed.Version)
				assert.NotNil(t, meta.Signed.Meta)
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
		compact  bool
		wantErr  bool
	}{
		{name: "Root to bytes compact", metadata: Root(expiry), compact: true},
		{name: "Root to bytes non-compact", metadata: Root(expiry), compact: false},
		{name: "Targets to bytes", metadata: Targets(expiry), compact: true},
		{name: "Snapshot to bytes", metadata: Snapshot(expiry), compact: true},
		{name: "Timestamp to bytes", metadata: Timestamp(expiry), compact: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				data []byte
				err  error
			)
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				data, err = meta.ToBytes(tt.compact)
			case *Metadata[TargetsType]:
				data, err = meta.ToBytes(tt.compact)
			case *Metadata[SnapshotType]:
				data, err = meta.ToBytes(tt.compact)
			case *Metadata[TimestampType]:
				data, err = meta.ToBytes(tt.compact)
			}

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.NotEmpty(t, data)

			// Verify the output is valid JSON.
			var jsonData any
			assert.NoError(t, json.Unmarshal(data, &jsonData))
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
		compact  bool
		wantErr  bool
	}{
		{name: "Root to file", metadata: Root(expiry), filename: "root.json"},
		{name: "Targets to file compact", metadata: Targets(expiry), filename: "targets.json", compact: true},
		{name: "Snapshot to file", metadata: Snapshot(expiry), filename: "snapshot.json"},
		{name: "Timestamp to file", metadata: Timestamp(expiry), filename: "timestamp.json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(testDir, tt.filename)
			var err error
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				err = meta.ToFile(path, tt.compact)
			case *Metadata[TargetsType]:
				err = meta.ToFile(path, tt.compact)
			case *Metadata[SnapshotType]:
				err = meta.ToFile(path, tt.compact)
			case *Metadata[TimestampType]:
				err = meta.ToFile(path, tt.compact)
			}

			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Verify the file contains valid JSON.
			raw, err := os.ReadFile(path)
			assert.NoError(t, err)
			var jsonData any
			assert.NoError(t, json.Unmarshal(raw, &jsonData))
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

			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, err := Root().FromFile(path)
				assert.NoError(t, err)
				assert.Equal(t, meta.Signed.Type, loaded.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loaded.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loaded.Signed.SpecVersion)

			case *Metadata[TargetsType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, err := Targets().FromFile(path)
				assert.NoError(t, err)
				assert.Equal(t, meta.Signed.Type, loaded.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loaded.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loaded.Signed.SpecVersion)

			case *Metadata[SnapshotType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, err := Snapshot().FromFile(path)
				assert.NoError(t, err)
				assert.Equal(t, meta.Signed.Type, loaded.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loaded.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loaded.Signed.SpecVersion)

			case *Metadata[TimestampType]:
				assert.NoError(t, meta.ToFile(path, false))
				loaded, err := Timestamp().FromFile(path)
				assert.NoError(t, err)
				assert.Equal(t, meta.Signed.Type, loaded.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loaded.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loaded.Signed.SpecVersion)
			}
		})
	}
}

func TestMetadataVersioning(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name       string
		metadata   any
		newVersion int64
	}{
		{name: "Increment Root version", metadata: Root(expiry), newVersion: 2},
		{name: "Set high version number", metadata: Targets(expiry), newVersion: 1_000_000},
		// Version 0 is below the valid minimum but the library permits setting it
		// directly; enforcement happens at validation/update time.
		{name: "Zero version (below minimum)", metadata: Snapshot(expiry), newVersion: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				meta.Signed.Version = tt.newVersion
				assert.Equal(t, tt.newVersion, meta.Signed.Version)
			case *Metadata[TargetsType]:
				meta.Signed.Version = tt.newVersion
				assert.Equal(t, tt.newVersion, meta.Signed.Version)
			case *Metadata[SnapshotType]:
				meta.Signed.Version = tt.newVersion
				assert.Equal(t, tt.newVersion, meta.Signed.Version)
			case *Metadata[TimestampType]:
				meta.Signed.Version = tt.newVersion
				assert.Equal(t, tt.newVersion, meta.Signed.Version)
			}
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
		expires   time.Time
		isExpired bool
	}{
		{name: "Root not expired", metadata: Root(future), expires: future, isExpired: false},
		{name: "Root expired", metadata: Root(past), expires: past, isExpired: true},
		{name: "Targets not expired", metadata: Targets(future), expires: future, isExpired: false},
		{name: "Targets expired", metadata: Targets(past), expires: past, isExpired: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				assert.Equal(t, tt.expires.Truncate(time.Second), meta.Signed.Expires.Truncate(time.Second))
				assert.Equal(t, tt.isExpired, meta.Signed.Expires.Before(now))
			case *Metadata[TargetsType]:
				assert.Equal(t, tt.expires.Truncate(time.Second), meta.Signed.Expires.Truncate(time.Second))
				assert.Equal(t, tt.isExpired, meta.Signed.Expires.Before(now))
			}
		})
	}
}

var testRootBytes = []byte("{\"signatures\":[{\"keyid\":\"roothash\",\"sig\":\"1307990e6ba5ca145eb35e99182a9bec46531bc54ddf656a602c780fa0240dee\"}],\"signed\":{\"_type\":\"root\",\"consistent_snapshot\":true,\"expires\":\"2030-08-15T14:30:45.0000001Z\",\"keys\":{\"roothash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubrootval\"},\"scheme\":\"ed25519\"},\"snapshothash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubsval\"},\"scheme\":\"ed25519\"},\"targetshash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubtrval\"},\"scheme\":\"ed25519\"},\"timestamphash\":{\"keytype\":\"ed25519\",\"keyval\":{\"public\":\"pubtmval\"},\"scheme\":\"ed25519\"}},\"roles\":{\"root\":{\"keyids\":[\"roothash\"],\"threshold\":1},\"snapshot\":{\"keyids\":[\"snapshothash\"],\"threshold\":1},\"targets\":{\"keyids\":[\"targetshash\"],\"threshold\":1},\"timestamp\":{\"keyids\":[\"timestamphash\"],\"threshold\":1}},\"spec_version\":\"1.0.31\",\"version\":1}}")

const TEST_REPOSITORY_DATA = "../internal/testutils/repository_data/repository/metadata"

var fixedExpire = time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

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
	_, err := root.FromFile(filepath.Join(TEST_REPOSITORY_DATA, "1.root.json"))
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

	fileName := filepath.Join(tmpDir, "1.root.json")
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

func TestTargetFilesEmptyHashesRejected(t *testing.T) {
	// Per TUF spec, hashes are mandatory for target files.
	// Targets metadata with empty hashes should be rejected at parse time.
	targetsJSON := []byte(`{
		"signatures": [],
		"signed": {
			"_type": "targets",
			"expires": "2030-08-15T14:30:45Z",
			"spec_version": "1.0.31",
			"targets": {
				"test.txt": {
					"hashes": {},
					"length": 100
				}
			},
			"version": 1
		}
	}`)

	_, err := Targets().FromBytes(targetsJSON)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "hashes must not be empty")
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
	snapshotVerifier, err := signature.LoadVerifier(snapshotPublicKey, snapshotHash)
	assert.NoError(t, err)
	err = snapshotVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")

	// Append a new signature with the unrelated key and assert that ...
	signer, err := signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "snapshot_key"), crypto.SHA256, cryptoutils.SkipPassword)
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
	signer, err = signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "timestamp_key"), crypto.SHA256, cryptoutils.SkipPassword)
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
	timestampVerifier, err := signature.LoadVerifier(timestampPublicKey, timestampHash)
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
	snapshotMetafile.Length = 652

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
		PathHashPrefixes: []string{"knsOz5xYT", "other prefix", "knsOz5xYT", "knsOz", "kn"},
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
