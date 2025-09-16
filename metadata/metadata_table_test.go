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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
)

func TestMetadataCreation(t *testing.T) {
	fixedExpire := time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC)

	tests := []struct {
		name         string
		createFunc   func() interface{}
		expectedType string
		wantErr      bool
	}{
		{
			name: "Root creation with default expiry",
			createFunc: func() interface{} {
				return Root()
			},
			expectedType: ROOT,
			wantErr:      false,
		},
		{
			name: "Root creation with fixed expiry",
			createFunc: func() interface{} {
				return Root(fixedExpire)
			},
			expectedType: ROOT,
			wantErr:      false,
		},
		{
			name: "Targets creation with default expiry",
			createFunc: func() interface{} {
				return Targets()
			},
			expectedType: TARGETS,
			wantErr:      false,
		},
		{
			name: "Targets creation with fixed expiry",
			createFunc: func() interface{} {
				return Targets(fixedExpire)
			},
			expectedType: TARGETS,
			wantErr:      false,
		},
		{
			name: "Snapshot creation with default expiry",
			createFunc: func() interface{} {
				return Snapshot()
			},
			expectedType: SNAPSHOT,
			wantErr:      false,
		},
		{
			name: "Snapshot creation with fixed expiry",
			createFunc: func() interface{} {
				return Snapshot(fixedExpire)
			},
			expectedType: SNAPSHOT,
			wantErr:      false,
		},
		{
			name: "Timestamp creation with default expiry",
			createFunc: func() interface{} {
				return Timestamp()
			},
			expectedType: TIMESTAMP,
			wantErr:      false,
		},
		{
			name: "Timestamp creation with fixed expiry",
			createFunc: func() interface{} {
				return Timestamp(fixedExpire)
			},
			expectedType: TIMESTAMP,
			wantErr:      false,
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
	tempManager := helpers.NewTempDirManager()
	defer tempManager.Cleanup(t)

	// Create test metadata files
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
			wantErr:      false,
		},
		{
			name:         "Valid Targets from bytes",
			metadataType: TARGETS,
			data:         validTargets,
			wantErr:      false,
		},
		{
			name:         "Valid Snapshot from bytes",
			metadataType: SNAPSHOT,
			data:         validSnapshot,
			wantErr:      false,
		},
		{
			name:         "Valid Timestamp from bytes",
			metadataType: TIMESTAMP,
			data:         validTimestamp,
			wantErr:      false,
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
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetadataFromFile(t *testing.T) {
	tempManager := helpers.NewTempDirManager()
	defer tempManager.Cleanup(t)

	testDir := tempManager.CreateTempDir(t, "metadata_test")

	// Create test files
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
			wantErr:      false,
		},
		{
			name:         "Valid Targets from file",
			metadataType: TARGETS,
			filePath:     targetsFile,
			wantErr:      false,
		},
		{
			name:         "Non-existent file",
			metadataType: ROOT,
			filePath:     filepath.Join(testDir, "nonexistent.json"),
			wantErr:      true,
			errorMsg:     "no such file or directory",
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
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestMetadataToBytes(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name     string
		metadata interface{}
		compact  bool
		wantErr  bool
	}{
		{
			name:     "Root to bytes compact",
			metadata: Root(expiry),
			compact:  true,
			wantErr:  false,
		},
		{
			name:     "Root to bytes non-compact",
			metadata: Root(expiry),
			compact:  false,
			wantErr:  false,
		},
		{
			name:     "Targets to bytes",
			metadata: Targets(expiry),
			compact:  true,
			wantErr:  false,
		},
		{
			name:     "Snapshot to bytes",
			metadata: Snapshot(expiry),
			compact:  true,
			wantErr:  false,
		},
		{
			name:     "Timestamp to bytes",
			metadata: Timestamp(expiry),
			compact:  true,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data []byte
			var err error

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
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, data)

				// Verify it's valid JSON
				var jsonData interface{}
				assert.NoError(t, json.Unmarshal(data, &jsonData))
			}
		})
	}
}

func TestMetadataToFile(t *testing.T) {
	tempManager := helpers.NewTempDirManager()
	defer tempManager.Cleanup(t)

	testDir := tempManager.CreateTempDir(t, "metadata_test")
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name     string
		metadata interface{}
		filename string
		compact  bool
		wantErr  bool
	}{
		{
			name:     "Root to file",
			metadata: Root(expiry),
			filename: "root.json",
			compact:  false,
			wantErr:  false,
		},
		{
			name:     "Targets to file compact",
			metadata: Targets(expiry),
			filename: "targets.json",
			compact:  true,
			wantErr:  false,
		},
		{
			name:     "Snapshot to file",
			metadata: Snapshot(expiry),
			filename: "snapshot.json",
			compact:  false,
			wantErr:  false,
		},
		{
			name:     "Timestamp to file",
			metadata: Timestamp(expiry),
			filename: "timestamp.json",
			compact:  false,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(testDir, tt.filename)
			var err error

			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				err = meta.ToFile(filePath, tt.compact)
			case *Metadata[TargetsType]:
				err = meta.ToFile(filePath, tt.compact)
			case *Metadata[SnapshotType]:
				err = meta.ToFile(filePath, tt.compact)
			case *Metadata[TimestampType]:
				err = meta.ToFile(filePath, tt.compact)
			}

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)

				// Verify file was created and contains valid JSON
				data, err := os.ReadFile(filePath)
				assert.NoError(t, err)
				var jsonData interface{}
				assert.NoError(t, json.Unmarshal(data, &jsonData))
			}
		})
	}
}

func TestMetadataRoundTrip(t *testing.T) {
	tempManager := helpers.NewTempDirManager()
	defer tempManager.Cleanup(t)

	testDir := tempManager.CreateTempDir(t, "roundtrip_test")
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name     string
		metadata interface{}
		filename string
	}{
		{
			name:     "Root roundtrip",
			metadata: Root(expiry),
			filename: "root.json",
		},
		{
			name:     "Targets roundtrip",
			metadata: Targets(expiry),
			filename: "targets.json",
		},
		{
			name:     "Snapshot roundtrip",
			metadata: Snapshot(expiry),
			filename: "snapshot.json",
		},
		{
			name:     "Timestamp roundtrip",
			metadata: Timestamp(expiry),
			filename: "timestamp.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filePath := filepath.Join(testDir, tt.filename)

			// Write metadata to file
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				assert.NoError(t, meta.ToFile(filePath, false))

				// Read back and compare
				loadedMeta, err := Root().FromFile(filePath)
				assert.NoError(t, err)

				// Compare essential fields
				assert.Equal(t, meta.Signed.Type, loadedMeta.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loadedMeta.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loadedMeta.Signed.SpecVersion)

			case *Metadata[TargetsType]:
				assert.NoError(t, meta.ToFile(filePath, false))

				loadedMeta, err := Targets().FromFile(filePath)
				assert.NoError(t, err)

				assert.Equal(t, meta.Signed.Type, loadedMeta.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loadedMeta.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loadedMeta.Signed.SpecVersion)

			case *Metadata[SnapshotType]:
				assert.NoError(t, meta.ToFile(filePath, false))

				loadedMeta, err := Snapshot().FromFile(filePath)
				assert.NoError(t, err)

				assert.Equal(t, meta.Signed.Type, loadedMeta.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loadedMeta.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loadedMeta.Signed.SpecVersion)

			case *Metadata[TimestampType]:
				assert.NoError(t, meta.ToFile(filePath, false))

				loadedMeta, err := Timestamp().FromFile(filePath)
				assert.NoError(t, err)

				assert.Equal(t, meta.Signed.Type, loadedMeta.Signed.Type)
				assert.Equal(t, meta.Signed.Version, loadedMeta.Signed.Version)
				assert.Equal(t, meta.Signed.SpecVersion, loadedMeta.Signed.SpecVersion)
			}
		})
	}
}

func TestMetadataVersioning(t *testing.T) {
	expiry := time.Now().UTC().Add(24 * time.Hour)

	tests := []struct {
		name       string
		metadata   interface{}
		newVersion int64
		wantErr    bool
	}{
		{
			name:       "Increment Root version",
			metadata:   Root(expiry),
			newVersion: 2,
			wantErr:    false,
		},
		{
			name:       "Set high version number",
			metadata:   Targets(expiry),
			newVersion: 1000000,
			wantErr:    false,
		},
		{
			name:       "Zero version (invalid)",
			metadata:   Snapshot(expiry),
			newVersion: 0,
			wantErr:    false, // Library might allow this, but it's not recommended
		},
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
	pastTime := now.Add(-24 * time.Hour)
	futureTime := now.Add(24 * time.Hour)

	tests := []struct {
		name       string
		metadata   interface{}
		expiration time.Time
		isExpired  bool
	}{
		{
			name:       "Root not expired",
			metadata:   Root(futureTime),
			expiration: futureTime,
			isExpired:  false,
		},
		{
			name:       "Root expired",
			metadata:   Root(pastTime),
			expiration: pastTime,
			isExpired:  true,
		},
		{
			name:       "Targets not expired",
			metadata:   Targets(futureTime),
			expiration: futureTime,
			isExpired:  false,
		},
		{
			name:       "Targets expired",
			metadata:   Targets(pastTime),
			expiration: pastTime,
			isExpired:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			switch meta := tt.metadata.(type) {
			case *Metadata[RootType]:
				assert.Equal(t, tt.expiration.Truncate(time.Second), meta.Signed.Expires.Truncate(time.Second))
				actualExpired := meta.Signed.Expires.Before(now)
				assert.Equal(t, tt.isExpired, actualExpired)
			case *Metadata[TargetsType]:
				assert.Equal(t, tt.expiration.Truncate(time.Second), meta.Signed.Expires.Truncate(time.Second))
				actualExpired := meta.Signed.Expires.Before(now)
				assert.Equal(t, tt.isExpired, actualExpired)
			}
		})
	}
}
