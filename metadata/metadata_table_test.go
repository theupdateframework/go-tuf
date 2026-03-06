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
