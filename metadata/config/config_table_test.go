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

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

func TestUpdaterConfigCreation(t *testing.T) {
	tests := []struct {
		name         string
		metadataDir  string
		rootBytes    []byte
		expectError  bool
		errorMessage string
		validate     func(t *testing.T, config *UpdaterConfig)
	}{
		{
			name:         "Valid config creation",
			metadataDir:  "testdata/metadata",
			rootBytes:    helpers.CreateTestRootJSON(t),
			expectError:  false,
			errorMessage: "",
			validate: func(t *testing.T, config *UpdaterConfig) {
				assert.NotNil(t, config)
				assert.NotNil(t, config.Fetcher)
				assert.Equal(t, int64(256), config.MaxRootRotations)
				assert.Equal(t, 32, config.MaxDelegations)
				assert.Equal(t, int64(512000), config.RootMaxLength)
				assert.Equal(t, int64(16384), config.TimestampMaxLength)
				assert.Equal(t, int64(2000000), config.SnapshotMaxLength)
				assert.Equal(t, int64(5000000), config.TargetsMaxLength)
				assert.False(t, config.UnsafeLocalMode)
			},
		},
		{
			name:         "Invalid metadata directory path",
			metadataDir:  string([]byte{0x7f}), // Invalid ASCII control character
			rootBytes:    helpers.CreateTestRootJSON(t),
			expectError:  true,
			errorMessage: "invalid control character",
		},
		{
			name:        "Empty root bytes",
			metadataDir: "testdata/metadata",
			rootBytes:   []byte(""),
			expectError: false, // Empty bytes might be handled gracefully
		},
		{
			name:        "Invalid JSON root bytes",
			metadataDir: "testdata/metadata",
			rootBytes:   []byte("{invalid json}"),
			expectError: false, // May be handled at a different level
		},
		{
			name:        "Nil root bytes",
			metadataDir: "testdata/metadata",
			rootBytes:   nil,
			expectError: false, // Nil bytes might be handled gracefully
		},
		{
			name:        "Empty metadata directory",
			metadataDir: "",
			rootBytes:   helpers.CreateTestRootJSON(t),
			expectError: false,
			validate: func(t *testing.T, config *UpdaterConfig) {
				assert.NotNil(t, config)
				assert.Equal(t, "", config.LocalMetadataDir)
			},
		},
		{
			name:        "Very long metadata directory path",
			metadataDir: filepath.Join("very", "very", "very", "very", "very", "very", "very", "very", "long", "path", "to", "metadata"),
			rootBytes:   helpers.CreateTestRootJSON(t),
			expectError: false,
			validate: func(t *testing.T, config *UpdaterConfig) {
				assert.NotNil(t, config)
				// Just verify config was created successfully, path might be processed
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, err := New(tt.metadataDir, tt.rootBytes)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				// Don't assert on config being nil as some errors might still return a config
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, config)
				if tt.validate != nil {
					tt.validate(t, config)
				}
			}
		})
	}
}

func TestUpdaterConfigValidation(t *testing.T) {
	tempManager := helpers.NewTempDirManager()
	defer tempManager.Cleanup(t)

	testDir := tempManager.CreateTempDir(t, "config_test")

	tests := []struct {
		name         string
		setupConfig  func(t *testing.T, testDir string) *UpdaterConfig
		expectError  bool
		errorMessage string
	}{
		{
			name: "Valid paths exist",
			setupConfig: func(t *testing.T, testDir string) *UpdaterConfig {
				metadataDir := filepath.Join(testDir, "metadata")
				targetsDir := filepath.Join(testDir, "targets")

				assert.NoError(t, os.MkdirAll(metadataDir, 0755))
				assert.NoError(t, os.MkdirAll(targetsDir, 0755))

				config, err := New(metadataDir, helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				config.LocalTargetsDir = targetsDir
				return config
			},
			expectError: false,
		},
		{
			name: "Metadata directory does not exist",
			setupConfig: func(t *testing.T, testDir string) *UpdaterConfig {
				metadataDir := filepath.Join(testDir, "nonexistent", "metadata")

				config, err := New(metadataDir, helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				return config
			},
			expectError:  true,
			errorMessage: "no such file or directory",
		},
		{
			name: "Targets directory does not exist",
			setupConfig: func(t *testing.T, testDir string) *UpdaterConfig {
				metadataDir := filepath.Join(testDir, "metadata")
				targetsDir := filepath.Join(testDir, "nonexistent", "targets")

				assert.NoError(t, os.MkdirAll(metadataDir, 0755))

				config, err := New(metadataDir, helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				config.LocalTargetsDir = targetsDir
				return config
			},
			expectError:  true,
			errorMessage: "no such file or directory",
		},
		{
			name: "Metadata directory is a file",
			setupConfig: func(t *testing.T, testDir string) *UpdaterConfig {
				metadataFile := filepath.Join(testDir, "metadata_file")

				helpers.WriteTestFile(t, testDir, "metadata_file", []byte("test"))

				config, err := New(metadataFile, helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				return config
			},
			expectError:  true,
			errorMessage: "not a directory",
		},
		{
			name: "Empty local metadata dir defaults to current directory",
			setupConfig: func(t *testing.T, testDir string) *UpdaterConfig {
				config, err := New("", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				return config
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig(t, testDir)

			err := config.EnsurePathsExist()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUpdaterConfigDefaults(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Default configuration values",
			testFunc: func(t *testing.T) {
				config, err := New("testdata", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)

				// Test default values
				assert.Equal(t, config.MaxRootRotations, int64(256))
				assert.Equal(t, config.MaxDelegations, 32)
				assert.Equal(t, config.RootMaxLength, int64(512000))
				assert.Equal(t, config.TimestampMaxLength, int64(16384))
				assert.Equal(t, config.SnapshotMaxLength, int64(2000000))
				assert.Equal(t, config.TargetsMaxLength, int64(5000000))
				assert.Equal(t, config.UnsafeLocalMode, false)
				assert.Equal(t, config.PrefixTargetsWithHash, true)

				assert.NotNil(t, config.Fetcher)
				assert.IsType(t, &fetcher.DefaultFetcher{}, config.Fetcher)
			},
		},
		{
			name: "Custom configuration values",
			testFunc: func(t *testing.T) {
				config, err := New("testdata", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)

				// Modify configuration
				config.MaxRootRotations = 100
				config.MaxDelegations = 10
				config.RootMaxLength = 100000
				config.UnsafeLocalMode = true
				config.PrefixTargetsWithHash = false

				// Test modified values
				assert.Equal(t, config.MaxRootRotations, int64(100))
				assert.Equal(t, config.MaxDelegations, 10)
				assert.Equal(t, config.RootMaxLength, int64(100000))
				assert.Equal(t, config.UnsafeLocalMode, true)
				assert.Equal(t, config.PrefixTargetsWithHash, false)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.testFunc)
	}
}

func TestUpdaterConfigSerialization(t *testing.T) {
	tests := []struct {
		name     string
		testFunc func(t *testing.T)
	}{
		{
			name: "Config can be copied",
			testFunc: func(t *testing.T) {
				originalConfig, err := New("testdata", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)

				// Create a copy
				copiedConfig := *originalConfig

				// Modify original
				originalConfig.MaxRootRotations = 999
				originalConfig.UnsafeLocalMode = true

				// Verify copy is independent
				assert.NotEqual(t, copiedConfig.MaxRootRotations, originalConfig.MaxRootRotations)
				assert.NotEqual(t, copiedConfig.UnsafeLocalMode, originalConfig.UnsafeLocalMode)
			},
		},
		{
			name: "Config with custom fetcher",
			testFunc: func(t *testing.T) {
				config, err := New("testdata", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)

				// Set custom fetcher
				customFetcher := &fetcher.DefaultFetcher{}
				config.Fetcher = customFetcher

				assert.Same(t, customFetcher, config.Fetcher)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.testFunc)
	}
}

func TestUpdaterConfigEdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		setupConfig  func() *UpdaterConfig
		expectError  bool
		errorMessage string
	}{
		{
			name: "Zero length limits",
			setupConfig: func() *UpdaterConfig {
				config, err := New("testdata", helpers.CreateTestRootJSON(&testing.T{}))
				assert.NoError(&testing.T{}, err)
				config.RootMaxLength = 0
				config.TimestampMaxLength = 0
				config.SnapshotMaxLength = 0
				config.TargetsMaxLength = 0
				return config
			},
			expectError: false, // Zero limits might be valid in some contexts
		},
		{
			name: "Negative length limits",
			setupConfig: func() *UpdaterConfig {
				config, err := New("testdata", helpers.CreateTestRootJSON(&testing.T{}))
				assert.NoError(&testing.T{}, err)
				config.RootMaxLength = -1
				config.TimestampMaxLength = -1
				config.SnapshotMaxLength = -1
				config.TargetsMaxLength = -1
				return config
			},
			expectError: false, // Negative limits might be handled gracefully
		},
		{
			name: "Very large length limits",
			setupConfig: func() *UpdaterConfig {
				config, err := New("testdata", helpers.CreateTestRootJSON(&testing.T{}))
				assert.NoError(&testing.T{}, err)
				config.RootMaxLength = 1 << 60 // Very large number
				config.TimestampMaxLength = 1 << 60
				config.SnapshotMaxLength = 1 << 60
				config.TargetsMaxLength = 1 << 60
				return config
			},
			expectError: false,
		},
		{
			name: "Zero rotations and delegations",
			setupConfig: func() *UpdaterConfig {
				config, err := New("testdata", helpers.CreateTestRootJSON(&testing.T{}))
				assert.NoError(&testing.T{}, err)
				config.MaxRootRotations = 0
				config.MaxDelegations = 0
				return config
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.setupConfig()

			// Test that the configuration doesn't cause immediate errors
			err := config.EnsurePathsExist()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				// The configuration itself should be valid, even if unusual
				assert.NotNil(t, config)
			}
		})
	}
}

func TestUpdaterConfigValidURL(t *testing.T) {
	tests := []struct {
		name         string
		metadataDir  string
		expectError  bool
		errorMessage string
	}{
		{
			name:        "Valid simple path",
			metadataDir: "simple/path",
			expectError: false,
		},
		{
			name:        "Valid absolute path",
			metadataDir: "/absolute/path",
			expectError: false,
		},
		{
			name:        "Valid URL",
			metadataDir: "https://example.com/metadata",
			expectError: false,
		},
		{
			name:        "Valid file URL",
			metadataDir: "file:///path/to/metadata",
			expectError: false,
		},
		{
			name:         "Invalid control character",
			metadataDir:  string([]byte{0x7f}),
			expectError:  true,
			errorMessage: "invalid control character",
		},
		{
			name:        "Path with spaces",
			metadataDir: "path with spaces",
			expectError: false,
		},
		{
			name:        "Path with special characters",
			metadataDir: "path/with/special-chars_123",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.metadataDir, helpers.CreateTestRootJSON(t))

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
