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

// TestUpdaterConfigNew tests the New constructor using table-driven tests.
// It covers valid and invalid remote URL inputs.
func TestUpdaterConfigNew(t *testing.T) {
	rootBytes := helpers.CreateTestRootJSON(t)

	tests := []struct {
		name         string
		remoteURL    string
		expectError  bool
		errorMessage string
		validate     func(t *testing.T, cfg *UpdaterConfig)
	}{
		{
			name:        "valid simple path",
			remoteURL:   "simple/path",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.NotNil(t, cfg)
				assert.Equal(t, "simple/path", cfg.RemoteMetadataURL)
				assert.Equal(t, int64(256), cfg.MaxRootRotations)
				assert.Equal(t, 32, cfg.MaxDelegations)
				assert.Equal(t, int64(512000), cfg.RootMaxLength)
				assert.Equal(t, int64(16384), cfg.TimestampMaxLength)
				assert.Equal(t, int64(2000000), cfg.SnapshotMaxLength)
				assert.Equal(t, int64(5000000), cfg.TargetsMaxLength)
				assert.False(t, cfg.UnsafeLocalMode)
				assert.True(t, cfg.PrefixTargetsWithHash)
				assert.NotNil(t, cfg.Fetcher)
				assert.IsType(t, &fetcher.DefaultFetcher{}, cfg.Fetcher)
			},
		},
		{
			name:        "valid absolute path",
			remoteURL:   "/absolute/path/to/metadata",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.NotNil(t, cfg)
				assert.Equal(t, "/absolute/path/to/metadata", cfg.RemoteMetadataURL)
			},
		},
		{
			name:        "valid https URL",
			remoteURL:   "https://example.com/metadata",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.Equal(t, "https://example.com/metadata", cfg.RemoteMetadataURL)
				assert.Equal(t, "https://example.com/metadata/targets", cfg.RemoteTargetsURL)
			},
		},
		{
			name:        "valid file URL",
			remoteURL:   "file:///path/to/metadata",
			expectError: false,
		},
		{
			name:        "empty remote URL",
			remoteURL:   "",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.NotNil(t, cfg)
				assert.Equal(t, "", cfg.RemoteMetadataURL)
			},
		},
		{
			name:         "invalid control character in URL",
			remoteURL:    string([]byte{0x7f}),
			expectError:  true,
			errorMessage: "invalid control character",
		},
		{
			name:        "path with spaces",
			remoteURL:   "path with spaces",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := New(tt.remoteURL, rootBytes)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, cfg)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, cfg)
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestUpdaterConfigDefaults verifies the default and custom configuration values.
func TestUpdaterConfigDefaults(t *testing.T) {
	t.Run("default configuration values", func(t *testing.T) {
		cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
		assert.NoError(t, err)

		assert.Equal(t, int64(256), cfg.MaxRootRotations)
		assert.Equal(t, 32, cfg.MaxDelegations)
		assert.Equal(t, int64(512000), cfg.RootMaxLength)
		assert.Equal(t, int64(16384), cfg.TimestampMaxLength)
		assert.Equal(t, int64(2000000), cfg.SnapshotMaxLength)
		assert.Equal(t, int64(5000000), cfg.TargetsMaxLength)
		assert.False(t, cfg.UnsafeLocalMode)
		assert.True(t, cfg.PrefixTargetsWithHash)
		assert.False(t, cfg.DisableLocalCache)
		assert.NotNil(t, cfg.Fetcher)
		assert.IsType(t, &fetcher.DefaultFetcher{}, cfg.Fetcher)
	})

	t.Run("custom configuration values", func(t *testing.T) {
		cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
		assert.NoError(t, err)

		cfg.MaxRootRotations = 100
		cfg.MaxDelegations = 10
		cfg.RootMaxLength = 100000
		cfg.UnsafeLocalMode = true
		cfg.PrefixTargetsWithHash = false

		assert.Equal(t, int64(100), cfg.MaxRootRotations)
		assert.Equal(t, 10, cfg.MaxDelegations)
		assert.Equal(t, int64(100000), cfg.RootMaxLength)
		assert.True(t, cfg.UnsafeLocalMode)
		assert.False(t, cfg.PrefixTargetsWithHash)
	})
}

// TestEnsurePathsExistTable tests EnsurePathsExist via table-driven subtests.
// EnsurePathsExist calls os.MkdirAll to create local cache directories.
func TestEnsurePathsExistTable(t *testing.T) {
	tests := []struct {
		name         string
		buildConfig  func(t *testing.T) *UpdaterConfig
		expectError  bool
		errorMessage string
	}{
		{
			name: "creates metadata and targets directories",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = filepath.Join(tmp, "metadata")
				cfg.LocalTargetsDir = filepath.Join(tmp, "targets")
				return cfg
			},
			expectError: false,
		},
		{
			name: "creates deeply nested directories",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = filepath.Join(tmp, "a", "b", "c", "metadata")
				cfg.LocalTargetsDir = filepath.Join(tmp, "a", "b", "c", "targets")
				return cfg
			},
			expectError: false,
		},
		{
			name: "no-op when DisableLocalCache is true",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.DisableLocalCache = true
				// Empty paths that would otherwise fail
				cfg.LocalMetadataDir = ""
				cfg.LocalTargetsDir = ""
				return cfg
			},
			expectError: false,
		},
		{
			name: "fails when metadata dir path is empty",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = ""
				cfg.LocalTargetsDir = ""
				return cfg
			},
			expectError: true,
		},
		{
			name: "fails when metadata dir path is a file",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				// Create a file at the path where a directory is expected
				metadataFile := filepath.Join(tmp, "metadata_file")
				err := os.WriteFile(metadataFile, []byte("test"), 0600)
				assert.NoError(t, err)

				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = metadataFile
				cfg.LocalTargetsDir = filepath.Join(tmp, "targets")
				return cfg
			},
			expectError:  true,
			errorMessage: "not a directory",
		},
		{
			name: "already-existing directories succeed",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				metadataDir := filepath.Join(tmp, "metadata")
				targetsDir := filepath.Join(tmp, "targets")
				assert.NoError(t, os.MkdirAll(metadataDir, 0700))
				assert.NoError(t, os.MkdirAll(targetsDir, 0700))

				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = metadataDir
				cfg.LocalTargetsDir = targetsDir
				return cfg
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.buildConfig(t)
			err := cfg.EnsurePathsExist()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestUpdaterConfigCopy verifies that config values can be copied independently.
func TestUpdaterConfigCopy(t *testing.T) {
	original, err := New("https://example.com", helpers.CreateTestRootJSON(t))
	assert.NoError(t, err)

	copied := *original

	// Mutate the original
	original.MaxRootRotations = 999
	original.UnsafeLocalMode = true

	// Verify the copy is independent of the original
	assert.NotEqual(t, copied.MaxRootRotations, original.MaxRootRotations)
	assert.NotEqual(t, copied.UnsafeLocalMode, original.UnsafeLocalMode)
}

// TestUpdaterConfigCustomFetcher verifies that a custom fetcher can be set.
func TestUpdaterConfigCustomFetcher(t *testing.T) {
	cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
	assert.NoError(t, err)

	customFetcher := &fetcher.DefaultFetcher{}
	cfg.Fetcher = customFetcher

	assert.Same(t, customFetcher, cfg.Fetcher)
}
