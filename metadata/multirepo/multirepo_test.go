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

package multirepo

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	validMapJSON := []byte(`{
		"repositories": {
			"test-repo": ["https://example.com/repo"]
		},
		"mapping": []
	}`)

	tests := []struct {
		name    string
		desc    string
		repoMap []byte
		roots   map[string][]byte
		wantErr bool
	}{
		{
			name:    "empty map file returns error",
			desc:    "Creating config with empty map file should fail",
			repoMap: []byte(""),
			roots:   map[string][]byte{},
			wantErr: true,
		},
		{
			name:    "empty roots returns error",
			desc:    "Creating config with empty roots should fail",
			repoMap: validMapJSON,
			roots:   map[string][]byte{},
			wantErr: true,
		},
		{
			name:    "valid config succeeds",
			desc:    "Creating config with valid map and roots should succeed",
			repoMap: validMapJSON,
			roots:   map[string][]byte{"test-repo": []byte(`{"signatures":[],"signed":{}}`)},
			wantErr: false,
		},
		{
			name:    "missing root for repo returns error",
			desc:    "Creating config with missing root metadata for a repository should fail",
			repoMap: validMapJSON,
			roots:   map[string][]byte{"other-repo": []byte(`{"signatures":[],"signed":{}}`)},
			wantErr: true,
		},
		{
			name:    "invalid JSON map file returns error",
			desc:    "Creating config with invalid JSON should fail",
			repoMap: []byte(`{invalid json}`),
			roots:   map[string][]byte{"test-repo": []byte(`{"signatures":[],"signed":{}}`)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Desc: %s", tt.desc)

			cfg, err := NewConfig(tt.repoMap, tt.roots)

			if tt.wantErr {
				assert.Error(t, err, "expected error but got none")
				return
			}

			assert.NoError(t, err, "expected no error but got %v", err)
			assert.NotNil(t, cfg, "expected config to be non-nil")
		})
	}
}

// TestNewConfigErrorWrapping asserts that NewConfig's input-validation
// error wraps only the sentinel matching the actually-missing input, so
// callers can use errors.Is to discriminate.
func TestNewConfigErrorWrapping(t *testing.T) {
	validMapJSON := []byte(`{
		"repositories": {
			"test-repo": ["https://example.com/repo"]
		},
		"mapping": []
	}`)
	rootBytes := []byte(`{"signatures":[],"signed":{}}`)

	tests := []struct {
		name         string
		repoMap      []byte
		roots        map[string][]byte
		shouldWrap   []error
		shouldNotWrap []error
	}{
		{
			name:          "only map file missing",
			repoMap:       nil,
			roots:         map[string][]byte{"test-repo": rootBytes},
			shouldWrap:    []error{ErrNoMapFile},
			shouldNotWrap: []error{ErrNoTrustedRoots},
		},
		{
			name:          "only trusted roots missing",
			repoMap:       validMapJSON,
			roots:         map[string][]byte{},
			shouldWrap:    []error{ErrNoTrustedRoots},
			shouldNotWrap: []error{ErrNoMapFile},
		},
		{
			name:       "both missing",
			repoMap:    nil,
			roots:      map[string][]byte{},
			shouldWrap: []error{ErrNoMapFile, ErrNoTrustedRoots},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewConfig(tt.repoMap, tt.roots)
			assert.Error(t, err)
			for _, target := range tt.shouldWrap {
				assert.ErrorIs(t, err, target, "error should wrap %v", target)
			}
			for _, target := range tt.shouldNotWrap {
				assert.NotErrorIs(t, err, target, "error must not wrap %v", target)
			}
		})
	}
}

func TestValidateRepoName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		// Valid names - must start with alphanumeric, contain only [a-zA-Z0-9._-]
		{"valid simple name", "my-repo", false},
		{"valid name with numbers", "repo123", false},
		{"valid starts with number", "123repo", false},
		{"valid name with dots", "my.repo.name", false},
		{"valid name with underscores", "my_repo_name", false},
		{"valid mixed", "sigstore-tuf-root", false},
		{"valid version style", "repo.v2.1", false},
		{"valid single char", "a", false},
		{"valid single number", "1", false},

		// Invalid: empty
		{"empty name", "", true},

		// Invalid: starts with non-alphanumeric
		{"starts with dot", ".hidden", true},
		{"starts with hyphen", "-repo", true},
		{"starts with underscore", "_repo", true},

		// Invalid: traversal components
		{"single dot", ".", true},
		{"double dot", "..", true},

		// Invalid: path separators
		{"unix path separator", "foo/bar", true},
		{"windows path separator", "foo\\bar", true},
		{"traversal with unix separator", "../escaped", true},
		{"traversal with windows separator", "..\\escaped", true},
		{"deep traversal", "../../etc/passwd", true},

		// Invalid: absolute paths
		{"unix absolute path", "/etc/passwd", true},
		{"windows absolute path", "C:\\Windows", true},

		// Invalid: special characters
		{"contains space", "my repo", true},
		{"contains at sign", "repo@org", true},
		{"contains colon", "repo:tag", true},
		{"contains hash", "repo#1", true},
		{"contains exclamation", "repo!", true},
		{"contains semicolon", "repo;rm", true},
		{"contains unicode", "репо", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRepoName(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRepoName(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
			}
			if err != nil && !errors.Is(err, ErrInvalidRepoName) {
				t.Errorf("validateRepoName(%q) error should wrap ErrInvalidRepoName, got %v", tt.input, err)
			}
		})
	}
}

func TestNewRejectsInvalidRepoNames(t *testing.T) {
	tests := []struct {
		name     string
		repoName string
	}{
		{"path traversal", "../escaped-repo"},
		{"starts with dot", ".hidden-repo"},
		{"contains slash", "foo/bar"},
		{"contains space", "my repo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapJSON := []byte(`{
				"repositories": {
					"` + tt.repoName + `": ["https://example.com/repo"]
				},
				"mapping": []
			}`)

			rootBytes := []byte(`{"signatures":[],"signed":{}}`)

			cfg, err := NewConfig(mapJSON, map[string][]byte{tt.repoName: rootBytes})
			if err != nil {
				t.Fatalf("NewConfig() unexpected error: %v", err)
			}

			_, err = New(cfg)
			if err == nil {
				t.Fatalf("New() should reject repository name %q", tt.repoName)
			}

			if !errors.Is(err, ErrInvalidRepoName) {
				t.Errorf("New() error should wrap ErrInvalidRepoName, got: %v", err)
			}
		})
	}
}

// TestEnsurePathsExistTable exercises MultiRepoConfig.EnsurePathsExist
// directly: it's the one method that has no dependence on the
// per-repository updater plumbing, so we can hit every branch with a
// plain config struct.
func TestEnsurePathsExistTable(t *testing.T) {
	tests := []struct {
		name        string
		buildCfg    func(t *testing.T) *MultiRepoConfig
		expectError bool
		errorIs     error
	}{
		{
			name: "creates metadata and targets directories",
			buildCfg: func(t *testing.T) *MultiRepoConfig {
				t.Helper()
				tmp := t.TempDir()
				return &MultiRepoConfig{
					LocalMetadataDir: filepath.Join(tmp, "metadata"),
					LocalTargetsDir:  filepath.Join(tmp, "targets"),
				}
			},
		},
		{
			name: "no-op when local cache is disabled",
			buildCfg: func(t *testing.T) *MultiRepoConfig {
				t.Helper()
				return &MultiRepoConfig{
					DisableLocalCache: true,
					LocalMetadataDir:  "", // would otherwise fail
					LocalTargetsDir:   "",
				}
			},
		},
		{
			name: "already-existing directories succeed",
			buildCfg: func(t *testing.T) *MultiRepoConfig {
				t.Helper()
				tmp := t.TempDir()
				md := filepath.Join(tmp, "metadata")
				td := filepath.Join(tmp, "targets")
				assert.NoError(t, os.MkdirAll(md, 0700))
				assert.NoError(t, os.MkdirAll(td, 0700))
				return &MultiRepoConfig{LocalMetadataDir: md, LocalTargetsDir: td}
			},
		},
		{
			name: "fails when paths are empty and cache is enabled",
			buildCfg: func(t *testing.T) *MultiRepoConfig {
				t.Helper()
				return &MultiRepoConfig{LocalMetadataDir: "", LocalTargetsDir: ""}
			},
			expectError: true,
			errorIs:     os.ErrNotExist,
		},
		{
			name: "fails when a path collides with an existing file",
			buildCfg: func(t *testing.T) *MultiRepoConfig {
				t.Helper()
				tmp := t.TempDir()
				file := filepath.Join(tmp, "blocking_file")
				assert.NoError(t, os.WriteFile(file, []byte("x"), 0600))
				return &MultiRepoConfig{
					LocalMetadataDir: file,
					LocalTargetsDir:  filepath.Join(tmp, "targets"),
				}
			},
			expectError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.buildCfg(t)
			err := cfg.EnsurePathsExist()
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
				return
			}
			assert.NoError(t, err)
		})
	}
}

// TestNewFailureCases covers the New() construction error paths that
// fire before any per-repository updater is created. The happy path
// requires a working network of TUF repositories and is out of scope
// for this unit-level test.
func TestNewFailureCases(t *testing.T) {
	validMapJSON := []byte(`{
		"repositories": {
			"test-repo": ["https://example.com/repo"]
		},
		"mapping": []
	}`)
	rootBytes := []byte(`{"signatures":[],"signed":{}}`)

	t.Run("invalid root bytes fail updater construction", func(t *testing.T) {
		cfg, err := NewConfig(validMapJSON, map[string][]byte{"test-repo": rootBytes})
		assert.NoError(t, err)
		cfg.LocalMetadataDir = t.TempDir()
		cfg.LocalTargetsDir = t.TempDir()

		// The root bytes pass NewConfig (which only checks "is the key
		// present") but fail when updater.New tries to parse them.
		_, err = New(cfg)
		assert.Error(t, err)
	})

	t.Run("empty trusted roots after NewConfig", func(t *testing.T) {
		cfg, err := NewConfig(validMapJSON, map[string][]byte{"test-repo": rootBytes})
		assert.NoError(t, err)
		cfg.LocalMetadataDir = t.TempDir()
		cfg.LocalTargetsDir = t.TempDir()
		// Sabotage the trusted-roots map after config construction so
		// initTUFClients hits the "trusted root missing" branch.
		cfg.TrustedRoots = map[string][]byte{}

		_, err = New(cfg)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to get trusted root metadata from config")
	})
}
