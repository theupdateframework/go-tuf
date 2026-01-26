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
	"testing"
)

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