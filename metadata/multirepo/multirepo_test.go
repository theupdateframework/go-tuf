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
	"path"
	"strings"
	"testing"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
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

			_, err := NewConfig(mapJSON, map[string][]byte{tt.repoName: rootBytes})
			if err == nil {
				t.Fatalf("New() should reject repository name %q", tt.repoName)
			}

			if !errors.Is(err, ErrInvalidRepoName) {
				t.Errorf("New() error should wrap ErrInvalidRepoName, got: %v", err)
			}
		})
	}
}

func TestNewRejectsRepositoriesWithoutURL(t *testing.T) {
	tests := []struct {
		name     string
		repoURLs string
	}{
		{"empty URL list", `[]`},
		{"null URL list", `null`},
		{"empty URL string", `[""]`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mapJSON := []byte(`{
				"repositories": {
					"my-repo": ` + tt.repoURLs + `
				},
				"mapping": []
			}`)

			rootBytes := []byte(`{"signatures":[],"signed":{}}`)

			_, err := NewConfig(mapJSON, map[string][]byte{"my-repo": rootBytes})
			if err == nil {
				t.Fatalf("New() should reject repository with URLs %s", tt.repoURLs)
			}

			if !errors.Is(err, ErrMissingRepoURL) {
				t.Errorf("New() error should wrap ErrMissingRepoURL, got: %v", err)
			}
		})
	}
}

func TestNewRejectsMappingWithUnknownRepository(t *testing.T) {
	// A mapping that references a repository absent from the top-level
	// "repositories" object leaves no TUF client for that name, which makes
	// GetTargetInfo dereference a nil *updater.Updater.
	mapJSON := []byte(`{
		"repositories": {
			"real-repo": ["https://example.com/repo"]
		},
		"mapping": [
			{
				"paths": ["*"],
				"repositories": ["typo-repo"],
				"threshold": 1,
				"terminating": true
			}
		]
	}`)

	rootBytes := []byte(`{"signatures":[],"signed":{}}`)

	_, err := NewConfig(mapJSON, map[string][]byte{"real-repo": rootBytes})
	if err == nil {
		t.Fatal("NewConfig() should reject a mapping referencing an unknown repository")
	}

	if !errors.Is(err, ErrUnknownMappingRepo) {
		t.Errorf("NewConfig() error should wrap ErrUnknownMappingRepo, got: %v", err)
	}
}

func TestNewRejectsNullMapping(t *testing.T) {
	// "mapping": [null] unmarshals into a []*Mapping holding a nil element,
	// which GetTargetInfo would dereference while walking the mappings.
	mapJSON := []byte(`{
		"repositories": {
			"real-repo": ["https://example.com/repo"]
		},
		"mapping": [null]
	}`)

	rootBytes := []byte(`{"signatures":[],"signed":{}}`)

	_, err := NewConfig(mapJSON, map[string][]byte{"real-repo": rootBytes})
	if err == nil {
		t.Fatal("NewConfig() should reject a null mapping entry")
	}
}

func TestNewRejectsMissingTrustedRoot(t *testing.T) {
	// every repository listed in the map file must come with a trusted root
	// metadata file, otherwise its TUF client cannot be bootstrapped
	mapJSON := []byte(`{
		"repositories": {
			"repo-with-root": ["https://example.com/repo"],
			"repo-without-root": ["https://example.com/other"]
		},
		"mapping": [
			{
				"paths": ["*"],
				"repositories": ["repo-with-root"],
				"threshold": 1,
				"terminating": true
			}
		]
	}`)

	rootBytes := []byte(`{"signatures":[],"signed":{}}`)

	_, err := NewConfig(mapJSON, map[string][]byte{"repo-with-root": rootBytes})
	if err == nil {
		t.Fatal("NewConfig() should reject a repository without trusted root metadata")
	}

	if !errors.Is(err, ErrMissingTrustedRoot) {
		t.Errorf("NewConfig() error should wrap ErrMissingTrustedRoot, got: %v", err)
	}
	if !strings.Contains(err.Error(), "repo-without-root") {
		t.Errorf("NewConfig() error should name the offending repository, got: %v", err)
	}
}

func TestNewRejectsConfigWithoutRepoMap(t *testing.T) {
	// MultiRepoConfig has exported fields, so callers can build one directly
	// without going through NewConfig and leave RepoMap unset.
	_, err := New(&MultiRepoConfig{})
	if err == nil {
		t.Fatal("New() should reject a config with no repository map")
	}
}

func TestNewRejectsNilConfig(t *testing.T) {
	// NewConfig returns a nil config alongside its error, so a caller that
	// ignores the error passes nil straight into New.
	_, err := New(nil)
	if err == nil {
		t.Fatal("New() should reject a nil config")
	}
}

// newBareMultiRepoClient constructs a MultiRepoClient with the given repo map
// mapping and no initialized repository clients. GetTargetInfo walks the
// mappings before it consults TUFClients, so a terminating mapping lets us
// exercise the path-pattern matching behavior without any TUF repository.
func newBareMultiRepoClient(mapping []*Mapping) *MultiRepoClient {
	return &MultiRepoClient{
		TUFClients: map[string]*updater.Updater{},
		Config: &MultiRepoConfig{
			RepoMap: &MultiRepoMapType{
				Repositories: map[string][]string{"repo": {"https://example.com"}},
				Mapping:      mapping,
			},
		},
	}
}

func TestGetTargetInfoInvalidPattern(t *testing.T) {
	// A malformed glob in a map.json mapping (an unterminated character
	// class) must surface an error to the caller instead of being silently
	// treated as a non-match. GetTargetInfo must never claim "target info
	// not found" for a reason it never checked.
	client := newBareMultiRepoClient([]*Mapping{
		{
			Paths:        []string{"targets/["},
			Repositories: []string{"repo"},
			Threshold:    1,
			Terminating:  true,
		},
	})
	_, _, err := client.GetTargetInfo("targets/foo")
	if err == nil {
		t.Fatal("GetTargetInfo() succeeded for a mapping whose path pattern is malformed, want path.ErrBadPattern")
	}
	if !errors.Is(err, path.ErrBadPattern) {
		t.Errorf("GetTargetInfo() error = %v, want it to wrap path.ErrBadPattern", err)
	}
}

// TestGetTargetInfoMatchIsOSIndependent verifies that map.json path patterns
// match "/"-separated target paths the same way on every OS, and that "\" in
// a pattern is a glob escape rather than a host path separator. Before this
// fix the multirepo client used filepath.Match, whose separator handling
// depends on the host OS, so a pattern like "a\/c" or a target name that
// contains a literal backslash resolved differently on Windows than on
// POSIX systems, breaking the TAP 4 mapping consensus (see #747).
func TestGetTargetInfoMatchIsOSIndependent(t *testing.T) {
	// Set up one fully offline simulated repository serving a single target.
	sim, metadataDir, targetsDir, err := simulator.InitMetadataDir()
	if err != nil {
		t.Fatalf("InitMetadataDir() failed: %v", err)
	}
	defer simulator.RepositoryCleanup(simulator.LocalDir)
	content := []byte("target content")
	sim.AddTarget("targets", content, "sigstore-tuf-root/root.json")
	sim.AddTarget("targets", content, `a/\`)

	rootBytes, err := simulator.GetRootBytes(metadataDir)
	if err != nil {
		t.Fatalf("GetRootBytes() failed: %v", err)
	}
	cfg, err := config.New(metadataDir, rootBytes)
	if err != nil {
		t.Fatalf("config.New() failed: %v", err)
	}
	cfg.Fetcher = sim
	cfg.LocalMetadataDir = metadataDir
	cfg.LocalTargetsDir = targetsDir
	repoUpdater, err := updater.New(cfg)
	if err != nil {
		t.Fatalf("updater.New() failed: %v", err)
	}

	tests := []struct {
		name    string
		pattern string
		target  string
		want    bool // whether the TAP 4 search should reach the target
	}{
		{
			name:    "escaped separator in pattern matches a plain target",
			pattern: `sigstore-tuf-root\/root.json`,
			target:  "sigstore-tuf-root/root.json",
			want:    true,
		},
		{
			name:    "wildcard with escaped separator matches",
			pattern: `*\/*`,
			target:  "sigstore-tuf-root/root.json",
			want:    true,
		},
		{
			name:    "literal backslash in target matched by a wildcard",
			pattern: "a/?",
			target:  `a/\`,
			want:    true,
		},
		{
			name:    "control single-segment glob matches same-segment target",
			pattern: "sigstore-tuf-root/*",
			target:  "sigstore-tuf-root/root.json",
			want:    true,
		},
		{
			name:    "control unrelated pattern does not match",
			pattern: "x/*",
			target:  "sigstore-tuf-root/root.json",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &MultiRepoClient{
				TUFClients: map[string]*updater.Updater{"repo": repoUpdater},
				Config: &MultiRepoConfig{
					RepoMap: &MultiRepoMapType{
						Repositories: map[string][]string{"repo": {"https://example.com"}},
						Mapping: []*Mapping{
							{
								Paths:        []string{tt.pattern},
								Repositories: []string{"repo"},
								Threshold:    1,
								Terminating:  true,
							},
						},
					},
				},
			}
			_, _, err := client.GetTargetInfo(tt.target)
			gotMatch := err == nil
			if gotMatch != tt.want {
				t.Errorf("GetTargetInfo(%q) with pattern %q: err = %v, want match = %v", tt.target, tt.pattern, err, tt.want)
			}
		})
	}
}
