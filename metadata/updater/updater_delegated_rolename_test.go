// Copyright 2026 The Update Framework Authors
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

package updater

import (
	"net/url"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// A delegated role name must not change where its cached metadata is read
// from on disk. persistMetadata, downloadMetadata and generateTargetFilePath
// all url.PathEscape the role name before using it as a path component, so a
// name is confined to LocalMetadataDir. loadTargets previously joined the raw
// name, so a name containing a path-traversal sequence or characters rewritten
// by url.PathEscape either resolved outside LocalMetadataDir or missed the
// escaped file written on persist.
func TestDelegatedRoleNameLocalReadStaysInMetadataDir(t *testing.T) {
	const targetPath = "target.txt"

	cases := []struct {
		name string
		role string
	}{
		{name: "dotdot", role: ".."},
		{name: "dot", role: "."},
		{name: "slash", role: "a/b"},
		{name: "space", role: "role with space"},
		{name: "percent", role: "100%"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			delegate(repo, metadata.TARGETS, tc.role, "*")
			repo.AddTarget(tc.role, []byte("hello"), targetPath)
			repo.UpdateSnapshot()

			// First client fetches the delegated metadata and caches it locally.
			up1, err := createAndRefresh(t, repo)
			require.NoError(t, err)
			info, err := up1.GetTargetInfo(targetPath)
			require.NoError(t, err)
			require.NotNil(t, info)

			expectedFile := filepath.Join(repo.MetadataDir, url.PathEscape(tc.role)+".json")
			assert.Equal(t, repo.MetadataDir, filepath.Dir(expectedFile))
			assert.FileExists(t, expectedFile)

			// A fresh client reads that cached metadata back instead of
			// refetching it from the remote repository.
			repo.Simulator.FetchTracker.Metadata = []simulator.FTMetadata{}
			up2, err := createAndRefresh(t, repo)
			require.NoError(t, err)
			info, err = up2.GetTargetInfo(targetPath)
			require.NoError(t, err)
			require.NotNil(t, info)

			refetched := slices.ContainsFunc(repo.Simulator.FetchTracker.Metadata, func(m simulator.FTMetadata) bool {
				return m.Name == tc.role
			})
			assert.False(t, refetched, "delegated role %q should be read from the local cache, not refetched", tc.role)
		})
	}
}
