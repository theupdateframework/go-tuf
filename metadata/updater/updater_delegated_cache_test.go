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

package updater

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/metadata/config"
)

// TestDelegatedMetadataCacheRoundTrip checks that metadata persisted for a
// delegated role can be read back from the cache. persistMetadata URL-escapes
// the role name in the file name, so the read side must escape it the same way.
// Before this was fixed the read used the raw role name, so a delegated role
// whose name contained a space, a "/", or a "." segment was written under one
// file name and looked for under another, causing a permanent cache miss (the
// metadata was re-downloaded on every refresh) and, for a name like "..", a
// read outside LocalMetadataDir.
func TestDelegatedMetadataCacheRoundTrip(t *testing.T) {
	roleNames := []string{
		"role with space",
		"a/b",
		"..",
		".",
		"100%",
	}

	for _, roleName := range roleNames {
		t.Run(roleName, func(t *testing.T) {
			dir := t.TempDir()
			update := &Updater{cfg: &config.UpdaterConfig{LocalMetadataDir: dir}}
			data := []byte("delegated metadata for " + roleName)

			err := update.persistMetadata(roleName, data)
			assert.NoError(t, err)

			// The cache file lives inside LocalMetadataDir under the escaped name.
			path := update.localMetadataPath(roleName)
			assert.Equal(t, dir, filepath.Dir(path))
			assert.Equal(t, url.PathEscape(roleName)+".json", filepath.Base(path))

			// The read loadTargets performs recovers the persisted bytes.
			got, err := os.ReadFile(path)
			assert.NoError(t, err)
			assert.Equal(t, data, got)
		})
	}
}
