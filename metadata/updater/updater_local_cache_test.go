// Copyright 2024 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// damage rewrites a cached metadata file in a way the local load has to reject.
var damage = map[string]func(original []byte) []byte{
	"truncated": func(original []byte) []byte {
		return original[:len(original)/2]
	},
	"not json": func([]byte) []byte {
		return []byte("not json at all")
	},
	"wrong _type": func([]byte) []byte {
		return []byte(`{"signed":{"_type":"not-a-role"},"signatures":[]}`)
	},
	"empty": func([]byte) []byte {
		return []byte{}
	},
}

// A damaged file in the local metadata cache must not block updates. Deleting the
// file recovers, and so does a file whose signature does not verify, so a client
// that cannot be repaired by re-downloading is the odd one out. The cases below
// used to leave Refresh failing on every call until the file was removed by hand.
func TestRefreshRecoversFromADamagedLocalCache(t *testing.T) {
	for _, role := range []string{metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		for name, corrupt := range damage {
			t.Run(role+"/"+name, func(t *testing.T) {
				assert.NoError(t, loadOrResetTrustedRootMetadata())

				updaterConfig, err := loadUpdaterConfig()
				assert.NoError(t, err)
				_, err = runRefresh(updaterConfig, time.Now())
				assert.NoError(t, err, "the first refresh must succeed, or this proves nothing")

				cached := filepath.Join(simulator.MetadataDir, role+".json")
				original, err := os.ReadFile(cached)
				assert.NoError(t, err)
				assert.NoError(t, os.WriteFile(cached, corrupt(original), 0644))

				updaterConfig, err = loadUpdaterConfig()
				assert.NoError(t, err)
				_, err = runRefresh(updaterConfig, time.Now())
				assert.NoError(t, err, "a damaged %s cache must be replaced from remote", role)

				refreshed, err := os.ReadFile(cached)
				assert.NoError(t, err)
				assert.Equal(t, original, refreshed, "the damaged file must be overwritten")
			})
		}
	}
}

// The signature case is the control: it has always recovered, because
// ErrUnsignedMetadata is an ErrRepository and the local load already fell back on
// those. It is here so a regression that breaks the fallback wholesale is
// distinguishable from one that only breaks the deserialization half.
func TestRefreshStillRecoversFromAnUnsignedLocalCache(t *testing.T) {
	assert.NoError(t, loadOrResetTrustedRootMetadata())

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	cached := filepath.Join(simulator.MetadataDir, metadata.TIMESTAMP+".json")
	original, err := os.ReadFile(cached)
	assert.NoError(t, err)

	damaged := make([]byte, len(original))
	copy(damaged, original)
	for i := len(damaged) - 1; i >= 0; i-- {
		if damaged[i] >= 'a' && damaged[i] <= 'e' {
			damaged[i]++
			break
		}
	}
	assert.NotEqual(t, original, damaged)
	assert.NoError(t, os.WriteFile(cached, damaged, 0644))

	updaterConfig, err = loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
}
