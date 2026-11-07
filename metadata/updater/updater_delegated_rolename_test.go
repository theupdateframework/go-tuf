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
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// A delegated role name must not change where its cached metadata is read
// from on disk. persistMetadata, downloadMetadata and generateTargetFilePath
// all url.PathEscape the role name before using it as a path component, so a
// name is confined to LocalMetadataDir. loadTargets joined the raw name, so a
// name containing a path-traversal sequence resolved the local read outside
// LocalMetadataDir and never matched the escaped name used on write.
func TestDelegatedRoleNameLocalReadStaysInMetadataDir(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = false
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	delegatedRole := metadata.DelegatedRole{
		Name:        "..",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	target := metadata.Targets(simulator.Sim.SafeExpiry)
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)
	simulator.Sim.UpdateSnapshot()

	// First client fetches the delegated metadata and caches it locally.
	cfg, err := loadUpdaterConfig()
	assert.NoError(t, err)
	up1 := initUpdater(cfg)
	assert.NoError(t, up1.Refresh())
	_, _ = up1.GetTargetInfo("anything")

	// A fresh client should read that cached metadata back instead of
	// refetching it from the remote.
	simulator.Sim.FetchTracker.Metadata = []simulator.FTMetadata{}
	cfg2, err := loadUpdaterConfig()
	assert.NoError(t, err)
	up2 := initUpdater(cfg2)
	assert.NoError(t, up2.Refresh())
	_, _ = up2.GetTargetInfo("anything")

	refetched := slices.ContainsFunc(simulator.Sim.FetchTracker.Metadata, func(m simulator.FTMetadata) bool {
		return m.Name == ".."
	})
	assert.False(t, refetched, "delegated role '..' should be read from the local cache, not refetched from outside LocalMetadataDir")
}
