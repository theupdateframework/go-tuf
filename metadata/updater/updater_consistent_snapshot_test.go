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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestTopLevelRolesUpdateWithConsistentSnapshotDisabled(t *testing.T) {
	// Test if the client fetches and stores metadata files with the
	// correct version prefix when ConsistentSnapshot is false

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = false
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	// cleanup fetch tracker metadata
	simulator.Sim.FetchTracker.Metadata = []simulator.FTMetadata{}
	err = updater.Refresh()
	if err != nil {
		t.Fatal(err)
	}
	assert.NoError(t, err)

	// metadata files are fetched with the expected version (or None)
	expectedsnapshotEnabled := []simulator.FTMetadata{
		{Name: "root", Value: 2},
		{Name: "root", Value: 3},
		{Name: "timestamp", Value: -1},
		{Name: "snapshot", Value: -1},
		{Name: "targets", Value: -1},
	}
	assert.EqualValues(t, expectedsnapshotEnabled, simulator.Sim.FetchTracker.Metadata)
	// metadata files are always persisted without a version prefix
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])
}

func TestTopLevelRolesUpdateWithConsistentSnapshotEnabled(t *testing.T) {
	// Test if the client fetches and stores metadata files with the
	// correct version prefix when ConsistentSnapshot is true

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = true
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	if updater == nil {
		t.Fatal("updater is nil")
	}
	// cleanup fetch tracker metadata
	simulator.Sim.FetchTracker.Metadata = []simulator.FTMetadata{}
	err = updater.Refresh()
	assert.NoError(t, err)

	// metadata files are fetched with the expected version (or None)
	expectedSnapshotDisabled := []simulator.FTMetadata{
		{Name: "root", Value: 2},
		{Name: "root", Value: 3},
		{Name: "timestamp", Value: -1},
		{Name: "snapshot", Value: 1},
		{Name: "targets", Value: 1},
	}
	assert.EqualValues(t, expectedSnapshotDisabled, simulator.Sim.FetchTracker.Metadata)
	// metadata files are always persisted without a version prefix
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])
}

func TestDelegatesRolesUpdateWithConsistentSnapshotDisabled(t *testing.T) {
	// Test if the client fetches and stores delegated metadata files with
	// the correct version prefix when ConsistentSnapshot is false

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = false
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	target := metadata.Targets(simulator.Sim.SafeExpiry)

	delegatedRole := metadata.DelegatedRole{
		Name:        "role1",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)

	delegatedRole = metadata.DelegatedRole{
		Name:        "..",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)

	delegatedRole = metadata.DelegatedRole{
		Name:        ".",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)

	simulator.Sim.UpdateSnapshot()
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	if updater == nil {
		t.Fatal("updater is nil")
	}
	err = updater.Refresh()
	assert.NoError(t, err)

	// cleanup fetch tracker metadata
	simulator.Sim.FetchTracker.Metadata = []simulator.FTMetadata{}
	// trigger updater to fetch the delegated metadata
	_, err = updater.GetTargetInfo("anything")
	assert.ErrorContains(t, err, "target anything not found")

	// metadata files are fetched with the expected version (or None)
	expectedsnapshotEnabled := []simulator.FTMetadata{
		{Name: "role1", Value: -1},
		{Name: "..", Value: -1},
		{Name: ".", Value: -1},
	}
	assert.ElementsMatch(t, expectedsnapshotEnabled, simulator.Sim.FetchTracker.Metadata)
	// metadata files are always persisted without a version prefix
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])
}

func TestDelegatesRolesUpdateWithConsistentSnapshotEnabled(t *testing.T) {
	// Test if the client fetches and stores delegated metadata files with
	// the correct version prefix when ConsistentSnapshot is true

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = true
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	target := metadata.Targets(simulator.Sim.SafeExpiry)

	delegatedRole := metadata.DelegatedRole{
		Name:        "role1",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)

	delegatedRole = metadata.DelegatedRole{
		Name:        "..",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)

	delegatedRole = metadata.DelegatedRole{
		Name:        ".",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"*"},
	}
	simulator.Sim.AddDelegation("targets", delegatedRole, target.Signed)

	simulator.Sim.UpdateSnapshot()
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	if updater == nil {
		t.Fatal("updater is nil")
	}
	err = updater.Refresh()
	assert.NoError(t, err)

	// cleanup fetch tracker metadata
	simulator.Sim.FetchTracker.Metadata = []simulator.FTMetadata{}
	// trigger updater to fetch the delegated metadata
	_, err = updater.GetTargetInfo("anything")
	assert.ErrorContains(t, err, "target anything not found")

	// metadata files are fetched with the expected version (or None)
	expectedsnapshotEnabled := []simulator.FTMetadata{
		{Name: "role1", Value: 1},
		{Name: "..", Value: 1},
		{Name: ".", Value: 1},
	}
	assert.ElementsMatch(t, expectedsnapshotEnabled, simulator.Sim.FetchTracker.Metadata)
	// metadata files are always persisted without a version prefix
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])
}
