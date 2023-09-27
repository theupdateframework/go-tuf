// Copyright 2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

package updater

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	simulator "github.com/rdimitrov/go-tuf-metadata/testutils/simulator"
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
	assert.EqualValues(t, expectedsnapshotEnabled, simulator.Sim.FetchTracker.Metadata)
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
