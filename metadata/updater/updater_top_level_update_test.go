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
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/testutils/testutils"
)

func TestMain(m *testing.M) {
	err := loadOrResetTrustedRootMetadata()
	simulator.PastDateTime = time.Now().UTC().Truncate(24 * time.Hour).Add(-5 * 24 * time.Hour)

	if err != nil {
		simulator.RepositoryCleanup(simulator.MetadataDir)
		log.Fatalf("failed to load TrustedRootMetadata: %v\n", err)
	}

	defer simulator.RepositoryCleanup(simulator.MetadataDir)
	m.Run()
}

func loadOrResetTrustedRootMetadata() error {
	var err error

	simulator.Sim, simulator.MetadataDir, testutils.TargetsDir, err = simulator.InitMetadataDir()
	if err != nil {
		log.Printf("failed to initialize metadata dir: %v", err)
		return err
	}

	simulator.RootBytes, err = simulator.GetRootBytes(simulator.MetadataDir)
	if err != nil {
		log.Printf("failed to load root bytes: %v", err)
		return err
	}
	return nil
}

func loadUpdaterConfig() (*config.UpdaterConfig, error) {
	updaterConfig, err := config.New(simulator.MetadataDir, simulator.RootBytes)
	updaterConfig.Fetcher = simulator.Sim
	updaterConfig.LocalMetadataDir = simulator.MetadataDir
	updaterConfig.LocalTargetsDir = testutils.TargetsDir
	return updaterConfig, err
}

func loadUnsafeUpdaterConfig() (*config.UpdaterConfig, error) {
	updaterConfig, err := loadUpdaterConfig()
	if err != nil {
		return nil, err
	}
	updaterConfig.UnsafeLocalMode = true

	return updaterConfig, nil
}

// runRefresh creates new Updater instance and runs Refresh
func runRefresh(updaterConfig *config.UpdaterConfig, moveInTime time.Time) (Updater, error) {
	if len(simulator.Sim.DumpDir) > 0 {
		simulator.Sim.Write()
	}

	updater, err := New(updaterConfig)
	if err != nil {
		log.Debugf("failed to create new updater config: %v", err)
		return Updater{}, err
	}
	if moveInTime != time.Now() {
		updater.trusted.RefTime = moveInTime
	}
	err = updater.Refresh()
	return *updater, err
}

func initUpdater(updaterConfig *config.UpdaterConfig) *Updater {
	if len(simulator.Sim.DumpDir) > 0 {
		simulator.Sim.Write()
	}

	updater, err := New(updaterConfig)
	if err != nil {
		log.Debugf("failed to create new updater config: %v", err)
	}
	return updater
}

// Asserts that local metadata files exist for 'roles'
func assertFilesExist(t *testing.T, roles []string) {
	expectedFiles := []string{}

	for _, role := range roles {
		expectedFiles = append(expectedFiles, fmt.Sprintf("%s.json", role))
	}
	localMetadataFiles, err := os.ReadDir(simulator.MetadataDir)
	assert.NoError(t, err)

	actual := []string{}
	for _, file := range localMetadataFiles {
		actual = append(actual, file.Name())
	}

	for _, file := range expectedFiles {
		assert.Contains(t, actual, file)
	}
}

func assertFilesExact(t *testing.T, roles []string) {
	expectedFiles := []string{}

	for _, role := range roles {
		expectedFiles = append(expectedFiles, fmt.Sprintf("%s.json", role))
	}
	localMetadataFiles, err := os.ReadDir(simulator.MetadataDir)
	assert.NoError(t, err)

	actual := []string{}
	for _, file := range localMetadataFiles {
		actual = append(actual, file.Name())
	}

	assert.ElementsMatch(t, actual, expectedFiles)
}

// Asserts that local file content is the expected
func assertContentEquals(t *testing.T, role string, version *int) {
	expectedContent, err := simulator.Sim.FetchMetadata(role, version)
	assert.NoError(t, err)

	content, err := os.ReadFile(filepath.Join(simulator.MetadataDir, fmt.Sprintf("%s.json", role)))
	assert.NoError(t, err)
	assert.Equal(t, string(expectedContent), string(content))
}

func assertVersionEquals(t *testing.T, role string, expectedVersion int64) {
	path := filepath.Join(simulator.MetadataDir, fmt.Sprintf("%s.json", role))
	switch role {
	case metadata.ROOT:
		md, err := simulator.Sim.MDRoot.FromFile(path)
		assert.NoError(t, err)
		assert.Equal(t, md.Signed.Version, expectedVersion)
	case metadata.TARGETS:
		md, err := simulator.Sim.MDTargets.FromFile(path)
		assert.NoError(t, err)
		assert.Equal(t, md.Signed.Version, expectedVersion)
	case metadata.TIMESTAMP:
		md, err := simulator.Sim.MDTimestamp.FromFile(path)
		assert.NoError(t, err)
		assert.Equal(t, md.Signed.Version, expectedVersion)
	case metadata.SNAPSHOT:
		md, err := simulator.Sim.MDSnapshot.FromFile(path)
		assert.NoError(t, err)
		assert.Equal(t, md.Signed.Version, expectedVersion)
	}
}

func TestLoadTrustedRootMetadata(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater, err := New(updaterConfig)
	assert.NoError(t, err)

	assert.Nil(t, err)
	if assert.NotNil(t, updater) {
		assert.Equal(t, metadata.ROOT, updater.trusted.Root.Signed.Type)
		assert.Equal(t, metadata.SPECIFICATION_VERSION, updater.trusted.Root.Signed.SpecVersion)
		assert.True(t, updater.trusted.Root.Signed.ConsistentSnapshot)
		assert.Equal(t, int64(1), updater.trusted.Root.Signed.Version)
		assert.Nil(t, updater.trusted.Snapshot)
		assert.Nil(t, updater.trusted.Timestamp)
		assert.Empty(t, updater.trusted.Targets)
	}
}

func TestUnsafeLoadTrustedRootMetadata(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	updaterConfig, err := loadUnsafeUpdaterConfig()
	assert.NoError(t, err)
	updater, err := New(updaterConfig)
	assert.NoError(t, err)

	assert.Nil(t, err)
	if assert.NotNil(t, updater) {
		assert.Equal(t, metadata.ROOT, updater.trusted.Root.Signed.Type)
		assert.Equal(t, metadata.SPECIFICATION_VERSION, updater.trusted.Root.Signed.SpecVersion)
		assert.True(t, updater.trusted.Root.Signed.ConsistentSnapshot)
		assert.Equal(t, int64(1), updater.trusted.Root.Signed.Version)
		assert.Nil(t, updater.trusted.Snapshot)
		assert.Nil(t, updater.trusted.Timestamp)
		assert.Empty(t, updater.trusted.Targets)
	}
}

func TestFirstTimeRefresh(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	assertFilesExist(t, []string{metadata.ROOT})
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])

	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		var version int
		if role == metadata.ROOT {
			version = 2
		}
		assertContentEquals(t, role, &version)
	}
}

func TestFirstUnsafeTimeRefresh(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	assertFilesExist(t, []string{metadata.ROOT})
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUnsafeUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.Error(t, err)
	// As no update was made only the root file should be present
	assertFilesExact(t, []string{metadata.ROOT})
}

func TestUnsafeRefresh(t *testing.T) {
	// First run a "real" refresh
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	assertFilesExist(t, []string{metadata.ROOT})
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])

	// Create a new unsafe updater, verify content is still valid
	updaterConfig, err = loadUnsafeUpdaterConfig()
	assert.NoError(t, err)
	updater, err := runRefresh(updaterConfig, time.Now())
	assert.NotNil(t, updater)
	assert.NoError(t, err)
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])

	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		var version int
		if role == metadata.ROOT {
			// The root file is written when the updater is
			// created, so the version is reset.
			version = 1
		}
		assertContentEquals(t, role, &version)
	}

	assert.Equal(t, metadata.ROOT, updater.trusted.Root.Signed.Type)
	assert.Equal(t, metadata.SPECIFICATION_VERSION, updater.trusted.Root.Signed.SpecVersion)
	assert.True(t, updater.trusted.Root.Signed.ConsistentSnapshot)
	assert.Equal(t, int64(1), updater.trusted.Root.Signed.Version)
	assert.NotNil(t, updater.trusted.Snapshot)
	assert.NotNil(t, updater.trusted.Timestamp)
	assert.Equal(t, 1, len(updater.trusted.Targets))
}

func TestTrustedRootMissing(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	localTrusedRoot := updaterConfig.LocalTrustedRoot
	updaterConfig.LocalTrustedRoot = []byte{}
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorContains(t, err, "no initial trusted root metadata or remote URL provided")
	updaterConfig.LocalTrustedRoot = localTrusedRoot
}

func TestTrustedRootExpired(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	simulator.Sim.MDRoot.Signed.Expires = simulator.PastDateTime
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	err = updater.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "final root.json is expired"})

	assertFilesExist(t, []string{metadata.ROOT})
	version := 2
	assertContentEquals(t, metadata.ROOT, &version)

	updater = initUpdater(updaterConfig)

	simulator.Sim.MDRoot.Signed.Expires = simulator.Sim.SafeExpiry
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()
	err = updater.Refresh()
	assert.NoError(t, err)

	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])
	version = 3
	assertContentEquals(t, metadata.ROOT, &version)
}

func TestTrustedRootUnsigned(t *testing.T) {
	//  Local trusted root is not signed

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	rootPath := filepath.Join(simulator.MetadataDir, fmt.Sprintf("%s.json", metadata.ROOT))
	mdRoot, err := simulator.Sim.MDRoot.FromFile(rootPath)
	assert.NoError(t, err)

	mdRoot.ClearSignatures()
	err = mdRoot.ToFile(rootPath, true)
	assert.NoError(t, err)
	newRootBytes, err := os.ReadFile(rootPath)
	assert.NoError(t, err)
	simulator.RootBytes = newRootBytes

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 0, want 1"})

	assertFilesExist(t, []string{metadata.ROOT})
	mdRootAfter, err := simulator.Sim.MDRoot.FromFile(rootPath)
	assert.NoError(t, err)
	expected, err := mdRoot.ToBytes(false)
	assert.NoError(t, err)
	actual, err := mdRootAfter.ToBytes(false)
	assert.NoError(t, err)

	assert.Equal(t, expected, actual)
}

func TestMaxRootRotations(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	updater.cfg.MaxRootRotations = 3

	for simulator.Sim.MDRoot.Signed.Version < updater.cfg.MaxRootRotations+3 {
		simulator.Sim.MDRoot.Signed.Version += 1
		simulator.Sim.PublishRoot()
	}

	rootPath := filepath.Join(simulator.MetadataDir, fmt.Sprintf("%s.json", metadata.ROOT))
	mdRoot, err := simulator.Sim.MDRoot.FromFile(rootPath)
	assert.NoError(t, err)
	initialRootVersion := mdRoot.Signed.Version

	err = updater.Refresh()
	assert.NoError(t, err)

	assertVersionEquals(t, metadata.ROOT, initialRootVersion+updaterConfig.MaxRootRotations)
}

func TestIntermediateRootInclorrectlySigned(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	simulator.Sim.MDRoot.Signed.Version += 1
	rootSigners := make(map[string]*signature.Signer)
	for k, v := range simulator.Sim.Signers[metadata.ROOT] {
		rootSigners[k] = v
	}
	for k := range simulator.Sim.Signers[metadata.ROOT] {
		delete(simulator.Sim.Signers[metadata.ROOT], k)
	}
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 0, want 1"})

	assertFilesExist(t, []string{metadata.ROOT})
	version := 1
	assertContentEquals(t, metadata.ROOT, &version)
}

func TestIntermediateRootExpired(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// The expiration of the new (intermediate) root metadata file
	// does not matter yet

	// Intermediate root v2 is expired
	simulator.Sim.MDRoot.Signed.Expires = simulator.PastDateTime
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	// Final root v3 is up to date
	simulator.Sim.MDRoot.Signed.Expires = simulator.Sim.SafeExpiry
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	// Successfully updated to root v3
	assertFilesExist(t, metadata.TOP_LEVEL_ROLE_NAMES[:])
	version := 3
	assertContentEquals(t, metadata.ROOT, &version)
}

func TestNewRootSameVersion(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a rollback_attack
	// Repository serves a root file with the same version as previous
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "bad version number, expected 2, got 1"})

	// The update failed, latest root version is v1
	assertFilesExist(t, []string{metadata.ROOT})
	version := 1
	assertContentEquals(t, metadata.ROOT, &version)
}

func TestNewRootNonconsecutiveVersion(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Repository serves non-consecutive root version
	simulator.Sim.MDRoot.Signed.Version += 2
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "bad version number, expected 2, got 3"})

	// The update failed, latest root version is v1
	assertFilesExist(t, []string{metadata.ROOT})
	version := 1
	assertContentEquals(t, metadata.ROOT, &version)
}

func TestFinalRootExpired(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a freeze attack
	// Final root is expired
	simulator.Sim.MDRoot.Signed.Expires = simulator.PastDateTime
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "final root.json is expired"})

	// The update failed but final root is persisted on the file system
	assertFilesExist(t, []string{metadata.ROOT})
	version := 2
	assertContentEquals(t, metadata.ROOT, &version)
}

func TestNewTimestampUnsigned(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for an arbitrary software attack
	delete(simulator.Sim.Signers, metadata.TIMESTAMP)

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying timestamp failed, not enough signatures, got 0, want 1"})

	assertFilesExist(t, []string{metadata.ROOT})
}

func TestExpiredTimestampVersionRollback(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Verifies that local timestamp is used in rollback checks even if it is expired.
	// The timestamp updates and rollback checks are performed
	// with the following timing:
	//   - Timestamp v1 expiry set to day 7
	//   - First updater refresh performed on day 0
	//   - Repository publishes timestamp v2 on day 0
	//   - Timestamp v2 expiry set to day 21
	//   - Second updater refresh performed on day 18:
	//     assert that rollback check uses expired timestamp v1

	now := time.Now()
	simulator.Sim.MDTimestamp.Signed.Expires = now.Add(time.Hour * 7 * 24)
	simulator.Sim.MDTimestamp.Signed.Version = 2

	// Make a successful update of valid metadata which stores it in cache
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	simulator.Sim.MDTimestamp.Signed.Expires = now.Add(time.Hour * 21 * 24)
	simulator.Sim.MDTimestamp.Signed.Version = 1

	// Check that a rollback protection is performed even if
	// local timestamp has expired
	moveInTime := time.Now().Add(time.Hour * 18 * 24)
	_, err = runRefresh(updaterConfig, moveInTime)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 2"})
	assertVersionEquals(t, metadata.TIMESTAMP, 2)
}

func TestNewTimestampVersionRollback(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a rollback attack
	simulator.Sim.MDTimestamp.Signed.Version = 2
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	simulator.Sim.MDTimestamp.Signed.Version = 1
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 2"})
	assertVersionEquals(t, metadata.TIMESTAMP, 2)
}

func TestNewTimestampSnapshotRollback(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a rollback attack.
	simulator.Sim.MDSnapshot.Signed.Version = 2
	simulator.Sim.UpdateTimestamp() // timestamp v2
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	// Snapshot meta version is smaller than previous
	simulator.Sim.MDTimestamp.Signed.Meta["snapshot.json"].Version = 1
	simulator.Sim.MDTimestamp.Signed.Version += 1 // timestamp v3
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "new snapshot version 1 must be >= 2"})
	assertVersionEquals(t, metadata.TIMESTAMP, 2)
}

func TestNewTimestampExpired(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a freeze attack
	simulator.Sim.MDTimestamp.Signed.Expires = simulator.PastDateTime
	simulator.Sim.UpdateTimestamp()
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"})
	assertFilesExist(t, []string{metadata.ROOT})
}

func TestNewTimestampFastForwardRecovery(t *testing.T) {
	//Test timestamp fast-forward recovery using key rotation.

	// The timestamp recovery is made by the following steps
	//   - Remove the timestamp key
	//   - Create and add a new key for timestamp
	//   - Bump and publish root
	//   - Rollback the timestamp version

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// attacker updates to a higher version
	simulator.Sim.MDTimestamp.Signed.Version = 99999

	// client refreshes the metadata and see the new timestamp version
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertVersionEquals(t, metadata.TIMESTAMP, 99999)

	// repository rotates timestamp keys, rolls back timestamp version
	simulator.Sim.RotateKeys(metadata.TIMESTAMP)
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()
	simulator.Sim.MDTimestamp.Signed.Version = 1

	// client refresh the metadata and see the initial timestamp version
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertVersionEquals(t, metadata.TIMESTAMP, 1)
}

func TestNewSnapshotHashMismatch(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check against timestamp role’s snapshot hash

	// Update timestamp with snapshot's hashes
	simulator.Sim.ComputeMetafileHashesAndLength = true
	simulator.Sim.UpdateTimestamp() // timestamp v2
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	// Modify snapshot contents without updating
	// timestamp's snapshot hash
	simulator.Sim.MDSnapshot.Signed.Expires = simulator.Sim.MDSnapshot.Signed.Expires.Add(time.Hour * 24)
	simulator.Sim.MDSnapshot.Signed.Version += 1 // snapshot v2
	simulator.Sim.MDTimestamp.Signed.Meta["snapshot.json"].Version = simulator.Sim.MDSnapshot.Signed.Version
	simulator.Sim.MDTimestamp.Signed.Version += 1 // timestamp v3

	// Hash mismatch error
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrLengthOrHashMismatch{Msg: "hash verification failed - mismatch for algorithm sha256"})
	assertVersionEquals(t, metadata.TIMESTAMP, 3)
	assertVersionEquals(t, metadata.SNAPSHOT, 1)
}

func TestNewSnapshotUnsigned(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for an arbitrary software attack
	delete(simulator.Sim.Signers, metadata.SNAPSHOT)
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying snapshot failed, not enough signatures, got 0, want 1"})

	assertFilesExist(t, []string{metadata.ROOT, metadata.TIMESTAMP})
}

func TestNewSnapshotVersionMismatch(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check against timestamp role’s snapshot version

	// Increase snapshot version without updating timestamp
	simulator.Sim.MDSnapshot.Signed.Version += 1

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "expected 1, got 2"})

	assertFilesExist(t, []string{metadata.ROOT, metadata.TIMESTAMP})
}

func TestNewSnapshotVersionRollback(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a rollback attack
	simulator.Sim.MDSnapshot.Signed.Version = 2
	simulator.Sim.UpdateTimestamp()
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	simulator.Sim.MDSnapshot.Signed.Version = 1
	simulator.Sim.UpdateTimestamp()
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "new snapshot version 1 must be >= 2"})

	assertVersionEquals(t, metadata.SNAPSHOT, 2)
}

func TestNewSnapshotFastForwardRecovery(t *testing.T) {
	// Test snapshot fast-forward recovery using key rotation.

	// The snapshot recovery requires the snapshot and timestamp key rotation.
	// It is made by the following steps:
	// - Remove the snapshot and timestamp keys
	// - Create and add a new key for snapshot and timestamp
	// - Rollback snapshot version
	// - Bump and publish root
	// - Bump the timestamp

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// attacker updates to a higher version (bumping timestamp is required)
	simulator.Sim.MDSnapshot.Signed.Version = 99999
	simulator.Sim.UpdateTimestamp()

	// client refreshes the metadata and see the new snapshot version
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertVersionEquals(t, metadata.SNAPSHOT, 99999)

	// repository rotates snapshot & timestamp keys, rolls back snapshot
	simulator.Sim.RotateKeys(metadata.SNAPSHOT)
	simulator.Sim.RotateKeys(metadata.TIMESTAMP)
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	simulator.Sim.MDSnapshot.Signed.Version = 1
	simulator.Sim.UpdateTimestamp()

	// client refresh the metadata and see the initial snapshot version
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertVersionEquals(t, metadata.SNAPSHOT, 1)
}

func TestNewSnapshotExpired(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a freeze attack
	simulator.Sim.MDSnapshot.Signed.Expires = simulator.PastDateTime
	simulator.Sim.UpdateSnapshot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "snapshot.json is expired"})

	assertFilesExist(t, []string{metadata.ROOT})
}

func TestNewTargetsHashMismatch(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check against snapshot role’s targets hashes
	simulator.Sim.ComputeMetafileHashesAndLength = true
	simulator.Sim.UpdateSnapshot()
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	// Modify targets contents without updating
	// snapshot's targets hashes
	simulator.Sim.MDTargets.Signed.Version += 1
	simulator.Sim.MDSnapshot.Signed.Meta["targets.json"].Version = simulator.Sim.MDTargets.Signed.Version
	simulator.Sim.MDSnapshot.Signed.Version += 1
	simulator.Sim.UpdateTimestamp()

	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrLengthOrHashMismatch{Msg: "hash verification failed - mismatch for algorithm sha256"})

	assertVersionEquals(t, metadata.SNAPSHOT, 3)
	assertVersionEquals(t, metadata.TARGETS, 1)
}

func TestNewTargetsUnsigned(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for an arbitrary software attack
	delete(simulator.Sim.Signers, metadata.TARGETS)

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying targets failed, not enough signatures, got 0, want 1"})

	assertFilesExist(t, []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT})
}

func TestNewTargetsVersionMismatch(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check against snapshot role’s targets version

	// Increase targets version without updating snapshot
	simulator.Sim.MDTargets.Signed.Version += 1
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "expected targets version 1, got 2"})

	assertFilesExist(t, []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT})
}

func TestNewTargetsExpired(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Check for a freeze attack.
	simulator.Sim.MDTargets.Signed.Expires = simulator.PastDateTime
	simulator.Sim.UpdateSnapshot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "new targets is expired"})

	assertFilesExist(t, []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT})
}

func TestComputeMetafileHashesLength(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	simulator.Sim.ComputeMetafileHashesAndLength = true
	simulator.Sim.UpdateSnapshot()
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	assertVersionEquals(t, metadata.TIMESTAMP, 2)
	assertVersionEquals(t, metadata.SNAPSHOT, 2)

	simulator.Sim.ComputeMetafileHashesAndLength = false
	simulator.Sim.UpdateSnapshot()
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	assertVersionEquals(t, metadata.TIMESTAMP, 3)
	assertVersionEquals(t, metadata.SNAPSHOT, 3)
}

func TestNewTargetsFastForwardRecovery(t *testing.T) {
	//Test targets fast-forward recovery using key rotation.

	// The targets recovery is made by issuing new Snapshot keys, by following
	// steps:
	// 	- Remove the snapshot key
	// 	- Create and add a new key for snapshot
	// 	- Bump and publish root
	// 	- Rollback the target version

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// attacker updates to a higher version
	simulator.Sim.MDTargets.Signed.Version = 99999
	simulator.Sim.UpdateSnapshot()

	// client refreshes the metadata and see the new targets version
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertVersionEquals(t, metadata.TARGETS, 99999)

	// repository rotates snapshot keys, rolls back targets version
	simulator.Sim.RotateKeys(metadata.SNAPSHOT)
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	simulator.Sim.MDTargets.Signed.Version = 1
	simulator.Sim.UpdateSnapshot()

	// client refreshes the metadata version and see initial targets version
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)
	assertVersionEquals(t, metadata.TARGETS, 1)
}

func TestSnapshotRollbackWithLocalSnapshotHashMismatch(t *testing.T) {
	// Test triggering snapshot rollback check on a newly downloaded snapshot
	// when the local snapshot is loaded even when there is a hash mismatch
	// with timestamp.snapshot_meta.

	// By raising this flag on timestamp update the simulator would:
	// 1) compute the hash of the new modified version of snapshot
	// 2) assign the hash to timestamp.snapshot_meta
	// The purpose is to create a hash mismatch between timestamp.meta and
	// the local snapshot, but to have hash match between timestamp.meta and
	// the next snapshot version.

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	simulator.Sim.ComputeMetafileHashesAndLength = true

	// Initialize all metadata and assign targets version higher than 1.
	simulator.Sim.MDTargets.Signed.Version = 2
	simulator.Sim.UpdateSnapshot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	// The new targets must have a lower version than the local trusted one.
	simulator.Sim.MDTargets.Signed.Version = 1
	simulator.Sim.UpdateSnapshot()

	// During the snapshot update, the local snapshot will be loaded even if
	// there is a hash mismatch with timestamp snapshot meta, because it will
	// be considered as trusted.
	// Should fail as a new version of snapshot will be fetched which lowers
	// the snapshot meta "targets.json" version by 1 and throws an error.
	_, err = runRefresh(updaterConfig, time.Now())
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "expected targets.json version 1, got 2"})
}

func TestExpiredMetadata(t *testing.T) {
	// Verifies that expired local timestamp/snapshot can be used for
	// updating from remote.

	// The updates and verifications are performed with the following timing:
	//   - Timestamp v1 expiry set to day 7
	//   - First updater refresh performed on day 0
	//   - Repository bumps snapshot and targets to v2 on day 0
	//   - Timestamp v2 expiry set to day 21
	//   - Second updater refresh performed on day 18,
	//     it is successful and timestamp/snaphot final versions are v2"

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	now := time.Now()
	simulator.Sim.MDTimestamp.Signed.Expires = now.Add(time.Hour * 7 * 24)

	// Make a successful update of valid metadata which stores it in cache
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	simulator.Sim.MDTargets.Signed.Version += 1
	simulator.Sim.UpdateSnapshot()
	simulator.Sim.MDTimestamp.Signed.Expires = now.Add(time.Hour * 21 * 24)

	// Mocking time so that local timestam has expired
	// but the new timestamp has not
	moveInTime := now.Add(time.Hour * 18 * 24)
	_, err = runRefresh(updaterConfig, moveInTime)
	assert.NoError(t, err)

	// Assert that the final version of timestamp/snapshot is version 2
	// which means a successful refresh is performed
	// with expired local metadata

	mdTimestamp, err := metadata.Timestamp().FromFile(filepath.Join(simulator.MetadataDir, "timestamp.json"))
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mdTimestamp.Signed.Version)

	mdSnapshot, err := metadata.Snapshot().FromFile(filepath.Join(simulator.MetadataDir, "snapshot.json"))
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mdSnapshot.Signed.Version)

	mdTargets, err := metadata.Targets().FromFile(filepath.Join(simulator.MetadataDir, "targets.json"))
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mdTargets.Signed.Version)
}

func TestMaxMetadataLengths(t *testing.T) {
	// Test that clients configured max metadata lengths are respected

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// client has root v1 already: create a new one available for download
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	// make sure going over any length limit raises DownloadLengthMismatchError
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updater := initUpdater(updaterConfig)
	updater.cfg.RootMaxLength = 100
	err = updater.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrDownloadLengthMismatch{Msg: "Downloaded 1567 bytes exceeding the maximum allowed length of 100"})

	updater = initUpdater(updaterConfig)
	updater.cfg.TimestampMaxLength = 100
	err = updater.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrDownloadLengthMismatch{Msg: "Downloaded 1567 bytes exceeding the maximum allowed length of 100"})

	updater = initUpdater(updaterConfig)
	updater.cfg.SnapshotMaxLength = 100
	err = updater.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrDownloadLengthMismatch{Msg: "Downloaded 1567 bytes exceeding the maximum allowed length of 100"})

	updater = initUpdater(updaterConfig)
	updater.cfg.TargetsMaxLength = 100
	err = updater.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrDownloadLengthMismatch{Msg: "Downloaded 1567 bytes exceeding the maximum allowed length of 100"})

	// All good with normal length limits
	updater = initUpdater(updaterConfig)
	err = updater.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrDownloadLengthMismatch{Msg: "Downloaded 1567 bytes exceeding the maximum allowed length of 100"})
}

func TestTimestampEqVersionsCheck(t *testing.T) {
	// Test that a modified timestamp with different content, but the same
	// version doesn't replace the valid locally stored one.

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)

	// Make a successful update of valid metadata which stores it in cache
	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	initialTimestampMetadataVer := simulator.Sim.MDTimestamp.Signed.Meta["snapshot.json"].Version
	// Change timestamp without bumping its version in order to test if a new
	// timestamp with the same version will be persisted.
	simulator.Sim.MDTimestamp.Signed.Meta["snapshot.json"].Version = 100
	_, err = runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	// If the local timestamp md file has the same snapshot_meta.version as
	// the initial one, then the new modified timestamp has not been stored.
	timestamp, err := metadata.Timestamp().FromFile(simulator.MetadataDir + "/timestamp.json")
	assert.NoError(t, err)
	assert.Equal(t, initialTimestampMetadataVer, timestamp.Signed.Meta["snapshot.json"].Version)
}
