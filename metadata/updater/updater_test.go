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
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
)

// skipIfWindows guards the target-download tables -- the simulator's URL
// routing for target files uses filepath.Separator, which is "\" on
// Windows; that combined with hardcoded "/targets/" prefix checks makes
// the routing unreachable from these tests. The underlying code under
// test still gets coverage from Linux and macOS runners.
func skipIfWindows(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("simulator target URL routing is broken on windows; see metadata/updater/updater_test.go")
	}
}

// createAndRefresh creates an updater for the test repository and runs Refresh
func createAndRefresh(t *testing.T, repo *simulator.TestRepository) (*Updater, error) {
	t.Helper()
	cfg, err := repo.GetUpdaterConfig()
	if err != nil {
		return nil, err
	}
	up, err := New(cfg)
	if err != nil {
		return nil, err
	}
	return up, up.Refresh()
}

// TestRootUpdatesTable tests root metadata update scenarios using table-driven tests
func TestRootUpdatesTable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, repo *simulator.TestRepository)
		wantErr     bool
		wantErrType error
		wantErrMsg  string
		assert      func(t *testing.T, repo *simulator.TestRepository)
	}{
		{
			name: "first time refresh succeeds",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.BumpVersion(metadata.ROOT)
			},
			wantErr: false,
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist(metadata.TOP_LEVEL_ROLE_NAMES[:])
			},
		},
		{
			name: "trusted root expired fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.SetExpired(metadata.ROOT)
				repo.BumpVersion(metadata.ROOT)
			},
			wantErr:     true,
			wantErrType: &metadata.ErrExpiredMetadata{},
			wantErrMsg:  "final root.json is expired",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT})
			},
		},
		{
			name: "new root same version fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				// Publishing without bumping version causes same version error
				repo.PublishRoot()
			},
			wantErr:     true,
			wantErrType: &metadata.ErrBadVersionNumber{},
			wantErrMsg:  "bad version number, expected 2, got 1",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT})
			},
		},
		{
			name: "new root non-consecutive version fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.Simulator.MDRoot.Signed.Version += 2
				repo.PublishRoot()
			},
			wantErr:     true,
			wantErrType: &metadata.ErrBadVersionNumber{},
			wantErrMsg:  "bad version number, expected 2, got 3",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT})
			},
		},
		{
			name: "intermediate root expired succeeds if final is valid",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				// Intermediate root v2 is expired
				repo.SetExpired(metadata.ROOT)
				repo.BumpVersion(metadata.ROOT)
				// Final root v3 is up to date
				repo.Simulator.MDRoot.Signed.Expires = repo.Simulator.SafeExpiry
				repo.BumpVersion(metadata.ROOT)
			},
			wantErr: false,
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist(metadata.TOP_LEVEL_ROLE_NAMES[:])
				repo.AssertVersionEquals(metadata.ROOT, 3)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Create fresh test repository
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			// Run setup
			if tc.setup != nil {
				tc.setup(t, repo)
			}

			// Run refresh
			_, err := createAndRefresh(t, repo)

			// Check error expectations
			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrType != nil {
					assert.ErrorIs(t, err, tc.wantErrType)
				}
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			// Run additional assertions
			if tc.assert != nil {
				tc.assert(t, repo)
			}
		})
	}
}

// TestTimestampUpdatesTable tests timestamp metadata update scenarios
func TestTimestampUpdatesTable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, repo *simulator.TestRepository)
		wantErr     bool
		wantErrType error
		wantErrMsg  string
		assert      func(t *testing.T, repo *simulator.TestRepository)
	}{
		{
			name: "new timestamp unsigned fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.RemoveSigners(metadata.TIMESTAMP)
			},
			wantErr:     true,
			wantErrType: &metadata.ErrUnsignedMetadata{},
			wantErrMsg:  "Verifying timestamp failed, not enough signatures, got 0, want 1",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT})
			},
		},
		{
			name: "new timestamp expired fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.SetExpired(metadata.TIMESTAMP)
				repo.UpdateTimestamp()
			},
			wantErr:     true,
			wantErrType: &metadata.ErrExpiredMetadata{},
			wantErrMsg:  "timestamp.json is expired",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			if tc.setup != nil {
				tc.setup(t, repo)
			}

			_, err := createAndRefresh(t, repo)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrType != nil {
					assert.ErrorIs(t, err, tc.wantErrType)
				}
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			if tc.assert != nil {
				tc.assert(t, repo)
			}
		})
	}
}

// TestSnapshotUpdatesTable tests snapshot metadata update scenarios
func TestSnapshotUpdatesTable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, repo *simulator.TestRepository)
		wantErr     bool
		wantErrType error
		wantErrMsg  string
		assert      func(t *testing.T, repo *simulator.TestRepository)
	}{
		{
			name: "new snapshot unsigned fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.RemoveSigners(metadata.SNAPSHOT)
			},
			wantErr:     true,
			wantErrType: &metadata.ErrUnsignedMetadata{},
			wantErrMsg:  "Verifying snapshot failed, not enough signatures, got 0, want 1",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT, metadata.TIMESTAMP})
			},
		},
		{
			name: "new snapshot expired fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.SetExpired(metadata.SNAPSHOT)
				repo.UpdateSnapshot()
			},
			wantErr:     true,
			wantErrType: &metadata.ErrExpiredMetadata{},
			wantErrMsg:  "snapshot.json is expired",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT})
			},
		},
		{
			name: "new snapshot version mismatch fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				// Increase snapshot version without updating timestamp
				repo.Simulator.MDSnapshot.Signed.Version++
			},
			wantErr:     true,
			wantErrType: &metadata.ErrBadVersionNumber{},
			wantErrMsg:  "expected 1, got 2",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT, metadata.TIMESTAMP})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			if tc.setup != nil {
				tc.setup(t, repo)
			}

			_, err := createAndRefresh(t, repo)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrType != nil {
					assert.ErrorIs(t, err, tc.wantErrType)
				}
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			if tc.assert != nil {
				tc.assert(t, repo)
			}
		})
	}
}

// TestTargetsUpdatesTable tests targets metadata update scenarios
func TestTargetsUpdatesTable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, repo *simulator.TestRepository)
		wantErr     bool
		wantErrType error
		wantErrMsg  string
		assert      func(t *testing.T, repo *simulator.TestRepository)
	}{
		{
			name: "new targets unsigned fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.RemoveSigners(metadata.TARGETS)
			},
			wantErr:     true,
			wantErrType: &metadata.ErrUnsignedMetadata{},
			wantErrMsg:  "Verifying targets failed, not enough signatures, got 0, want 1",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT})
			},
		},
		{
			name: "new targets expired fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				repo.SetExpired(metadata.TARGETS)
				repo.UpdateSnapshot()
			},
			wantErr:     true,
			wantErrType: &metadata.ErrExpiredMetadata{},
			wantErrMsg:  "new targets is expired",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT})
			},
		},
		{
			name: "new targets version mismatch fails",
			setup: func(t *testing.T, repo *simulator.TestRepository) {
				// Increase targets version without updating snapshot
				repo.Simulator.MDTargets.Signed.Version++
			},
			wantErr:     true,
			wantErrType: &metadata.ErrBadVersionNumber{},
			wantErrMsg:  "expected targets version 1, got 2",
			assert: func(t *testing.T, repo *simulator.TestRepository) {
				repo.AssertFilesExist([]string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT})
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			if tc.setup != nil {
				tc.setup(t, repo)
			}

			_, err := createAndRefresh(t, repo)

			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrType != nil {
					assert.ErrorIs(t, err, tc.wantErrType)
				}
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
			} else {
				assert.NoError(t, err)
			}

			if tc.assert != nil {
				tc.assert(t, repo)
			}
		})
	}
}

// TestTimestampFastForwardRecovery tests timestamp fast-forward attack recovery
func TestTimestampFastForwardRecovery(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	// Attacker updates timestamp to a higher version
	repo.Simulator.MDTimestamp.Signed.Version = 99999

	// Client refreshes and sees new version
	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.TIMESTAMP, 99999)

	// Repository rotates timestamp keys
	repo.RotateKeys(metadata.TIMESTAMP)
	repo.BumpVersion(metadata.ROOT)

	// Roll back timestamp version
	repo.Simulator.MDTimestamp.Signed.Version = 1

	// Client refreshes and sees initial version
	_, err = createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.TIMESTAMP, 1)
}

// TestSnapshotFastForwardRecovery tests snapshot fast-forward attack recovery
func TestSnapshotFastForwardRecovery(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	// Attacker updates snapshot to a higher version (bumping timestamp is required)
	repo.Simulator.MDSnapshot.Signed.Version = 99999
	repo.UpdateTimestamp()

	// Client refreshes and sees new version
	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.SNAPSHOT, 99999)

	// Repository rotates snapshot & timestamp keys
	repo.RotateKeys(metadata.SNAPSHOT)
	repo.RotateKeys(metadata.TIMESTAMP)
	repo.BumpVersion(metadata.ROOT)

	// Roll back snapshot version
	repo.Simulator.MDSnapshot.Signed.Version = 1
	repo.UpdateTimestamp()

	// Client refreshes and sees initial version
	_, err = createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.SNAPSHOT, 1)
}

// TestTargetsFastForwardRecovery tests targets fast-forward attack recovery
func TestTargetsFastForwardRecovery(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	// Attacker updates targets to a higher version
	repo.Simulator.MDTargets.Signed.Version = 99999
	repo.UpdateSnapshot()

	// Client refreshes and sees new version
	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.TARGETS, 99999)

	// Repository rotates snapshot keys (which resets targets tracking)
	repo.RotateKeys(metadata.SNAPSHOT)
	repo.BumpVersion(metadata.ROOT)

	// Roll back targets version
	repo.Simulator.MDTargets.Signed.Version = 1
	repo.UpdateSnapshot()

	// Client refreshes and sees initial version
	_, err = createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.TARGETS, 1)
}

// TestVersionRollbackTable tests version rollback attack detection
func TestVersionRollbackTable(t *testing.T) {
	tests := []struct {
		name string
		role string
	}{
		{
			name: "timestamp version rollback fails",
			role: metadata.TIMESTAMP,
		},
		{
			name: "snapshot version rollback fails",
			role: metadata.SNAPSHOT,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			// Set initial higher version
			repo.SetVersion(tc.role, 2)
			repo.UpdateSnapshot()

			// First refresh succeeds
			_, err := createAndRefresh(t, repo)
			assert.NoError(t, err)

			// Now try to rollback
			repo.SetVersion(tc.role, 1)
			repo.UpdateSnapshot()

			// Second refresh should fail with rollback detection
			_, err = createAndRefresh(t, repo)
			assert.Error(t, err)
			assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{})
			// Error message will contain "must be >= X" where X is the previously seen version
			assert.ErrorContains(t, err, "must be >=")
		})
	}
}

// TestConsistentSnapshotTable tests consistent snapshot behavior
func TestConsistentSnapshotTable(t *testing.T) {
	tests := []struct {
		name               string
		consistentSnapshot bool
		expectedMetadata   []simulator.FTMetadata
	}{
		{
			name:               "consistent snapshot disabled",
			consistentSnapshot: false,
			expectedMetadata: []simulator.FTMetadata{
				{Name: "root", Value: 2},
				{Name: "root", Value: 3},
				{Name: "timestamp", Value: -1},
				{Name: "snapshot", Value: -1},
				{Name: "targets", Value: -1},
			},
		},
		{
			name:               "consistent snapshot enabled",
			consistentSnapshot: true,
			expectedMetadata: []simulator.FTMetadata{
				{Name: "root", Value: 2},
				{Name: "root", Value: 3},
				{Name: "timestamp", Value: -1},
				{Name: "snapshot", Value: 1},
				{Name: "targets", Value: 1},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			repo.Simulator.MDRoot.Signed.ConsistentSnapshot = tc.consistentSnapshot
			repo.BumpVersion(metadata.ROOT)

			// Get updater config and create updater manually to track fetch
			cfg, err := repo.GetUpdaterConfig()
			assert.NoError(t, err)

			updater, err := New(cfg)
			assert.NoError(t, err)

			// Clear fetch tracker
			repo.Simulator.FetchTracker.Metadata = []simulator.FTMetadata{}

			err = updater.Refresh()
			assert.NoError(t, err)

			// Verify metadata was fetched with expected versions
			assert.EqualValues(t, tc.expectedMetadata, repo.Simulator.FetchTracker.Metadata)
			repo.AssertFilesExist(metadata.TOP_LEVEL_ROLE_NAMES[:])
		})
	}
}

// TestHashMismatchTable tests hash mismatch detection scenarios
func TestHashMismatchTable(t *testing.T) {
	tests := []struct {
		name        string
		role        string
		wantErrType error
		wantErrMsg  string
	}{
		{
			name:        "snapshot hash mismatch",
			role:        metadata.SNAPSHOT,
			wantErrType: &metadata.ErrLengthOrHashMismatch{},
			wantErrMsg:  "hash verification failed - mismatch for algorithm sha256",
		},
		{
			name:        "targets hash mismatch",
			role:        metadata.TARGETS,
			wantErrType: &metadata.ErrLengthOrHashMismatch{},
			wantErrMsg:  "hash verification failed - mismatch for algorithm sha256",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			// Enable hash computation and do initial update
			repo.EnableComputeHashesAndLength()
			repo.UpdateSnapshot()

			// First refresh succeeds
			_, err := createAndRefresh(t, repo)
			assert.NoError(t, err)

			// Modify metadata without updating hashes
			switch tc.role {
			case metadata.SNAPSHOT:
				repo.Simulator.MDSnapshot.Signed.Expires = repo.Simulator.MDSnapshot.Signed.Expires.Add(time.Hour * 24)
				repo.Simulator.MDSnapshot.Signed.Version++
				repo.Simulator.MDTimestamp.Signed.Meta["snapshot.json"].Version = repo.Simulator.MDSnapshot.Signed.Version
				repo.Simulator.MDTimestamp.Signed.Version++
			case metadata.TARGETS:
				repo.Simulator.MDTargets.Signed.Version++
				repo.Simulator.MDSnapshot.Signed.Meta["targets.json"].Version = repo.Simulator.MDTargets.Signed.Version
				repo.Simulator.MDSnapshot.Signed.Version++
				repo.UpdateTimestamp()
			}

			// Disable hash computation so hashes don't match
			repo.DisableComputeHashesAndLength()

			// Second refresh should fail with hash mismatch
			_, err = createAndRefresh(t, repo)
			assert.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErrType)
			assert.ErrorContains(t, err, tc.wantErrMsg)
		})
	}
}

// TestUpdaterConstructorTable exercises Updater construction itself
// (independently of Refresh): the unsafe variant, the trusted root
// missing case, and the initial trusted-set assertions.
func TestUpdaterConstructorTable(t *testing.T) {
	tests := []struct {
		name        string
		buildCfg    func(t *testing.T, repo *simulator.TestRepository) *config.UpdaterConfig
		wantErr     bool
		wantErrMsg  string
		assertTrust func(t *testing.T, up *Updater)
	}{
		{
			name: "constructor loads trusted root",
			buildCfg: func(t *testing.T, repo *simulator.TestRepository) *config.UpdaterConfig {
				t.Helper()
				cfg, err := repo.GetUpdaterConfig()
				assert.NoError(t, err)
				return cfg
			},
			assertTrust: func(t *testing.T, up *Updater) {
				t.Helper()
				ts := up.GetTrustedMetadataSet()
				assert.Equal(t, metadata.ROOT, ts.Root.Signed.Type)
				assert.Equal(t, metadata.SPECIFICATION_VERSION, ts.Root.Signed.SpecVersion)
				assert.True(t, ts.Root.Signed.ConsistentSnapshot)
				assert.Equal(t, int64(1), ts.Root.Signed.Version)
				assert.Nil(t, ts.Snapshot)
				assert.Nil(t, ts.Timestamp)
				assert.Empty(t, ts.Targets)
			},
		},
		{
			name: "unsafe constructor loads trusted root",
			buildCfg: func(t *testing.T, repo *simulator.TestRepository) *config.UpdaterConfig {
				t.Helper()
				cfg, err := repo.GetUnsafeUpdaterConfig()
				assert.NoError(t, err)
				return cfg
			},
			assertTrust: func(t *testing.T, up *Updater) {
				t.Helper()
				ts := up.GetTrustedMetadataSet()
				assert.Equal(t, metadata.ROOT, ts.Root.Signed.Type)
				assert.Equal(t, int64(1), ts.Root.Signed.Version)
				assert.True(t, ts.Root.Signed.ConsistentSnapshot)
				assert.Nil(t, ts.Snapshot)
				assert.Nil(t, ts.Timestamp)
				assert.Empty(t, ts.Targets)
			},
		},
		{
			name: "missing trusted root and remote URL fails construction",
			buildCfg: func(t *testing.T, repo *simulator.TestRepository) *config.UpdaterConfig {
				t.Helper()
				cfg, err := repo.GetUpdaterConfig()
				assert.NoError(t, err)
				cfg.LocalTrustedRoot = []byte{}
				cfg.RemoteMetadataURL = ""
				return cfg
			},
			wantErr:    true,
			wantErrMsg: "no initial trusted root metadata or remote URL provided",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			cfg := tc.buildCfg(t, repo)
			up, err := New(cfg)
			if tc.wantErr {
				assert.Error(t, err)
				if tc.wantErrMsg != "" {
					assert.ErrorContains(t, err, tc.wantErrMsg)
				}
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, up)
			if tc.assertTrust != nil {
				tc.assertTrust(t, up)
			}
		})
	}
}

// TestUnsafeRefreshTable covers refresh behaviour with UnsafeLocalMode:
// fresh state should fail (no remote fetches), but a previously-warmed
// cache should be loadable in unsafe mode.
func TestUnsafeRefreshTable(t *testing.T) {
	t.Run("fresh unsafe refresh fails -- no remote fetch performed", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		defer repo.Cleanup()

		repo.BumpVersion(metadata.ROOT)

		cfg, err := repo.GetUnsafeUpdaterConfig()
		assert.NoError(t, err)
		up, err := New(cfg)
		assert.NoError(t, err)

		err = up.Refresh()
		assert.Error(t, err)
		// Only the trusted root file should be present on disk.
		repo.AssertFilesExact([]string{metadata.ROOT})
	})

	t.Run("unsafe refresh loads cached metadata after a real refresh", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		defer repo.Cleanup()

		repo.BumpVersion(metadata.ROOT)

		// First, do a real refresh to populate the cache.
		_, err := createAndRefresh(t, repo)
		assert.NoError(t, err)
		repo.AssertFilesExist(metadata.TOP_LEVEL_ROLE_NAMES[:])

		// Now construct an unsafe updater pointing at the same dirs;
		// it should load the cached set without any new fetches.
		unsafeCfg, err := repo.GetUnsafeUpdaterConfig()
		assert.NoError(t, err)
		up, err := New(unsafeCfg)
		assert.NoError(t, err)
		err = up.Refresh()
		assert.NoError(t, err)

		ts := up.GetTrustedMetadataSet()
		assert.NotNil(t, ts.Snapshot)
		assert.NotNil(t, ts.Timestamp)
		assert.Equal(t, 1, len(ts.Targets))
	})
}

// TestTrustedRootUnsignedTable: if the locally-stored root.json has its
// signatures cleared, New must reject it via the standard threshold
// verification path.
func TestTrustedRootUnsignedTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	rootPath := filepath.Join(repo.MetadataDir, "root.json")
	mdRoot, err := repo.Simulator.MDRoot.FromFile(rootPath)
	assert.NoError(t, err)
	mdRoot.ClearSignatures()
	assert.NoError(t, mdRoot.ToFile(rootPath, true))
	assert.NoError(t, repo.ReloadRootBytes())

	_, err = createAndRefresh(t, repo)
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 0, want 1"})

	// The on-disk root must remain the unsigned one we just wrote.
	repo.AssertFilesExist([]string{metadata.ROOT})
	mdRootAfter, err := repo.Simulator.MDRoot.FromFile(rootPath)
	assert.NoError(t, err)
	expected, err := mdRoot.ToBytes(false)
	assert.NoError(t, err)
	actual, err := mdRootAfter.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

// TestIntermediateRootIncorrectlySignedTable: a published intermediate
// root that wasn't signed by the trusted root keys is rejected.
func TestIntermediateRootIncorrectlySignedTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	repo.Simulator.MDRoot.Signed.Version += 1
	// Drop all root signers so PublishRoot writes an unsigned root v2.
	for k := range repo.Simulator.Signers[metadata.ROOT] {
		delete(repo.Simulator.Signers[metadata.ROOT], k)
	}
	repo.PublishRoot()

	_, err := createAndRefresh(t, repo)
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 0, want 1"})
	repo.AssertFilesExist([]string{metadata.ROOT})
	repo.AssertVersionEquals(metadata.ROOT, 1)
}

// TestMaxRootRotationsTable: the client stops walking root versions
// once MaxRootRotations have been applied.
func TestMaxRootRotationsTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	cfg, err := repo.GetUpdaterConfig()
	assert.NoError(t, err)
	cfg.MaxRootRotations = 3
	up, err := New(cfg)
	assert.NoError(t, err)

	for repo.Simulator.MDRoot.Signed.Version < cfg.MaxRootRotations+3 {
		repo.BumpVersion(metadata.ROOT)
	}

	rootPath := filepath.Join(repo.MetadataDir, "root.json")
	mdRoot, err := repo.Simulator.MDRoot.FromFile(rootPath)
	assert.NoError(t, err)
	initialRootVersion := mdRoot.Signed.Version

	assert.NoError(t, up.Refresh())
	repo.AssertVersionEquals(metadata.ROOT, initialRootVersion+cfg.MaxRootRotations)
}

// TestTrustedRootExpiredRecoveryTable: after the trusted root expires,
// publishing a fresh (non-expired) root must let the next refresh
// recover. Exercises the recovery half that TestRootUpdatesTable's
// "trusted root expired fails" only sets up.
func TestTrustedRootExpiredRecoveryTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	// Publish an expired root v2.
	repo.SetExpired(metadata.ROOT)
	repo.BumpVersion(metadata.ROOT)

	cfg, err := repo.GetUpdaterConfig()
	assert.NoError(t, err)
	up, err := New(cfg)
	assert.NoError(t, err)
	err = up.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "final root.json is expired"})
	repo.AssertFilesExist([]string{metadata.ROOT})
	repo.AssertVersionEquals(metadata.ROOT, 2)

	// Now publish a fresh root v3 with a future expiry.
	repo.Simulator.MDRoot.Signed.Expires = repo.Simulator.SafeExpiry
	repo.BumpVersion(metadata.ROOT)

	up, err = New(cfg)
	assert.NoError(t, err)
	assert.NoError(t, up.Refresh())
	repo.AssertFilesExist(metadata.TOP_LEVEL_ROLE_NAMES[:])
	repo.AssertVersionEquals(metadata.ROOT, 3)
}

// TestExpiredTimestampVersionRollbackTable: rollback protection must
// use the trusted local timestamp even when that local timestamp has
// expired. The harness uses UnsafeSetRefTime to simulate the clock
// moving forward past the local timestamp's expiry.
func TestExpiredTimestampVersionRollbackTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	now := time.Now()
	// Timestamp v2 expires in 7 days. First refresh stores it in cache.
	repo.SetExpiresAt(metadata.TIMESTAMP, now.Add(7*24*time.Hour))
	repo.SetVersion(metadata.TIMESTAMP, 2)

	cfg, err := repo.GetUpdaterConfig()
	assert.NoError(t, err)
	up, err := New(cfg)
	assert.NoError(t, err)
	assert.NoError(t, up.Refresh())

	// Repository now serves timestamp v1 (rollback attempt) with a 21-day
	// expiry. Simulate the client clock 18 days later: local v2 has
	// expired, but the rollback rule must still reject v1.
	repo.SetExpiresAt(metadata.TIMESTAMP, now.Add(21*24*time.Hour))
	repo.SetVersion(metadata.TIMESTAMP, 1)

	up, err = New(cfg)
	assert.NoError(t, err)
	up.UnsafeSetRefTime(now.Add(18 * 24 * time.Hour))
	err = up.Refresh()
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 2"})
	repo.AssertVersionEquals(metadata.TIMESTAMP, 2)
}

// TestNewTimestampSnapshotRollbackTable: the timestamp's snapshot meta
// version must never regress relative to what the client previously
// trusted, even if the published timestamp is a strictly newer version.
func TestNewTimestampSnapshotRollbackTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	repo.SetVersion(metadata.SNAPSHOT, 2)
	repo.UpdateTimestamp() // timestamp v2 referencing snapshot v2
	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)

	// Drop snapshot meta version to 1 while bumping timestamp to v3.
	repo.Simulator.MDTimestamp.Signed.Meta["snapshot.json"].Version = 1
	repo.Simulator.MDTimestamp.Signed.Version += 1

	_, err = createAndRefresh(t, repo)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "new snapshot version 1 must be >= 2"})
	repo.AssertVersionEquals(metadata.TIMESTAMP, 2)
}

// TestComputeMetafileHashesLengthTable: enabling the simulator's hash
// computation must not break successive refreshes, and switching it
// off mid-flight must also still produce a valid refresh.
func TestComputeMetafileHashesLengthTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	repo.EnableComputeHashesAndLength()
	repo.UpdateSnapshot()
	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.TIMESTAMP, 2)
	repo.AssertVersionEquals(metadata.SNAPSHOT, 2)

	repo.DisableComputeHashesAndLength()
	repo.UpdateSnapshot()
	_, err = createAndRefresh(t, repo)
	assert.NoError(t, err)
	repo.AssertVersionEquals(metadata.TIMESTAMP, 3)
	repo.AssertVersionEquals(metadata.SNAPSHOT, 3)
}

// TestSnapshotRollbackWithLocalSnapshotHashMismatchTable: snapshot
// rollback detection must still fire on the new snapshot even when
// the locally-stored snapshot's hash disagrees with timestamp.meta.
func TestSnapshotRollbackWithLocalSnapshotHashMismatchTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	repo.EnableComputeHashesAndLength()
	// Targets starts at version 2; snapshot meta now references targets@2.
	repo.SetVersion(metadata.TARGETS, 2)
	repo.UpdateSnapshot()
	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)

	// Now the repository tries to ship targets@1 -- rollback.
	repo.SetVersion(metadata.TARGETS, 1)
	repo.UpdateSnapshot()
	_, err = createAndRefresh(t, repo)
	assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "expected targets.json version 1, got 2"})
}

// TestExpiredMetadataTable: an expired local timestamp/snapshot must
// still be usable to fetch and validate newer remote metadata.
func TestExpiredMetadataTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	now := time.Now()
	repo.SetExpiresAt(metadata.TIMESTAMP, now.Add(7*24*time.Hour))

	cfg, err := repo.GetUpdaterConfig()
	assert.NoError(t, err)
	up, err := New(cfg)
	assert.NoError(t, err)
	assert.NoError(t, up.Refresh())

	// Repository bumps targets and snapshot, refreshes timestamp expiry.
	repo.Simulator.MDTargets.Signed.Version += 1
	repo.UpdateSnapshot()
	repo.SetExpiresAt(metadata.TIMESTAMP, now.Add(21*24*time.Hour))

	// 18 days later the local timestamp v1 is expired; the client must
	// still successfully refresh to v2.
	up, err = New(cfg)
	assert.NoError(t, err)
	up.UnsafeSetRefTime(now.Add(18 * 24 * time.Hour))
	assert.NoError(t, up.Refresh())

	mdTs, err := metadata.Timestamp().FromFile(filepath.Join(repo.MetadataDir, "timestamp.json"))
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mdTs.Signed.Version)

	mdSn, err := metadata.Snapshot().FromFile(filepath.Join(repo.MetadataDir, "snapshot.json"))
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mdSn.Signed.Version)

	mdTg, err := metadata.Targets().FromFile(filepath.Join(repo.MetadataDir, "targets.json"))
	assert.NoError(t, err)
	assert.Equal(t, int64(2), mdTg.Signed.Version)
}

// TestMaxMetadataLengthsTable: lowering the per-role MaxLength below
// the actual payload must trip ErrDownloadLengthMismatch for that role.
func TestMaxMetadataLengthsTable(t *testing.T) {
	tests := []struct {
		name      string
		applyLow  func(cfg *config.UpdaterConfig)
		wantErrIs error
	}{
		{
			name:      "root max length too low",
			applyLow:  func(cfg *config.UpdaterConfig) { cfg.RootMaxLength = 100 },
			wantErrIs: &metadata.ErrDownloadLengthMismatch{},
		},
		{
			name:      "timestamp max length too low",
			applyLow:  func(cfg *config.UpdaterConfig) { cfg.TimestampMaxLength = 100 },
			wantErrIs: &metadata.ErrDownloadLengthMismatch{},
		},
		{
			name:      "snapshot max length too low",
			applyLow:  func(cfg *config.UpdaterConfig) { cfg.SnapshotMaxLength = 100 },
			wantErrIs: &metadata.ErrDownloadLengthMismatch{},
		},
		{
			name:      "targets max length too low",
			applyLow:  func(cfg *config.UpdaterConfig) { cfg.TargetsMaxLength = 100 },
			wantErrIs: &metadata.ErrDownloadLengthMismatch{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			// Ensure there's a root v2 to fetch so RootMaxLength bites.
			repo.BumpVersion(metadata.ROOT)

			cfg, err := repo.GetUpdaterConfig()
			assert.NoError(t, err)
			tc.applyLow(cfg)
			up, err := New(cfg)
			assert.NoError(t, err)

			err = up.Refresh()
			assert.ErrorIs(t, err, tc.wantErrIs)
		})
	}
}

// TestTimestampEqVersionsCheckTable: a timestamp whose version matches
// the locally-trusted version (but with different meta) must not
// replace the trusted copy.
func TestTimestampEqVersionsCheckTable(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	_, err := createAndRefresh(t, repo)
	assert.NoError(t, err)

	initial := repo.Simulator.MDTimestamp.Signed.Meta["snapshot.json"].Version
	// Mutate meta without bumping timestamp version.
	repo.Simulator.MDTimestamp.Signed.Meta["snapshot.json"].Version = 100

	_, err = createAndRefresh(t, repo)
	assert.NoError(t, err)

	stored, err := metadata.Timestamp().FromFile(filepath.Join(repo.MetadataDir, "timestamp.json"))
	assert.NoError(t, err)
	assert.Equal(t, initial, stored.Signed.Meta["snapshot.json"].Version)
}

// TestDelegatesConsistentSnapshotTable verifies the delegated-targets
// fetch behaviour under both consistent-snapshot modes. The fetch
// tracker records every metadata GET so we can assert the exact set
// of version-prefixed (or unprefixed) names the client requested.
func TestDelegatesConsistentSnapshotTable(t *testing.T) {
	tests := []struct {
		name               string
		consistentSnapshot bool
		expectedDelegates  []simulator.FTMetadata
	}{
		{
			name:               "consistent snapshot disabled -- no version prefix on delegate fetches",
			consistentSnapshot: false,
			expectedDelegates: []simulator.FTMetadata{
				{Name: "role1", Value: -1},
				{Name: "..", Value: -1},
				{Name: ".", Value: -1},
			},
		},
		{
			name:               "consistent snapshot enabled -- version prefix on delegate fetches",
			consistentSnapshot: true,
			expectedDelegates: []simulator.FTMetadata{
				{Name: "role1", Value: 1},
				{Name: "..", Value: 1},
				{Name: ".", Value: 1},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			repo.Simulator.MDRoot.Signed.ConsistentSnapshot = tc.consistentSnapshot
			repo.BumpVersion(metadata.ROOT)

			// Register three delegated roles with distinctive names.
			target := metadata.Targets(repo.Simulator.SafeExpiry)
			for _, name := range []string{"role1", "..", "."} {
				dr := metadata.DelegatedRole{
					Name:        name,
					KeyIDs:      []string{},
					Threshold:   1,
					Terminating: false,
					Paths:       []string{"*"},
				}
				repo.Simulator.AddDelegation("targets", dr, target.Signed)
			}
			repo.UpdateSnapshot()

			cfg, err := repo.GetUpdaterConfig()
			assert.NoError(t, err)
			up, err := New(cfg)
			assert.NoError(t, err)
			assert.NoError(t, up.Refresh())

			// Reset tracker to isolate the delegate-fetch requests
			// triggered by GetTargetInfo.
			repo.Simulator.FetchTracker.Metadata = []simulator.FTMetadata{}
			_, err = up.GetTargetInfo("anything")
			assert.ErrorContains(t, err, "target anything not found")

			assert.ElementsMatch(t, tc.expectedDelegates, repo.Simulator.FetchTracker.Metadata)
			repo.AssertFilesExist(metadata.TOP_LEVEL_ROLE_NAMES[:])
		})
	}
}

// TestGetTargetInfoTable covers GetTargetInfo lookup behaviour: returning
// the right TargetFiles for a known path, and returning the canonical "not
// found" error for an unknown one. The known-target case also exercises
// the implicit Refresh that GetTargetInfo triggers when targets isn't
// trusted yet.
func TestGetTargetInfoTable(t *testing.T) {
	skipIfWindows(t)
	const targetPath = "hello.txt"
	targetContent := []byte("hello, table-driven world")

	tests := []struct {
		name       string
		targetPath string
		wantErr    bool
		wantErrMsg string
	}{
		{name: "known target is returned", targetPath: targetPath},
		{
			name:       "unknown target returns not-found",
			targetPath: "does-not-exist",
			wantErr:    true,
			wantErrMsg: "target does-not-exist not found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			repo.AddTarget(metadata.TARGETS, targetContent, targetPath)
			repo.UpdateSnapshot()

			// Construct the updater without a preceding Refresh so the
			// GetTargetInfo call exercises its implicit "if Targets
			// isn't trusted yet, Refresh first" branch.
			cfg, err := repo.GetUpdaterConfig()
			assert.NoError(t, err)
			up, err := New(cfg)
			assert.NoError(t, err)

			info, err := up.GetTargetInfo(tc.targetPath)
			if tc.wantErr {
				assert.ErrorContains(t, err, tc.wantErrMsg)
				assert.Nil(t, info)
				return
			}
			assert.NoError(t, err)
			if assert.NotNil(t, info) {
				assert.Equal(t, tc.targetPath, info.Path)
				assert.Equal(t, int64(len(targetContent)), info.Length)
			}
		})
	}
}

// TestDownloadTargetTable covers DownloadTarget across its main branches:
// happy path with the configured base URL, happy path with an explicit
// targetBaseURL argument, and the rejection when neither is set.
func TestDownloadTargetTable(t *testing.T) {
	skipIfWindows(t)
	// The simulator's URL routing for targets has multiple bugs that
	// compound under consistent-snapshot mode -- a flat target path
	// panics lastIndex, and a nested one collides with the hash-prefix
	// parser. Use a doubly-nested layout and switch consistent_snapshot
	// off below.
	const targetPath = "a/b/doc.txt"
	targetContent := []byte("doc body")

	tests := []struct {
		name        string
		useExplicit bool // pass cfg.RemoteTargetsURL as the explicit baseURL arg
		clearCfgURL bool // wipe cfg.RemoteTargetsURL before the call
		wantErr     bool
		wantErrMsg  string
	}{
		{name: "uses cfg.RemoteTargetsURL when baseURL is empty"},
		{
			name:        "uses explicit baseURL argument",
			useExplicit: true,
		},
		{
			name:        "errors when both cfg URL and arg are empty",
			clearCfgURL: true,
			wantErr:     true,
			wantErrMsg:  "targetBaseURL must be set",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()
			// Disable consistent-snapshot to dodge the simulator's
			// hash-prefix URL parsing path for targets.
			repo.Simulator.MDRoot.Signed.ConsistentSnapshot = false
			repo.BumpVersion(metadata.ROOT)
			repo.AddTarget(metadata.TARGETS, targetContent, targetPath)
			repo.UpdateSnapshot()

			cfg, err := repo.GetUpdaterConfig()
			assert.NoError(t, err)
			// The simulator's URL routing keys off the LocalDir layout
			// (/metadata/* vs /targets/*); TestRepository's default
			// RemoteTargetsURL (MetadataDir + "/targets") doesn't match
			// either branch, so we point it at the actual TargetsDir.
			cfg.RemoteTargetsURL = repo.TargetsDir
			savedURL := cfg.RemoteTargetsURL
			if tc.clearCfgURL {
				cfg.RemoteTargetsURL = ""
			}
			up, err := New(cfg)
			assert.NoError(t, err)
			assert.NoError(t, up.Refresh())

			info, err := up.GetTargetInfo(targetPath)
			assert.NoError(t, err)
			assert.NotNil(t, info)

			// When the case wants to exercise the "explicit baseURL"
			// branch, pass the saved cfg URL so the download still
			// resolves through the simulator. Otherwise pass empty.
			var baseURL string
			if tc.useExplicit {
				baseURL = savedURL
			}

			targetDir := t.TempDir()
			dst := filepath.Join(targetDir, "downloaded")
			path, data, err := up.DownloadTarget(info, dst, baseURL)
			if tc.wantErr {
				assert.ErrorContains(t, err, tc.wantErrMsg)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, dst, path)
			assert.Equal(t, targetContent, data)

			// The file is also persisted on disk.
			onDisk, err := os.ReadFile(dst)
			assert.NoError(t, err)
			assert.Equal(t, targetContent, onDisk)
		})
	}
}

// TestFindCachedTargetTable covers FindCachedTarget after a known
// DownloadTarget call, after a hash-mismatching local file, and when the
// local file is missing entirely.
func TestFindCachedTargetTable(t *testing.T) {
	skipIfWindows(t)
	// As in TestDownloadTargetTable, use a doubly-nested path so the
	// simulator's URL parser doesn't trip on shallow names.
	const targetPath = "a/b/cached.txt"
	targetContent := []byte("cached payload")

	t.Run("returns cached path and bytes after a download", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		defer repo.Cleanup()
		repo.Simulator.MDRoot.Signed.ConsistentSnapshot = false
		repo.BumpVersion(metadata.ROOT)
		repo.AddTarget(metadata.TARGETS, targetContent, targetPath)
		repo.UpdateSnapshot()

		cfg, err := repo.GetUpdaterConfig()
		assert.NoError(t, err)
		cfg.RemoteTargetsURL = repo.TargetsDir
		up, err := New(cfg)
		assert.NoError(t, err)
		assert.NoError(t, up.Refresh())
		info, err := up.GetTargetInfo(targetPath)
		assert.NoError(t, err)

		dst := filepath.Join(t.TempDir(), "out")
		_, _, err = up.DownloadTarget(info, dst, "")
		assert.NoError(t, err)

		gotPath, gotData, err := up.FindCachedTarget(info, dst)
		assert.NoError(t, err)
		assert.Equal(t, dst, gotPath)
		assert.Equal(t, targetContent, gotData)
	})

	t.Run("returns empty when the cached file is missing", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		defer repo.Cleanup()
		repo.AddTarget(metadata.TARGETS, targetContent, targetPath)
		repo.UpdateSnapshot()

		up, err := createAndRefresh(t, repo)
		assert.NoError(t, err)
		info, err := up.GetTargetInfo(targetPath)
		assert.NoError(t, err)

		// Point at a file that doesn't exist.
		gotPath, gotData, err := up.FindCachedTarget(info, filepath.Join(t.TempDir(), "absent"))
		assert.NoError(t, err)
		assert.Empty(t, gotPath)
		assert.Empty(t, gotData)
	})

	t.Run("returns empty when the cached file is corrupted", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		defer repo.Cleanup()
		repo.AddTarget(metadata.TARGETS, targetContent, targetPath)
		repo.UpdateSnapshot()

		up, err := createAndRefresh(t, repo)
		assert.NoError(t, err)
		info, err := up.GetTargetInfo(targetPath)
		assert.NoError(t, err)

		// Write a file with mismatching content; the cache lookup must
		// reject it on hash verification.
		dst := filepath.Join(t.TempDir(), "bad")
		assert.NoError(t, os.WriteFile(dst, []byte("not the right bytes"), 0644))

		gotPath, gotData, err := up.FindCachedTarget(info, dst)
		assert.NoError(t, err)
		assert.Empty(t, gotPath)
		assert.Empty(t, gotData)
	})

	t.Run("no-op when local cache is disabled", func(t *testing.T) {
		repo := simulator.NewTestRepository(t)
		defer repo.Cleanup()
		repo.AddTarget(metadata.TARGETS, targetContent, targetPath)
		repo.UpdateSnapshot()

		cfg, err := repo.GetUpdaterConfig()
		assert.NoError(t, err)
		cfg.DisableLocalCache = true
		up, err := New(cfg)
		assert.NoError(t, err)
		assert.NoError(t, up.Refresh())
		info, err := up.GetTargetInfo(targetPath)
		assert.NoError(t, err)

		gotPath, gotData, err := up.FindCachedTarget(info, "")
		assert.NoError(t, err)
		assert.Empty(t, gotPath)
		assert.Empty(t, gotData)
	})
}
