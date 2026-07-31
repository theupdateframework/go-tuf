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
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

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
