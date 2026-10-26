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

package simulator_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

func TestBuilderBootstrap(t *testing.T) {
	for _, tc := range []struct {
		name  string
		build func() *simulator.SimulatorBuilder
		check func(*testing.T, *metadata.Metadata[metadata.RootType])
	}{
		{"consistent snapshots disabled", func() *simulator.SimulatorBuilder { return simulator.NewSimulator().WithConsistentSnapshot(false) }, func(t *testing.T, root *metadata.Metadata[metadata.RootType]) {
			require.False(t, root.Signed.ConsistentSnapshot)
		}},
		{"expired root", func() *simulator.SimulatorBuilder { return simulator.NewSimulator().WithExpiredRole(metadata.ROOT) }, func(t *testing.T, root *metadata.Metadata[metadata.RootType]) {
			require.True(t, root.Signed.Expires.Before(time.Now()))
		}},
		{"unsigned root", func() *simulator.SimulatorBuilder { return simulator.NewSimulator().WithoutSigners(metadata.ROOT) }, func(t *testing.T, root *metadata.Metadata[metadata.RootType]) { require.Empty(t, root.Signatures) }},
		{"explicit root version", func() *simulator.SimulatorBuilder { return simulator.NewSimulator().WithVersion(metadata.ROOT, 7) }, func(t *testing.T, root *metadata.Metadata[metadata.RootType]) {
			require.EqualValues(t, 7, root.Signed.Version)
		}},
		{"expiry", func() *simulator.SimulatorBuilder { return simulator.NewSimulator().WithExpiry(time.Hour) }, func(t *testing.T, root *metadata.Metadata[metadata.RootType]) {
			require.WithinDuration(t, time.Now().Add(time.Hour), root.Signed.Expires, 2*time.Second)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepositoryWithBuilder(t, tc.build())
			root, err := metadata.Root().FromBytes(repo.RootBytes)
			require.NoError(t, err)
			tc.check(t, root)
		})
	}
}

func TestBuilderRefresh(t *testing.T) {
	repo := simulator.NewTestRepositoryWithBuilder(t, simulator.NewSimulator().
		WithConsistentSnapshot(false).WithComputeHashesAndLength(true).
		WithVersion(metadata.ROOT, 7).WithRootRotations(2).
		WithVersion(metadata.TARGETS, 5).WithTargetsVersionBump(1).
		WithVersion(metadata.SNAPSHOT, 9).WithSnapshotVersionBump(2).
		WithVersion(metadata.TIMESTAMP, 7).WithTimestampVersionBump(3).
		WithTarget("artifact.txt", []byte("fixture")))
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	up, err := updater.New(cfg)
	require.NoError(t, err)
	require.NoError(t, up.Refresh())
	trusted := up.GetTrustedMetadataSet()
	require.EqualValues(t, 9, trusted.Root.Signed.Version)
	require.EqualValues(t, 6, trusted.Targets[metadata.TARGETS].Signed.Version)
	require.EqualValues(t, 11, trusted.Snapshot.Signed.Version)
	require.EqualValues(t, 10, trusted.Timestamp.Signed.Version)
	info, err := up.GetTargetInfo("artifact.txt")
	require.NoError(t, err)
	require.NoError(t, info.VerifyLengthHashes([]byte("fixture")))
	require.NoError(t, repo.WriteRoot(8))
	repo.AssertVersionEquals(metadata.ROOT, 8)
}

func TestCacheAssertionsDoNotMutateRepository(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	up, err := updater.New(cfg)
	require.NoError(t, err)
	require.NoError(t, up.Refresh())
	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		cachedVersion := repo.GetVersion(role)
		trackerBefore := len(repo.Simulator.FetchTracker.Metadata)
		version := int(cachedVersion)
		repo.AssertContentEquals(role, &version)
		require.Len(t, repo.Simulator.FetchTracker.Metadata, trackerBefore, "assertions must not record fetches")
		repo.BumpVersion(role)
		repo.AssertVersionEquals(role, cachedVersion)
		require.Equal(t, cachedVersion+1, repo.GetVersion(role), "asserting %s must not change remote metadata", role)
	}
}
