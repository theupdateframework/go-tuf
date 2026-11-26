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
	"bytes"
	"errors"
	"maps"
	"os"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
)

type memoryMetadataStore struct {
	docs       map[string][]byte
	loadErr    map[string]error
	persistErr map[string]error
	reads      int
	writes     int
}

func newMemoryMetadataStore() *memoryMetadataStore {
	return &memoryMetadataStore{
		docs:       make(map[string][]byte),
		loadErr:    make(map[string]error),
		persistErr: make(map[string]error),
	}
}

func (s *memoryMetadataStore) Load(role string) ([]byte, error) {
	s.reads++
	if err, ok := s.loadErr[role]; ok && err != nil {
		return nil, err
	}
	data, ok := s.docs[role]
	if !ok {
		return nil, os.ErrNotExist
	}
	return bytes.Clone(data), nil
}

func (s *memoryMetadataStore) Persist(role string, data []byte) error {
	s.writes++
	if err, ok := s.persistErr[role]; ok && err != nil {
		return err
	}
	s.docs[role] = bytes.Clone(data)
	return nil
}

func newStoreConfig(t *testing.T, repo *simulator.TestRepository, store config.MetadataStore) *config.UpdaterConfig {
	t.Helper()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	cfg.MetadataStore = store
	cfg.LocalMetadataDir = ""
	cfg.LocalTargetsDir = ""
	return cfg
}

func TestMetadataStoreRefreshAndCacheReuse(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	store := newMemoryMetadataStore()
	cfg := newStoreConfig(t, repo, store)

	u1, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, u1.Refresh())

	for _, role := range []string{metadata.ROOT, metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		assert.NotEmpty(t, store.docs[role], "store did not persist %s", role)
	}

	// Second Updater reuses cached snapshot and targets from MetadataStore.
	repo.Simulator.FetchTracker.Metadata = nil
	readsBefore := store.reads
	u2, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, u2.Refresh())
	assert.Greater(t, store.reads, readsBefore)

	for _, fetched := range repo.Simulator.FetchTracker.Metadata {
		assert.NotEqual(t, metadata.SNAPSHOT, fetched.Name, "snapshot should be served from MetadataStore")
		assert.NotEqual(t, metadata.TARGETS, fetched.Name, "targets should be served from MetadataStore")
	}

	// UnsafeLocalMode also reads directly from MetadataStore without network calls.
	repo.Simulator.FetchTracker.Metadata = nil
	offlineCfg := *cfg
	offlineCfg.UnsafeLocalMode = true
	uOffline, err := New(&offlineCfg)
	require.NoError(t, err)
	require.NoError(t, uOffline.Refresh())
	assert.Empty(t, repo.Simulator.FetchTracker.Metadata)
}

func TestMetadataStorePreservesRotatedRootAcrossRestarts(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	store := newMemoryMetadataStore()
	cfg := newStoreConfig(t, repo, store)
	// Keep embedded v1 bootstrap root in cfg.LocalTrustedRoot across restarts.
	v1Bootstrap := bytes.Clone(cfg.LocalTrustedRoot)

	// Rotate root (cross-signed by v1 and v2) and timestamp to v2 on remote.
	v1RootSigners := maps.Clone(repo.Simulator.Signers[metadata.ROOT])
	repo.RotateKeys(metadata.ROOT)
	v2RootSigners := maps.Clone(repo.Simulator.Signers[metadata.ROOT])
	maps.Copy(repo.Simulator.Signers[metadata.ROOT], v1RootSigners)
	repo.RotateKeys(metadata.TIMESTAMP)
	repo.BumpVersion(metadata.ROOT)
	repo.UpdateTimestamp()

	u1, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, u1.Refresh())

	storedRoot, err := metadata.Root().FromBytes(store.docs[metadata.ROOT])
	require.NoError(t, err)
	assert.Equal(t, int64(2), storedRoot.Signed.Version)

	// Rotate root to v3 (cross-signed by v2 and v3 only, revoking v1) and
	// invalidate 2.root.json on remote so any client that resets its stored
	// root back to v1 cannot walk v1 -> v2 -> v3.
	repo.Simulator.Signers[metadata.ROOT] = maps.Clone(v2RootSigners)
	repo.RotateKeys(metadata.ROOT)
	maps.Copy(repo.Simulator.Signers[metadata.ROOT], v2RootSigners)
	repo.BumpVersion(metadata.ROOT)
	repo.Simulator.SignedRoots[1] = []byte("invalid-v2-root")

	cfg.LocalTrustedRoot = v1Bootstrap
	u2, err := New(cfg)
	require.NoError(t, err)
	assert.Equal(t, int64(2), u2.GetTrustedMetadataSet().Root.Signed.Version)

	require.NoError(t, u2.Refresh())
	assert.Equal(t, int64(3), u2.GetTrustedMetadataSet().Root.Signed.Version)

	storedRoot, err = metadata.Root().FromBytes(store.docs[metadata.ROOT])
	require.NoError(t, err)
	assert.Equal(t, int64(3), storedRoot.Signed.Version)
}

func TestMetadataStoreDelegatedRoleNames(t *testing.T) {
	const targetPath = "artifact.bin"

	for _, role := range []string{"team/subrole", "..", "role with space"} {
		t.Run(role, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			delegate(repo, metadata.TARGETS, role, "*")
			repo.AddTarget(role, []byte("payload"), targetPath)
			repo.UpdateSnapshot()

			store := newMemoryMetadataStore()
			cfg := newStoreConfig(t, repo, store)

			u1, err := New(cfg)
			require.NoError(t, err)
			info, err := u1.GetTargetInfo(targetPath)
			require.NoError(t, err)
			require.NotNil(t, info)
			assert.NotEmpty(t, store.docs[role], "store must key delegated metadata by raw role name %q", role)

			// Fresh Updater reads the exact raw role name back from MetadataStore.
			repo.Simulator.FetchTracker.Metadata = nil
			u2, err := New(cfg)
			require.NoError(t, err)
			info, err = u2.GetTargetInfo(targetPath)
			require.NoError(t, err)
			require.NotNil(t, info)

			refetched := slices.ContainsFunc(repo.Simulator.FetchTracker.Metadata, func(m simulator.FTMetadata) bool {
				return m.Name == role
			})
			assert.False(t, refetched, "delegated role %q should be read from MetadataStore, not refetched", role)
		})
	}
}

func TestMetadataStoreFailuresFailClosed(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	diskErr := errors.New("storage unavailable")

	// 1. Persist failure during initial bootstrap in New.
	emptyStore := newMemoryMetadataStore()
	emptyStore.persistErr[metadata.ROOT] = diskErr
	_, err := New(newStoreConfig(t, repo, emptyStore))
	assert.ErrorIs(t, err, diskErr)

	// Populate a healthy store first.
	store := newMemoryMetadataStore()
	cfg := newStoreConfig(t, repo, store)
	u, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, u.Refresh())

	// 2. Non-ErrNotExist Load failure on "root" fails closed in New instead of
	// falling back to LocalTrustedRoot.
	store.loadErr[metadata.ROOT] = diskErr
	_, err = New(cfg)
	assert.ErrorIs(t, err, diskErr)
	delete(store.loadErr, metadata.ROOT)

	// 3. Non-ErrNotExist Load failures on timestamp, snapshot, and targets abort
	// Refresh instead of silently treating cached rollback state as empty.
	for _, role := range []string{metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		t.Run("load_error_"+role, func(t *testing.T) {
			store.loadErr[role] = diskErr
			defer delete(store.loadErr, role)

			uRole, err := New(cfg)
			require.NoError(t, err)
			assert.ErrorIs(t, uRole.Refresh(), diskErr)
		})
	}

	// 4. Persist failure during Refresh propagates.
	repo.BumpVersion(metadata.TIMESTAMP)
	store.persistErr[metadata.TIMESTAMP] = diskErr
	defer delete(store.persistErr, metadata.TIMESTAMP)

	uPersist, err := New(cfg)
	require.NoError(t, err)
	assert.ErrorIs(t, uPersist.Refresh(), diskErr)
}

func TestMetadataStoreRespectsDisableLocalCache(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	store := newMemoryMetadataStore()
	cfg := newStoreConfig(t, repo, store)
	cfg.DisableLocalCache = true

	u, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, u.Refresh())

	assert.Zero(t, store.reads, "DisableLocalCache must skip MetadataStore.Load")
	assert.Zero(t, store.writes, "DisableLocalCache must skip MetadataStore.Persist")
}
