// Copyright 2026 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
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
	"maps"
	"testing"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// delegate delegates paths from parent to role and returns the signer of
// the key that parent trusts for role.
func delegate(repo *simulator.TestRepository, parent, role string, paths ...string) map[string]*signature.Signer {
	sim := repo.Simulator
	known := maps.Clone(sim.Signers[role])
	targets := metadata.Targets(sim.SafeExpiry)
	// the simulator only extends the delegations of a delegated role if set
	targets.Signed.Delegations = &metadata.Delegations{
		Keys:  map[string]*metadata.Key{},
		Roles: []metadata.DelegatedRole{},
	}
	sim.AddDelegation(parent, metadata.DelegatedRole{
		Name:      role,
		KeyIDs:    []string{},
		Threshold: 1,
		Paths:     paths,
	}, targets.Signed)

	added := maps.Clone(sim.Signers[role])
	maps.DeleteFunc(added, func(keyID string, _ *signature.Signer) bool {
		_, ok := known[keyID]
		return ok
	})
	return added
}

// setupSharedRole creates a repository where two parents delegate to
// the same role, each for its own paths and each listing its own key for it:
//
//	targets -- a/* --> parent-a -- a/* --> shared (key listed by parent-a: signersA)
//	targets -- b/* --> parent-b -- b/* --> shared (key listed by parent-b: signersB)
//
// "shared" is a single metadata file. A target under "a/" is only reached
// through "parent-a" and a target under "b/" only through "parent-b", so
// "shared" is accepted for a path only if it is signed with the key listed by
// the parent that path is reached through.
//
// It returns the repository and the signers of the two keys. Both are
// registered for "shared", which is therefore signed with both keys unless a
// test narrows repo.Simulator.Signers["shared"] to one of them.
func setupSharedRole(t *testing.T) (repo *simulator.TestRepository, signersA, signersB map[string]*signature.Signer) {
	t.Helper()
	repo = simulator.NewTestRepository(t)

	delegate(repo, metadata.TARGETS, "parent-a", "a/*")
	delegate(repo, metadata.TARGETS, "parent-b", "b/*")
	signersA = delegate(repo, "parent-a", "shared", "a/*")
	signersB = delegate(repo, "parent-b", "shared", "b/*")
	return repo, signersA, signersB
}

// refreshedUpdater publishes the repository and returns an updater for it.
func refreshedUpdater(t *testing.T, repo *simulator.TestRepository) *Updater {
	t.Helper()
	repo.UpdateSnapshot()
	updater, err := createAndRefresh(t, repo)
	require.NoError(t, err)
	require.NotNil(t, updater)
	return updater
}

// refreshedUpdaterWithMaxDelegations publishes the repository and returns
// an updater for it that visits at most maxDelegations delegated roles, or
// the default number of them if maxDelegations is 0.
func refreshedUpdaterWithMaxDelegations(t *testing.T, repo *simulator.TestRepository, maxDelegations int) *Updater {
	t.Helper()
	repo.UpdateSnapshot()
	cfg, err := repo.GetUpdaterConfig()
	require.NoError(t, err)
	if maxDelegations != 0 {
		cfg.MaxDelegations = maxDelegations
	}
	updater, err := New(cfg)
	require.NoError(t, err)
	require.NoError(t, updater.Refresh())
	return updater
}

func TestSharedRoleVerifiedByEachDelegator(t *testing.T) {
	// "shared" is signed with the keys of both parents, so it is valid
	// through either of them
	repo, _, _ := setupSharedRole(t)
	repo.AddTarget("shared", []byte("a"), "a/file")
	repo.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t, repo)

	// "a/file" is reached through "parent-a" and "b/file" through
	// "parent-b": each parent verifies "shared" with its own key
	for _, targetPath := range []string{"a/file", "b/file", "a/file"} {
		info, err := updater.GetTargetInfo(targetPath)
		assert.NoError(t, err)
		assert.NotNil(t, info)
	}

	// the role is loaded once and reused for both delegators
	fetched := 0
	for _, md := range repo.Simulator.FetchTracker.Metadata {
		if md.Name == "shared" {
			fetched++
		}
	}
	assert.Equal(t, 1, fetched)
}

func TestCachedRoleNotVerifiedByOtherDelegator(t *testing.T) {
	// "shared" is signed with the key of "parent-a" only
	repo, signersA, _ := setupSharedRole(t)
	repo.Simulator.Signers["shared"] = signersA
	repo.AddTarget("shared", []byte("a"), "a/file")
	repo.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t, repo)

	// "a/file" is reached through "parent-a", whose key signed "shared"
	info, err := updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// "b/file" is reached through "parent-b", whose key did not sign
	// "shared": the copy cached for "parent-a" is not reused for "parent-b"
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}

func TestCachedRoleReplacedThroughOtherDelegator(t *testing.T) {
	// "shared" is first signed with the key of "parent-b" only
	repo, signersA, signersB := setupSharedRole(t)
	repo.Simulator.Signers["shared"] = signersB
	repo.AddTarget("shared", []byte("a"), "a/file")
	repo.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t, repo)

	// "b/file" is reached through "parent-b", whose key signed "shared"
	info, err := updater.GetTargetInfo("b/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the repository then serves a copy signed with the key of "parent-a"
	// only. "a/file" is reached through "parent-a": the cached copy is not
	// signed with its key, so the new copy is loaded and replaces it
	repo.Simulator.Signers["shared"] = signersA
	info, err = updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// "b/file" is reached through "parent-b" again: it verified the earlier
	// copy, but its key did not sign the one that replaced it
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}

func TestCachedRoleNotVerifiedByReplacedDelegator(t *testing.T) {
	// "shared" is first signed with the key of "parent-a" only. It delegates
	// all paths to "leaf", which holds the targets and is signed with the
	// key that "shared" lists for it:
	//
	//	parent-a -- a/* --> shared -- */* --> leaf
	//	parent-b -- b/* --> shared -- */* --> leaf
	repo, signersA, signersB := setupSharedRole(t)
	repo.Simulator.Signers["shared"] = signersA
	delegate(repo, "shared", "leaf", "*/*")
	repo.AddTarget("leaf", []byte("a"), "a/file")
	repo.AddTarget("leaf", []byte("b"), "b/file")
	updater := refreshedUpdater(t, repo)

	// "a/file" is reached through "parent-a", whose key signed "shared",
	// and then through "shared", whose listed key signed "leaf"
	info, err := updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the repository then serves a copy of "shared" signed with the key of
	// "parent-b" only, which lists another key for "leaf". "leaf" itself is
	// unchanged
	publicKey, _ := helpers.GenerateTestKeyPair(t)
	key, err := metadata.KeyFromPublicKey(publicKey)
	require.NoError(t, err)
	keyID, err := key.ID()
	require.NoError(t, err)
	delegations := repo.Simulator.MDDelegates["shared"].Signed.Delegations
	delegations.Keys = map[string]*metadata.Key{keyID: key}
	delegations.Roles[0].KeyIDs = []string{keyID}
	repo.Simulator.Signers["shared"] = signersB

	// "b/file" is reached through "parent-b", which accepts the new copy of
	// "shared". The cached "leaf" was verified by the previous copy and is
	// not signed with the key that the new copy lists
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}

// setupDiamond creates a repository where two parents delegate all paths
// to the same role, each listing its own key for it:
//
//	targets -- */* --> parent-a -- */* --> shared (key listed by parent-a: signersA)
//	targets -- */* --> parent-b -- */* --> shared (key listed by parent-b: signersB)
//
// A search for a target that no role lists walks into "shared" twice:
// first through "parent-a" and then through "parent-b".
func setupDiamond(t *testing.T) (repo *simulator.TestRepository, signersA, signersB map[string]*signature.Signer) {
	t.Helper()
	repo = simulator.NewTestRepository(t)

	delegate(repo, metadata.TARGETS, "parent-a", "*/*")
	delegate(repo, metadata.TARGETS, "parent-b", "*/*")
	signersA = delegate(repo, "parent-a", "shared", "*/*")
	signersB = delegate(repo, "parent-b", "shared", "*/*")
	return repo, signersA, signersB
}

func TestSharedRoleVisitedThroughEachDelegationPath(t *testing.T) {
	tests := []struct {
		name string
		// whether "shared" is signed with the key listed by each parent
		signedByA, signedByB bool
		maxDelegations       int
		wantErr              error
		wantErrMsg           string
	}{
		{
			name:       "signed with the keys of both parents",
			signedByA:  true,
			signedByB:  true,
			wantErrMsg: "target dir/missing not found",
		},
		{
			// "shared" is valid through "parent-a" but is visited again
			// through "parent-b", whose key did not sign it
			name:      "signed with the key of the first parent only",
			signedByA: true,
			wantErr:   &metadata.ErrUnsignedMetadata{},
		},
		{
			name:      "signed with the key of the second parent only",
			signedByB: true,
			wantErr:   &metadata.ErrUnsignedMetadata{},
		},
		{
			// targets, parent-a, shared and parent-b are visited: visiting
			// "shared" again through "parent-b" would exceed the limit
			name:           "visiting the role again exceeds the maximum number of delegations",
			signedByA:      true,
			maxDelegations: 3,
			wantErrMsg:     "target dir/missing not found",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo, signersA, signersB := setupDiamond(t)
			signers := map[string]*signature.Signer{}
			if tc.signedByA {
				maps.Copy(signers, signersA)
			}
			if tc.signedByB {
				maps.Copy(signers, signersB)
			}
			repo.Simulator.Signers["shared"] = signers
			updater := refreshedUpdaterWithMaxDelegations(t, repo, tc.maxDelegations)

			info, err := updater.GetTargetInfo("dir/missing")
			if tc.wantErr != nil {
				assert.ErrorIs(t, err, tc.wantErr)
			} else {
				assert.ErrorContains(t, err, tc.wantErrMsg)
			}
			assert.Nil(t, info)
		})
	}
}

func TestDelegationCyclesSkipped(t *testing.T) {
	// "parent-a" and "parent-b" delegate to themselves and to each other,
	// and "parent-c" lists the target:
	//
	//	targets -- */* --> parent-a -- */* --> parent-a, parent-b
	//	        -- */* --> parent-b -- */* --> parent-b, parent-a
	//	        -- */* --> parent-c
	//
	// A role is skipped only if it is already on the delegation path used
	// to reach it, so the search visits targets, parent-a, parent-b
	// (through parent-a), parent-b and parent-a (through parent-b), and
	// then finds the target in parent-c, the sixth role it visits
	tests := []struct {
		name           string
		maxDelegations int
		wantFound      bool
	}{
		{
			name:      "default maximum number of delegations",
			wantFound: true,
		},
		{
			name:           "parent-c is the last role allowed",
			maxDelegations: 5,
			wantFound:      true,
		},
		{
			// roles visited again through another delegation path count
			// toward the maximum number of delegations
			name:           "parent-c exceeds the maximum number of delegations",
			maxDelegations: 4,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			delegate(repo, metadata.TARGETS, "parent-a", "*/*")
			delegate(repo, metadata.TARGETS, "parent-b", "*/*")
			delegate(repo, metadata.TARGETS, "parent-c", "*/*")
			delegate(repo, "parent-a", "parent-a", "*/*")
			delegate(repo, "parent-a", "parent-b", "*/*")
			delegate(repo, "parent-b", "parent-b", "*/*")
			delegate(repo, "parent-b", "parent-a", "*/*")
			repo.AddTarget("parent-c", []byte("c"), "dir/file")
			updater := refreshedUpdaterWithMaxDelegations(t, repo, tc.maxDelegations)

			info, err := updater.GetTargetInfo("dir/file")
			if tc.wantFound {
				assert.NoError(t, err)
				assert.NotNil(t, info)
			} else {
				assert.ErrorContains(t, err, "target dir/file not found")
				assert.Nil(t, info)
			}

			// each role is loaded once, however many times it is visited
			fetched := map[string]int{}
			for _, md := range repo.Simulator.FetchTracker.Metadata {
				fetched[md.Name]++
			}
			assert.Equal(t, 1, fetched["parent-a"])
			assert.Equal(t, 1, fetched["parent-b"])
		})
	}
}
