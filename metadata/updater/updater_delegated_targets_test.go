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

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// delegate delegates paths from parent to role and returns the signer of
// the key that parent trusts for role.
func delegate(parent, role string, paths ...string) map[string]*signature.Signer {
	known := maps.Clone(simulator.Sim.Signers[role])
	targets := metadata.Targets(simulator.Sim.SafeExpiry)
	// the simulator only extends the delegations of a delegated role if set
	targets.Signed.Delegations = &metadata.Delegations{
		Keys:  map[string]*metadata.Key{},
		Roles: []metadata.DelegatedRole{},
	}
	simulator.Sim.AddDelegation(parent, metadata.DelegatedRole{
		Name:      role,
		KeyIDs:    []string{},
		Threshold: 1,
		Paths:     paths,
	}, targets.Signed)

	added := maps.Clone(simulator.Sim.Signers[role])
	maps.DeleteFunc(added, func(keyID string, _ *signature.Signer) bool {
		_, ok := known[keyID]
		return ok
	})
	return added
}

// setupSharedRole resets the repository to one where "shared" is delegated
// by "parent-a" for "a/*" and by "parent-b" for "b/*", each trusting its own
// key. It returns the signers of those two keys.
func setupSharedRole(t *testing.T) (signersA, signersB map[string]*signature.Signer) {
	t.Helper()
	require.NoError(t, loadOrResetTrustedRootMetadata())

	delegate(metadata.TARGETS, "parent-a", "a/*")
	delegate(metadata.TARGETS, "parent-b", "b/*")
	signersA = delegate("parent-a", "shared", "a/*")
	signersB = delegate("parent-b", "shared", "b/*")
	return signersA, signersB
}

// refreshedUpdater publishes the repository and returns an updater for it.
func refreshedUpdater(t *testing.T) *Updater {
	t.Helper()
	simulator.Sim.UpdateSnapshot()
	updaterConfig, err := loadUpdaterConfig()
	require.NoError(t, err)
	updater := initUpdater(updaterConfig)
	require.NotNil(t, updater)
	require.NoError(t, updater.Refresh())
	return updater
}

func TestSharedRoleVerifiedByEachDelegator(t *testing.T) {
	// "shared" meets the keys and threshold of both delegators
	setupSharedRole(t)
	simulator.Sim.AddTarget("shared", []byte("a"), "a/file")
	simulator.Sim.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	for _, targetPath := range []string{"a/file", "b/file", "a/file"} {
		info, err := updater.GetTargetInfo(targetPath)
		assert.NoError(t, err)
		assert.NotNil(t, info)
	}

	// the role is loaded once and reused for both delegators
	fetched := 0
	for _, md := range simulator.Sim.FetchTracker.Metadata {
		if md.Name == "shared" {
			fetched++
		}
	}
	assert.Equal(t, 1, fetched)
}

func TestCachedRoleNotVerifiedByOtherDelegator(t *testing.T) {
	// "shared" only meets the keys of "parent-a"
	signersA, _ := setupSharedRole(t)
	simulator.Sim.Signers["shared"] = signersA
	simulator.Sim.AddTarget("shared", []byte("a"), "a/file")
	simulator.Sim.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	info, err := updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the copy cached for "parent-a" is not reused for "parent-b"
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}

func TestCachedRoleReplacedThroughOtherDelegator(t *testing.T) {
	// "shared" first only meets the keys of "parent-b"
	signersA, signersB := setupSharedRole(t)
	simulator.Sim.Signers["shared"] = signersB
	simulator.Sim.AddTarget("shared", []byte("a"), "a/file")
	simulator.Sim.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	info, err := updater.GetTargetInfo("b/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the repository then serves a copy that only meets the keys of
	// "parent-a", which replaces the cached one
	simulator.Sim.Signers["shared"] = signersA
	info, err = updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the earlier verification by "parent-b" does not cover the new copy
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}

func TestCachedRoleNotVerifiedByReplacedDelegator(t *testing.T) {
	// "shared" first only meets the keys of "parent-a" and delegates to "leaf"
	signersA, signersB := setupSharedRole(t)
	simulator.Sim.Signers["shared"] = signersA
	delegate("shared", "leaf", "*/*")
	simulator.Sim.AddTarget("leaf", []byte("a"), "a/file")
	simulator.Sim.AddTarget("leaf", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	info, err := updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the repository then serves a copy of "shared" that only meets the keys
	// of "parent-b" and trusts another key for "leaf"
	publicKey, _, _ := simulator.CreateKey()
	key, err := metadata.KeyFromPublicKey(*publicKey)
	require.NoError(t, err)
	keyID, err := key.ID()
	require.NoError(t, err)
	delegations := simulator.Sim.MDDelegates["shared"].Signed.Delegations
	delegations.Keys = map[string]*metadata.Key{keyID: key}
	delegations.Roles[0].KeyIDs = []string{keyID}
	simulator.Sim.Signers["shared"] = signersB

	// "leaf" was verified by the previous copy of "shared", not by this one
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}
