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

// setupSharedRole resets the repository to one where two parents delegate to
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
// It returns the signers of the two keys. Both are registered for "shared",
// which is therefore signed with both keys unless a test narrows
// simulator.Sim.Signers["shared"] to one of them.
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
	// "shared" is signed with the keys of both parents, so it is valid
	// through either of them
	setupSharedRole(t)
	simulator.Sim.AddTarget("shared", []byte("a"), "a/file")
	simulator.Sim.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	// "a/file" is reached through "parent-a" and "b/file" through
	// "parent-b": each parent verifies "shared" with its own key
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
	// "shared" is signed with the key of "parent-a" only
	signersA, _ := setupSharedRole(t)
	simulator.Sim.Signers["shared"] = signersA
	simulator.Sim.AddTarget("shared", []byte("a"), "a/file")
	simulator.Sim.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

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
	signersA, signersB := setupSharedRole(t)
	simulator.Sim.Signers["shared"] = signersB
	simulator.Sim.AddTarget("shared", []byte("a"), "a/file")
	simulator.Sim.AddTarget("shared", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	// "b/file" is reached through "parent-b", whose key signed "shared"
	info, err := updater.GetTargetInfo("b/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the repository then serves a copy signed with the key of "parent-a"
	// only. "a/file" is reached through "parent-a": the cached copy is not
	// signed with its key, so the new copy is loaded and replaces it
	simulator.Sim.Signers["shared"] = signersA
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
	signersA, signersB := setupSharedRole(t)
	simulator.Sim.Signers["shared"] = signersA
	delegate("shared", "leaf", "*/*")
	simulator.Sim.AddTarget("leaf", []byte("a"), "a/file")
	simulator.Sim.AddTarget("leaf", []byte("b"), "b/file")
	updater := refreshedUpdater(t)

	// "a/file" is reached through "parent-a", whose key signed "shared",
	// and then through "shared", whose listed key signed "leaf"
	info, err := updater.GetTargetInfo("a/file")
	assert.NoError(t, err)
	assert.NotNil(t, info)

	// the repository then serves a copy of "shared" signed with the key of
	// "parent-b" only, which lists another key for "leaf". "leaf" itself is
	// unchanged
	publicKey, _, _ := simulator.CreateKey()
	key, err := metadata.KeyFromPublicKey(*publicKey)
	require.NoError(t, err)
	keyID, err := key.ID()
	require.NoError(t, err)
	delegations := simulator.Sim.MDDelegates["shared"].Signed.Delegations
	delegations.Keys = map[string]*metadata.Key{keyID: key}
	delegations.Roles[0].KeyIDs = []string{keyID}
	simulator.Sim.Signers["shared"] = signersB

	// "b/file" is reached through "parent-b", which accepts the new copy of
	// "shared". The cached "leaf" was verified by the previous copy and is
	// not signed with the key that the new copy lists
	info, err = updater.GetTargetInfo("b/file")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
	assert.Nil(t, info)
}
