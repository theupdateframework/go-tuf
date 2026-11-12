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
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// A role delegated by two parents has to be signature-checked for each parent.
// Loading it through the first parent must not make the second parent skip verification.
func TestSharedDelegationSignatureCheck(t *testing.T) {
	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = false
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	empty := metadata.Targets(simulator.Sim.SafeExpiry)
	for _, parent := range []struct {
		name string
		path string
	}{
		{name: "parent-a", path: "path-a"},
		{name: "parent-b", path: "path-b"},
	} {
		simulator.Sim.AddDelegation("targets", metadata.DelegatedRole{
			Name:      parent.name,
			Threshold: 1,
			Paths:     []string{parent.path},
		}, empty.Signed)
	}

	release := metadata.Targets(simulator.Sim.SafeExpiry)
	for path, content := range map[string]string{
		"path-a": "content-a",
		"path-b": "content-b",
	} {
		targetFile, err := metadata.TargetFile().FromBytes(path, []byte(content), "sha256")
		assert.NoError(t, err)
		release.Signed.Targets[path] = targetFile
	}
	simulator.Sim.MDDelegates["release"] = *release

	parentAKey := delegateRelease(t, "parent-a", "path-a")
	parentBKey := delegateRelease(t, "parent-b", "path-b")
	if parentAKey == parentBKey {
		t.Fatal("each parent needs its own release key")
	}

	simulator.Sim.UpdateSnapshot()
	updater := refreshUpdater(t)
	targetA, err := updater.GetTargetInfo("path-a")
	assert.NoError(t, err)
	assert.NotNil(t, targetA)
	targetB, err := updater.GetTargetInfo("path-b")
	assert.NoError(t, err)
	assert.NotNil(t, targetB)

	// Next release is signed only by parent-a.
	delete(simulator.Sim.Signers["release"], parentBKey)
	next := simulator.Sim.MDDelegates["release"]
	next.Signed.Version++
	simulator.Sim.MDDelegates["release"] = next
	simulator.Sim.UpdateSnapshot()

	updater = refreshUpdater(t)
	targetA, err = updater.GetTargetInfo("path-a")
	assert.NoError(t, err)
	assert.NotNil(t, targetA)
	_, err = updater.GetTargetInfo("path-b")
	assert.ErrorIs(t, err, &metadata.ErrUnsignedMetadata{})
}

func delegateRelease(t *testing.T, parent, pathPattern string) string {
	t.Helper()
	public, _, signer := simulator.CreateKey()
	mdkey, err := metadata.KeyFromPublicKey(*public)
	if err != nil {
		t.Fatal(err)
	}
	keyID, err := mdkey.ID()
	if err != nil {
		t.Fatal(err)
	}
	parentMD := simulator.Sim.MDDelegates[parent]
	if parentMD.Signed.Delegations == nil {
		parentMD.Signed.Delegations = &metadata.Delegations{
			Keys:  map[string]*metadata.Key{},
			Roles: []metadata.DelegatedRole{},
		}
	}
	parentMD.Signed.Delegations.Roles = append(parentMD.Signed.Delegations.Roles, metadata.DelegatedRole{
		Name:      "release",
		Threshold: 1,
		Paths:     []string{pathPattern},
	})
	if err = parentMD.Signed.AddKey(mdkey, "release"); err != nil {
		t.Fatal(err)
	}
	simulator.Sim.MDDelegates[parent] = parentMD
	simulator.Sim.AddSigner("release", keyID, *signer)
	return keyID
}

func refreshUpdater(t *testing.T) *Updater {
	t.Helper()
	updaterConfig, err := loadUpdaterConfig()
	if err != nil {
		t.Fatal(err)
	}
	updater := initUpdater(updaterConfig)
	if updater == nil {
		t.Fatal("updater is nil")
	}
	if err = updater.Refresh(); err != nil {
		t.Fatal(err)
	}
	return updater
}
