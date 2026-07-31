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

package simulator

import (
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// DelegationSpec defines a delegation to be created in the repository
type DelegationSpec struct {
	DelegatorName string
	Role          metadata.DelegatedRole
	Targets       metadata.TargetsType
}

// SimulatorBuilder creates configured RepositorySimulator instances using a fluent API
type SimulatorBuilder struct {
	expiry                         time.Duration
	consistentSnapshot             bool
	computeHashesAndLength         bool
	prefixTargetsWithHash          bool
	targets                        map[string][]byte
	delegations                    []DelegationSpec
	expiredRoles                   map[string]bool
	roleVersions                   map[string]int64
	unsignedRoles                  map[string]bool
	succinctRoles                  map[string]succinctRoleSpec
	rootRotations                  int
	timestampVersionBump           int64
	snapshotVersionBump            int64
	targetsVersionBump             int64
}

type succinctRoleSpec struct {
	bitLength  int
	namePrefix string
}

// NewSimulator creates a new SimulatorBuilder with sensible defaults
func NewSimulator() *SimulatorBuilder {
	return &SimulatorBuilder{
		expiry:                 30 * 24 * time.Hour,
		consistentSnapshot:     true,
		computeHashesAndLength: false,
		prefixTargetsWithHash:  true,
		targets:                make(map[string][]byte),
		delegations:            []DelegationSpec{},
		expiredRoles:           make(map[string]bool),
		roleVersions:           make(map[string]int64),
		unsignedRoles:          make(map[string]bool),
		succinctRoles:          make(map[string]succinctRoleSpec),
		rootRotations:          0,
	}
}

// WithExpiry sets the default metadata expiration duration
func (b *SimulatorBuilder) WithExpiry(d time.Duration) *SimulatorBuilder {
	b.expiry = d
	return b
}

// WithConsistentSnapshot enables or disables consistent snapshots
func (b *SimulatorBuilder) WithConsistentSnapshot(enabled bool) *SimulatorBuilder {
	b.consistentSnapshot = enabled
	return b
}

// WithComputeHashesAndLength enables or disables hash/length computation for meta files
func (b *SimulatorBuilder) WithComputeHashesAndLength(enabled bool) *SimulatorBuilder {
	b.computeHashesAndLength = enabled
	return b
}

// WithPrefixTargetsWithHash enables or disables hash-prefixed target file names
func (b *SimulatorBuilder) WithPrefixTargetsWithHash(enabled bool) *SimulatorBuilder {
	b.prefixTargetsWithHash = enabled
	return b
}

// WithTarget adds a target file to the repository
func (b *SimulatorBuilder) WithTarget(path string, content []byte) *SimulatorBuilder {
	b.targets[path] = content
	return b
}

// WithTargets adds multiple target files to the repository
func (b *SimulatorBuilder) WithTargets(targets map[string][]byte) *SimulatorBuilder {
	for path, content := range targets {
		b.targets[path] = content
	}
	return b
}

// WithExpiredRole marks a role's metadata as expired
func (b *SimulatorBuilder) WithExpiredRole(role string) *SimulatorBuilder {
	b.expiredRoles[role] = true
	return b
}

// WithVersion sets the version for a specific role
func (b *SimulatorBuilder) WithVersion(role string, version int64) *SimulatorBuilder {
	b.roleVersions[role] = version
	return b
}

// WithoutSigners removes signers for a role (for testing unsigned metadata)
func (b *SimulatorBuilder) WithoutSigners(role string) *SimulatorBuilder {
	b.unsignedRoles[role] = true
	return b
}

// WithDelegation adds a delegated targets role
func (b *SimulatorBuilder) WithDelegation(delegatorName string, role metadata.DelegatedRole, targets metadata.TargetsType) *SimulatorBuilder {
	b.delegations = append(b.delegations, DelegationSpec{
		DelegatorName: delegatorName,
		Role:          role,
		Targets:       targets,
	})
	return b
}

// WithSuccinctRoles adds succinct roles to a delegator
func (b *SimulatorBuilder) WithSuccinctRoles(delegatorName string, bitLength int, namePrefix string) *SimulatorBuilder {
	b.succinctRoles[delegatorName] = succinctRoleSpec{
		bitLength:  bitLength,
		namePrefix: namePrefix,
	}
	return b
}

// WithRootRotations performs the specified number of root rotations
func (b *SimulatorBuilder) WithRootRotations(count int) *SimulatorBuilder {
	b.rootRotations = count
	return b
}

// WithTimestampVersionBump bumps the timestamp version by the specified amount
func (b *SimulatorBuilder) WithTimestampVersionBump(bump int64) *SimulatorBuilder {
	b.timestampVersionBump = bump
	return b
}

// WithSnapshotVersionBump bumps the snapshot version by the specified amount
func (b *SimulatorBuilder) WithSnapshotVersionBump(bump int64) *SimulatorBuilder {
	b.snapshotVersionBump = bump
	return b
}

// WithTargetsVersionBump bumps the targets version by the specified amount
func (b *SimulatorBuilder) WithTargetsVersionBump(bump int64) *SimulatorBuilder {
	b.targetsVersionBump = bump
	return b
}

// Build creates the configured RepositorySimulator
func (b *SimulatorBuilder) Build(t *testing.T) *RepositorySimulator {
	t.Helper()

	sim := NewRepository()

	// Configure consistent snapshot
	sim.MDRoot.Signed.ConsistentSnapshot = b.consistentSnapshot
	sim.PrefixTargetsWithHash = b.prefixTargetsWithHash
	sim.ComputeMetafileHashesAndLength = b.computeHashesAndLength

	// Set expiry time
	now := time.Now().UTC()
	safeExpiry := now.Truncate(time.Second).Add(b.expiry)
	sim.SafeExpiry = safeExpiry
	sim.MDRoot.Signed.Expires = safeExpiry
	sim.MDTargets.Signed.Expires = safeExpiry
	sim.MDSnapshot.Signed.Expires = safeExpiry
	sim.MDTimestamp.Signed.Expires = safeExpiry

	// Apply expired roles (use a past time)
	pastTime := now.Add(-5 * 24 * time.Hour)
	for role := range b.expiredRoles {
		switch role {
		case metadata.ROOT:
			sim.MDRoot.Signed.Expires = pastTime
		case metadata.TARGETS:
			sim.MDTargets.Signed.Expires = pastTime
		case metadata.SNAPSHOT:
			sim.MDSnapshot.Signed.Expires = pastTime
		case metadata.TIMESTAMP:
			sim.MDTimestamp.Signed.Expires = pastTime
		}
	}

	// Apply version settings
	for role, version := range b.roleVersions {
		switch role {
		case metadata.ROOT:
			sim.MDRoot.Signed.Version = version
		case metadata.TARGETS:
			sim.MDTargets.Signed.Version = version
		case metadata.SNAPSHOT:
			sim.MDSnapshot.Signed.Version = version
		case metadata.TIMESTAMP:
			sim.MDTimestamp.Signed.Version = version
		}
	}

	// Apply version bumps
	if b.timestampVersionBump > 0 {
		sim.MDTimestamp.Signed.Version += b.timestampVersionBump
	}
	if b.snapshotVersionBump > 0 {
		sim.MDSnapshot.Signed.Version += b.snapshotVersionBump
	}
	if b.targetsVersionBump > 0 {
		sim.MDTargets.Signed.Version += b.targetsVersionBump
	}

	// Add targets
	for path, content := range b.targets {
		sim.AddTarget(metadata.TARGETS, content, path)
	}

	// Add delegations
	for _, delegation := range b.delegations {
		sim.AddDelegation(delegation.DelegatorName, delegation.Role, delegation.Targets)
	}

	// Add succinct roles
	for delegatorName, spec := range b.succinctRoles {
		sim.AddSuccinctRoles(delegatorName, spec.bitLength, spec.namePrefix)
	}

	// Perform root rotations
	for i := 0; i < b.rootRotations; i++ {
		sim.MDRoot.Signed.Version++
		sim.PublishRoot()
	}

	// Remove signers for unsigned roles (do this after other setup)
	for role := range b.unsignedRoles {
		delete(sim.Signers, role)
	}

	// Update snapshot and timestamp to reflect changes
	sim.UpdateSnapshot()

	return sim
}
