// Copyright 2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

package trustedmetadata

import (
	"crypto"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/testutils/testutils"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/maps"
)

var allRoles map[string][]byte

func setAllRolesBytes(path string) {
	allRoles = make(map[string][]byte)
	root, err := os.ReadFile(fmt.Sprintf("%s/root.json", path))
	if err != nil {
		log.Fatalf("failed to root bytes: %v", err)
	}
	allRoles[metadata.ROOT] = root
	targets, err := os.ReadFile(fmt.Sprintf("%s/targets.json", path))
	if err != nil {
		log.Fatalf("failed to targets bytes: %v", err)
	}
	allRoles[metadata.TARGETS] = targets
	snapshot, err := os.ReadFile(fmt.Sprintf("%s/snapshot.json", path))
	if err != nil {
		log.Fatalf("failed to snapshot bytes: %v", err)
	}
	allRoles[metadata.SNAPSHOT] = snapshot
	timestamp, err := os.ReadFile(fmt.Sprintf("%s/timestamp.json", path))
	if err != nil {
		log.Fatalf("failed to timestamp bytes: %v", err)
	}
	allRoles[metadata.TIMESTAMP] = timestamp
	role1, err := os.ReadFile(fmt.Sprintf("%s/role1.json", path))
	if err != nil {
		log.Fatalf("failed to role1 bytes: %v", err)
	}
	allRoles["role1"] = role1
	role2, err := os.ReadFile(fmt.Sprintf("%s/role2.json", path))
	if err != nil {
		log.Fatalf("failed to role2 bytes: %v", err)
	}
	allRoles["role2"] = role2
}

func TestMain(m *testing.M) {

	repoPath := "../../testutils/repository_data/repository/metadata"
	keystorePath := "../../testutils/repository_data/keystore"
	targetsPath := "../../testutils/repository_data/repository/targets"
	err := testutils.SetupTestDirs(repoPath, targetsPath, keystorePath)
	defer testutils.Cleanup()

	if err != nil {
		log.Fatalf("failed to setup test dirs: %v", err)
	}
	setAllRolesBytes(testutils.RepoDir)
	m.Run()
}

type modifyRoot func(*metadata.Metadata[metadata.RootType])

func modifyRootMetadata(fn modifyRoot) ([]byte, error) {
	root, err := metadata.Root().FromBytes(allRoles[metadata.ROOT])
	if err != nil {
		log.Debugf("failed to create root metadata from bytes: %v", err)
	}
	fn(root)

	signer, err := signature.LoadSignerFromPEMFile(testutils.KeystoreDir+"/root_key", crypto.SHA256, cryptoutils.SkipPassword)
	if err != nil {
		log.Debugf("failed to load signer from pem file: %v", err)
	}
	root.ClearSignatures()
	_, err = root.Sign(signer)
	if err != nil {
		log.Debugf("failed to sign root: %v", err)
	}
	return root.ToBytes(true)
}

type modifyTimestamp func(*metadata.Metadata[metadata.TimestampType])

func modifyTimestamptMetadata(fn modifyTimestamp) ([]byte, error) {
	timestamp, err := metadata.Timestamp().FromBytes(allRoles[metadata.TIMESTAMP])
	if err != nil {
		log.Debugf("failed to create timestamp metadata from bytes: %v", err)
	}
	fn(timestamp)

	signer, err := signature.LoadSignerFromPEMFile(testutils.KeystoreDir+"/timestamp_key", crypto.SHA256, cryptoutils.SkipPassword)
	if err != nil {
		log.Debugf("failed to load signer from pem file: %v", err)
	}
	timestamp.ClearSignatures()
	_, err = timestamp.Sign(signer)
	if err != nil {
		log.Debugf("failed to sign timestamp: %v", err)
	}
	return timestamp.ToBytes(true)
}

type modifySnapshot func(*metadata.Metadata[metadata.SnapshotType])

func modifySnapshotMetadata(fn modifySnapshot) ([]byte, error) {
	snapshot, err := metadata.Snapshot().FromBytes(allRoles[metadata.SNAPSHOT])
	if err != nil {
		log.Debugf("failed to create snapshot metadata from bytes: %v", err)
	}
	fn(snapshot)

	signer, err := signature.LoadSignerFromPEMFile(testutils.KeystoreDir+"/snapshot_key", crypto.SHA256, cryptoutils.SkipPassword)
	if err != nil {
		log.Debugf("failed to load signer from pem file: %v", err)
	}
	snapshot.ClearSignatures()
	_, err = snapshot.Sign(signer)
	if err != nil {
		log.Debugf("failed to sign snapshot: %v", err)
	}
	return snapshot.ToBytes(true)
}

type modifyTargets func(*metadata.Metadata[metadata.TargetsType])

func modifyTargetsMetadata(fn modifyTargets) ([]byte, error) {
	targets, err := metadata.Targets().FromBytes(allRoles[metadata.TARGETS])
	if err != nil {
		log.Debugf("failed to create targets metadata from bytes: %v", err)
	}
	fn(targets)

	signer, err := signature.LoadSignerFromPEMFile(testutils.KeystoreDir+"/targets_key", crypto.SHA256, cryptoutils.SkipPassword)
	if err != nil {
		log.Debugf("failed to load signer from pem file: %v", err)
	}
	targets.ClearSignatures()
	_, err = targets.Sign(signer)
	if err != nil {
		log.Debugf("failed to sign targets: %v", err)
	}
	return targets.ToBytes(true)
}

func TestUpdate(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateDelegatedTargets(allRoles["role1"], "role1", metadata.TARGETS)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateDelegatedTargets(allRoles["role2"], "role2", "role1")
	assert.NoError(t, err)

	// The 4 top level metadata objects + 2 additional delegated targets
	// self.assertTrue(len(self.trusted_set), 6)
	assert.NotNil(t, trustedSet.Root)
	assert.NotNil(t, trustedSet.Timestamp)
	assert.NotNil(t, trustedSet.Snapshot)
	assert.NotNil(t, trustedSet.Targets)
}

func TestOutOfOrderOps(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)

	//  Update snapshot before timestamp
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrRuntime{Msg: "cannot update snapshot before timestamp"})

	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)

	// Update root after timestamp
	_, err = trustedSet.UpdateRoot(allRoles[metadata.ROOT])
	assert.ErrorIs(t, err, metadata.ErrRuntime{Msg: "cannot update root after timestamp"})

	// Update targets before snapshot
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.ErrorIs(t, err, metadata.ErrRuntime{Msg: "cannot load targets before snapshot"})

	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.NoError(t, err)

	// Update timestamp after snapshot
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.ErrorIs(t, err, metadata.ErrRuntime{Msg: "cannot update timestamp after snapshot"})

	// Update delegated targets before targets
	_, err = trustedSet.UpdateDelegatedTargets(allRoles["role1"], "role1", metadata.TARGETS)
	assert.ErrorIs(t, err, metadata.ErrRuntime{Msg: "cannot load targets before delegator"})

	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.NoError(t, err)

	//  Update snapshot after sucessful targets update
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrRuntime{Msg: "cannot update snapshot after targets"})

	_, err = trustedSet.UpdateDelegatedTargets(allRoles["role1"], "role1", metadata.TARGETS)
	assert.NoError(t, err)
}

func TestRootWithInvalidJson(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)

	// Test loading initial root and root update

	// root is not json
	_, err = trustedSet.UpdateRoot([]byte(""))
	assert.ErrorContains(t, err, "unexpected end of JSON input")

	// root is not valid
	root, err := metadata.Root().FromBytes(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	root.Signed.Version += 1
	rootBytes, err := root.ToBytes(true)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateRoot(rootBytes)
	assert.ErrorIs(t, err, metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 0, want 1"})

	// metadata is of wrong type
	_, err = trustedSet.UpdateRoot(allRoles[metadata.SNAPSHOT])
	assert.ErrorIs(t, err, metadata.ErrValue{Msg: "expected metadata type root, got - snapshot"})
}

func TestTopLevelMetadataWithInvalidJSON(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)

	//TIMESTAMP
	// timestamp is not json
	_, err = trustedSet.UpdateTimestamp([]byte(""))
	assert.ErrorContains(t, err, "unexpected end of JSON input")

	// timestamp is not valid
	timestamp, err := metadata.Timestamp().FromBytes(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)
	properTimestampBytes, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	timestamp.Signed.Version += 1
	timestampBytes, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(timestampBytes)
	assert.ErrorIs(t, err, metadata.ErrUnsignedMetadata{Msg: "Verifying timestamp failed, not enough signatures, got 0, want 1"})

	// timestamp is of wrong type
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.ROOT])
	assert.ErrorIs(t, err, metadata.ErrValue{Msg: "expected metadata type timestamp, got - root"})

	// SNAPSHOT
	_, err = trustedSet.UpdateTimestamp(properTimestampBytes)
	assert.NoError(t, err)
	// snapshot is not json
	_, err = trustedSet.UpdateSnapshot([]byte(""), false)
	assert.ErrorContains(t, err, "unexpected end of JSON input")

	// snapshot is not valid
	snapshot, err := metadata.Snapshot().FromBytes(allRoles[metadata.SNAPSHOT])
	assert.NoError(t, err)
	properSnapshotBytes, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	snapshot.Signed.Version += 1
	snapshotBytes, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(snapshotBytes, false)
	assert.ErrorIs(t, err, metadata.ErrUnsignedMetadata{Msg: "Verifying snapshot failed, not enough signatures, got 0, want 1"})

	// snapshot is of wrong type
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.ROOT], false)
	assert.ErrorIs(t, err, metadata.ErrValue{Msg: "expected metadata type snapshot, got - root"})

	// TARGETS
	_, err = trustedSet.UpdateSnapshot(properSnapshotBytes, false)
	assert.NoError(t, err)
	// targets is not json
	_, err = trustedSet.UpdateTargets([]byte(""))
	assert.ErrorContains(t, err, "unexpected end of JSON input")

	// targets is not valid
	targets, err := metadata.Targets().FromBytes(allRoles[metadata.TARGETS])
	assert.NoError(t, err)
	targets.Signed.Version += 1
	targetsBytes, err := targets.ToBytes(true)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTargets(targetsBytes)
	assert.ErrorIs(t, err, metadata.ErrUnsignedMetadata{Msg: "Verifying targets failed, not enough signatures, got 0, want 1"})

	// targets is of wrong type
	_, err = trustedSet.UpdateTargets(allRoles[metadata.ROOT])
	assert.ErrorIs(t, err, metadata.ErrValue{Msg: "expected metadata type targets, got - root"})
}

func TestUpdateRootNewRoot(t *testing.T) {
	// Test that root can be updated with a new valid version
	modifyRootVersion := func(root *metadata.Metadata[metadata.RootType]) {
		root.Signed.Version += 1
	}

	root, err := modifyRootMetadata(modifyRootVersion)
	assert.NoError(t, err)

	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateRoot(root)
	assert.NoError(t, err)
}

func TestUpdateRootNewRootFailTreshholdVerification(t *testing.T) {
	// Increase threshold in new root, do not add enough keys
	bumpRootThreshold := func(root *metadata.Metadata[metadata.RootType]) {
		root.Signed.Version += 1
		root.Signed.Roles[metadata.ROOT].Threshold += 1
	}
	root, err := modifyRootMetadata(bumpRootThreshold)
	assert.NoError(t, err)

	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateRoot(root)
	assert.ErrorIs(t, err, metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 1, want 2"})
}

func TestUpdateRootNewRootVerSameAsTrustedRootVer(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)

	_, err = trustedSet.UpdateRoot(allRoles[metadata.ROOT])
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "bad version number, expected 2, got 1"})
}

func TestRootExpiredFinalRoot(t *testing.T) {
	// test that root can be updated with a new valid version
	modifyRootExpiry := func(root *metadata.Metadata[metadata.RootType]) {
		root.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}

	// Intermediate root can be expired
	root, err := modifyRootMetadata(modifyRootExpiry)
	assert.NoError(t, err)
	trustedSet, err := New(root)
	assert.NoError(t, err)

	// Update timestamp to trigger final root expiry check
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.ErrorIs(t, err, metadata.ErrExpiredMetadata{Msg: "final root.json is expired"})
}

func TestUpdateTimestampNewTimestampVerBelowTrustedVer(t *testing.T) {
	// newTimestamp.Version < trustedTimestamp.Version
	modifyTimestampVersion := func(timestamp *metadata.Metadata[metadata.TimestampType]) {
		timestamp.Signed.Version = 3
	}
	timestamp, err := modifyTimestamptMetadata(modifyTimestampVersion)
	assert.NoError(t, err)

	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(timestamp)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 3"})
}

func TestUpdateTimestampWithSameTimestamp(t *testing.T) {
	// Test that timestamp is NOT updated if:
	// newTimestamp.Version = trustedTimestamp.Version
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)

	initialTimestamp := trustedSet.Timestamp
	// Update timestamp with the same version.
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	// EqualVersionNumberError
	assert.ErrorIs(t, err, metadata.ErrEqualVersionNumber{Msg: "new timestamp version 1 equals the old one 1"})

	// Verify that the timestamp object was not updated.
	assert.Equal(t, initialTimestamp, trustedSet.Timestamp)
}

func TestUpdateTimestampSnapshotCerBellowCurrent(t *testing.T) {
	bumpSnapshotVersion := func(timestamp *metadata.Metadata[metadata.TimestampType]) {
		timestamp.Signed.Meta["snapshot.json"].Version = 2
		// The timestamp version must be increased to initiate a update.
		timestamp.Signed.Version += 1
	}
	// Set current known snapshot.json version to 2
	timestamp, err := modifyTimestamptMetadata(bumpSnapshotVersion)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(timestamp)
	assert.NoError(t, err)

	// new timestamp meta version < trusted timestamp meta version
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 2"})
}

func TestUpdateTimestampExpired(t *testing.T) {
	// New timestamp has expired
	modifyTimestampExpiry := func(timestamp *metadata.Metadata[metadata.TimestampType]) {
		timestamp.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	// Expired intermediate timestamp is loaded but raises ExpiredMetadataError
	timestamp, err := modifyTimestamptMetadata(modifyTimestampExpiry)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(timestamp)
	assert.ErrorIs(t, err, metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"})
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"})
}

func TestUpdateSnapshotLengthOrHashMismatch(t *testing.T) {
	modifySnapshotLength := func(timestamp *metadata.Metadata[metadata.TimestampType]) {
		timestamp.Signed.Meta["snapshot.json"].Length = 1
	}
	// Set known snapshot.json length to 1
	timestamp, err := modifyTimestamptMetadata(modifySnapshotLength)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(timestamp)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrLengthOrHashMismatch{Msg: "length verification failed - expected 1, got 652"})
}

func TestUpdateSnapshotFailThreshholdVerification(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)

	snapshot, err := metadata.Snapshot().FromBytes(allRoles[metadata.SNAPSHOT])
	assert.NoError(t, err)
	snapshot.ClearSignatures()
	snapshotBytes, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(snapshotBytes, false)
	assert.ErrorIs(t, err, metadata.ErrUnsignedMetadata{Msg: "Verifying snapshot failed, not enough signatures, got 0, want 1"})
}

func TestUpdateSnapshotVersionDivergeTimestampSnapshotVersion(t *testing.T) {
	modifyTimestampVersion := func(timestamp *metadata.Metadata[metadata.TimestampType]) {
		timestamp.Signed.Meta["snapshot.json"].Version = 2
	}
	timestamp, err := modifyTimestamptMetadata(modifyTimestampVersion)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(timestamp)
	assert.NoError(t, err)

	// If intermediate snapshot version is incorrect, load it but also raise
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "expected 2, got 1"})

	// Targets update starts but fails if snapshot version does not match
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "expected 2, got 1"})
}

// Update all metadata roles besides targets.
func updateAllBesidesTargets(trustedSet *TrustedMetadata, timestampBytes []byte, snapshotBytes []byte) error {
	if len(timestampBytes) <= 0 {
		timestampBytes = allRoles[metadata.TIMESTAMP]
	}
	_, err := trustedSet.UpdateTimestamp(timestampBytes)
	if err != nil {
		return err
	}
	if len(snapshotBytes) <= 0 {
		snapshotBytes = allRoles[metadata.SNAPSHOT]
	}
	_, err = trustedSet.UpdateSnapshot(snapshotBytes, false)
	if err != nil {
		return err
	}
	return nil
}

func TestUpdateSnapshotFileRemovedFromMeta(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	err = updateAllBesidesTargets(trustedSet, allRoles[metadata.TIMESTAMP], []byte{})
	assert.NoError(t, err)
	removeFileFromMeta := func(snaphot *metadata.Metadata[metadata.SnapshotType]) {
		delete(snaphot.Signed.Meta, "targets.json")
	}
	// Test removing a meta_file in new_snapshot compared to the old snapshot
	snapshot, err := modifySnapshotMetadata(removeFileFromMeta)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(snapshot, false)
	assert.ErrorIs(t, err, metadata.ErrRepository{Msg: "new snapshot is missing info for targets.json"})
}

func TestUpdateSnapshotMetaVersionDecreases(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)

	modifyMetaVersion := func(snaphot *metadata.Metadata[metadata.SnapshotType]) {
		snaphot.Signed.Meta["targets.json"].Version += 1
	}
	snapshot, err := modifySnapshotMetadata(modifyMetaVersion)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(snapshot, false)
	assert.NoError(t, err)

	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "expected targets.json version 1, got 2"})
}

func TestUpdateSnapshotExpiredNewSnapshot(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)

	modifySnapshotExpired := func(snaphot *metadata.Metadata[metadata.SnapshotType]) {
		snaphot.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	// Expired intermediate snapshot is loaded but will raise
	snapshot, err := modifySnapshotMetadata(modifySnapshotExpired)
	assert.NoError(t, err)

	_, err = trustedSet.UpdateSnapshot(snapshot, false)
	assert.ErrorIs(t, err, metadata.ErrExpiredMetadata{Msg: "snapshot.json is expired"})

	// Targets update does start but fails because snapshot is expired
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.ErrorIs(t, err, metadata.ErrExpiredMetadata{Msg: "snapshot.json is expired"})

}

func TestUpdateSnapshotSuccessfulRollbackChecks(t *testing.T) {
	// Load a "local" timestamp, then update to newer one:
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
	assert.NoError(t, err)

	bumpMetaVersion := func(timestamp *metadata.Metadata[metadata.TimestampType]) {
		timestamp.Signed.Meta["snapshot.json"].Version += 1
		// The timestamp version must be increased to initiate a update.
		timestamp.Signed.Version += 1
	}
	newTimestamp, err := modifyTimestamptMetadata(bumpMetaVersion)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTimestamp(newTimestamp)
	assert.NoError(t, err)

	// Load a "local" snapshot with mismatching version (loading happens but
	// ErrBadVersionNumber is raised), then update to newer one:
	_, err = trustedSet.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "expected 2, got 1"})

	bumpVersion := func(snapahot *metadata.Metadata[metadata.SnapshotType]) {
		snapahot.Signed.Version += 1
	}
	newSnapshot, err := modifySnapshotMetadata(bumpVersion)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateSnapshot(newSnapshot, false)
	assert.NoError(t, err)

	// Update targets to trigger final snapshot meta version check
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.NoError(t, err)
}

func TestUpdateTargetsMoMetaInSnapshot(t *testing.T) {

	clearMeta := func(snapahot *metadata.Metadata[metadata.SnapshotType]) {
		maps.Clear(snapahot.Signed.Meta)
	}
	snapshot, err := modifySnapshotMetadata(clearMeta)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	err = updateAllBesidesTargets(trustedSet, allRoles[metadata.TIMESTAMP], snapshot)
	assert.NoError(t, err)

	// Remove meta information with information about targets from snapshot
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.ErrorIs(t, err, metadata.ErrRepository{Msg: "snapshot does not contain information for targets"})

}

func TestUpdateTargetsHashDiverfeFromSnapshotMetaHash(t *testing.T) {
	modifyMetaLength := func(snapshot *metadata.Metadata[metadata.SnapshotType]) {
		for metafilePath := range snapshot.Signed.Meta {
			snapshot.Signed.Meta[metafilePath] = &metadata.MetaFiles{
				Version: 1,
				Length:  1,
			}
		}
	}
	snapshot, err := modifySnapshotMetadata(modifyMetaLength)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	err = updateAllBesidesTargets(trustedSet, allRoles[metadata.TIMESTAMP], snapshot)
	assert.NoError(t, err)

	// Observed hash != stored hash in snapshot meta for targets
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.ErrorIs(t, err, metadata.ErrLengthOrHashMismatch{Msg: "length verification failed - expected 1, got 1266"})
}

func TestUpdateTargetsVersionDivergeSnapshotMetaVersion(t *testing.T) {
	modifyMeta := func(snapshot *metadata.Metadata[metadata.SnapshotType]) {
		for metafilePath := range snapshot.Signed.Meta {
			snapshot.Signed.Meta[metafilePath] = &metadata.MetaFiles{Version: 2}
		}
	}
	snapshot, err := modifySnapshotMetadata(modifyMeta)
	assert.NoError(t, err)
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	err = updateAllBesidesTargets(trustedSet, allRoles[metadata.TIMESTAMP], snapshot)
	assert.NoError(t, err)

	// New delegate sigfned version != meta version stored in snapshot
	_, err = trustedSet.UpdateTargets(allRoles[metadata.TARGETS])
	assert.ErrorIs(t, err, metadata.ErrBadVersionNumber{Msg: "expected targets version 2, got 1"})
}

func TestUpdateTargetsExpiredMewTarget(t *testing.T) {
	trustedSet, err := New(allRoles[metadata.ROOT])
	assert.NoError(t, err)
	err = updateAllBesidesTargets(trustedSet, allRoles[metadata.TIMESTAMP], allRoles[metadata.SNAPSHOT])
	assert.NoError(t, err)

	// New delegated target has expired
	modifyTargetExpiry := func(targets *metadata.Metadata[metadata.TargetsType]) {
		targets.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	targets, err := modifyTargetsMetadata(modifyTargetExpiry)
	assert.NoError(t, err)
	_, err = trustedSet.UpdateTargets(targets)
	assert.ErrorIs(t, err, metadata.ErrExpiredMetadata{Msg: "new targets is expired"})
}
