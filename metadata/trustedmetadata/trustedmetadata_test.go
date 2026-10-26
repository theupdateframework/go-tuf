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

package trustedmetadata

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/rsapss"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

// allRoles is the canonical set of metadata bytes loaded from the
// repository fixture by TestMain. Every Update* call in this file reads
// inputs from here.
var allRoles map[string][]byte

func setAllRolesBytes(path string) {
	log := metadata.GetLogger()

	allRoles = make(map[string][]byte)
	rootPath := filepath.Join(path, "root.json")
	root, err := os.ReadFile(rootPath)
	if err != nil {
		log.Error(err, "failed to read root bytes")
		os.Exit(1)
	}
	allRoles[metadata.ROOT] = root

	targetsPath := filepath.Join(path, "targets.json")
	targets, err := os.ReadFile(targetsPath)
	if err != nil {
		log.Error(err, "failed to read targets bytes")
		os.Exit(1)
	}
	allRoles[metadata.TARGETS] = targets

	snapshotPath := filepath.Join(path, "snapshot.json")
	snapshot, err := os.ReadFile(snapshotPath)
	if err != nil {
		log.Error(err, "failed to read snapshot bytes")
		os.Exit(1)
	}
	allRoles[metadata.SNAPSHOT] = snapshot

	timestampPath := filepath.Join(path, "timestamp.json")
	timestamp, err := os.ReadFile(timestampPath)
	if err != nil {
		log.Error(err, "failed to read timestamp bytes")
		os.Exit(1)
	}
	allRoles[metadata.TIMESTAMP] = timestamp

	role1Path := filepath.Join(path, "role1.json")
	role1, err := os.ReadFile(role1Path)
	if err != nil {
		log.Error(err, "failed to read role1 bytes")
		os.Exit(1)
	}
	allRoles["role1"] = role1

	role2Path := filepath.Join(path, "role2.json")
	role2, err := os.ReadFile(role2Path)
	if err != nil {
		log.Error(err, "failed to read role2 bytes")
		os.Exit(1)
	}
	allRoles["role2"] = role2
}

func TestMain(m *testing.M) {
	log := metadata.GetLogger()

	repoPath := "../../internal/testutils/repository_data/repository/metadata"
	keystorePath := "../../internal/testutils/repository_data/keystore"
	targetsPath := "../../internal/testutils/repository_data/repository/targets"
	err := testutils.SetupTestDirs(repoPath, targetsPath, keystorePath)
	defer testutils.Cleanup()

	if err != nil {
		log.Error(err, "failed to setup test dirs")
		os.Exit(1)
	}
	setAllRolesBytes(testutils.RepoDir)
	m.Run()
}

// modifyRootMetadata returns the canonical root.json mutated by fn and
// re-signed with the fixture root key. The mirror helpers below do the
// same for the other top-level roles.
type modifyRoot func(*metadata.Metadata[metadata.RootType])

func modifyRootMetadata(fn modifyRoot) ([]byte, error) {
	log := metadata.GetLogger()

	root, err := metadata.Root().FromBytes(allRoles[metadata.ROOT])
	if err != nil {
		log.Error(err, "failed to create root metadata from bytes")
	}
	fn(root)

	signer, err := rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "root_key"))
	if err != nil {
		log.Error(err, "failed to load signer from pem file")
	}
	root.ClearSignatures()
	_, err = root.Sign(signer)
	if err != nil {
		log.Error(err, "failed to sign root")
	}
	return root.ToBytes(true)
}

type modifyTimestamp func(*metadata.Metadata[metadata.TimestampType])

func modifyTimestamptMetadata(fn modifyTimestamp) ([]byte, error) {
	log := metadata.GetLogger()

	timestamp, err := metadata.Timestamp().FromBytes(allRoles[metadata.TIMESTAMP])
	if err != nil {
		log.Error(err, "failed to create timestamp metadata from bytes")
	}
	fn(timestamp)

	signer, err := rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "timestamp_key"))
	if err != nil {
		log.Error(err, "failed to load signer from pem file")
	}
	timestamp.ClearSignatures()
	_, err = timestamp.Sign(signer)
	if err != nil {
		log.Error(err, "failed to sign timestamp")
	}
	return timestamp.ToBytes(true)
}

type modifySnapshot func(*metadata.Metadata[metadata.SnapshotType])

func modifySnapshotMetadata(fn modifySnapshot) ([]byte, error) {
	log := metadata.GetLogger()

	snapshot, err := metadata.Snapshot().FromBytes(allRoles[metadata.SNAPSHOT])
	if err != nil {
		log.Error(err, "failed to create snapshot metadata from bytes")
	}
	fn(snapshot)

	signer, err := rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "snapshot_key"))
	if err != nil {
		log.Error(err, "failed to load signer from pem file")
	}
	snapshot.ClearSignatures()
	_, err = snapshot.Sign(signer)
	if err != nil {
		log.Error(err, "failed to sign snapshot")
	}
	return snapshot.ToBytes(true)
}

type modifyTargets func(*metadata.Metadata[metadata.TargetsType])

func modifyTargetsMetadata(fn modifyTargets) ([]byte, error) {
	log := metadata.GetLogger()

	targets, err := metadata.Targets().FromBytes(allRoles[metadata.TARGETS])
	if err != nil {
		log.Error(err, "failed to create targets metadata from bytes")
	}
	fn(targets)

	signer, err := rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "targets_key"))
	if err != nil {
		log.Error(err, "failed to load signer from pem file")
	}
	targets.ClearSignatures()
	_, err = targets.Sign(signer)
	if err != nil {
		log.Error(err, "failed to sign targets")
	}
	return targets.ToBytes(true)
}

// updateAllBesidesTargets loads timestamp and snapshot onto trustedSet,
// substituting the canonical fixtures for empty inputs. Used by the
// targets-focused subtests to set up a state where only the targets
// update remains.
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

// newTrustedSetT is a small require-style helper: construct a fresh
// TrustedMetadata from the canonical root fixture or fail the test.
func newTrustedSetT(t *testing.T) *TrustedMetadata {
	t.Helper()
	ts, err := New(allRoles[metadata.ROOT])
	require.NoError(t, err)
	return ts
}

// expectErr asserts the test's expectation about err. Order:
//   - errIs (errors.Is)
//   - errContains (substring)
//   - nil (no error expected)
func expectErr(t *testing.T, err error, errIs error, errContains string) {
	t.Helper()
	switch {
	case errIs != nil:
		assert.ErrorIs(t, err, errIs)
	case errContains != "":
		assert.ErrorContains(t, err, errContains)
	default:
		assert.NoError(t, err)
	}
}

// TestUpdateFlowTable covers TestUpdate (happy path) and TestOutOfOrderOps
// (the ordering rules) via a single sequenced table. Each case is a list of
// (action, input, expectErr) tuples that we apply in order to a fresh
// TrustedMetadata.
func TestUpdateFlowTable(t *testing.T) {
	type step struct {
		op          string // root|timestamp|snapshot|targets|delegated
		input       string // role name (e.g. metadata.ROOT, "role1") to pull from allRoles
		role        string // delegated role name, only for op=="delegated"
		delegator   string // delegator role name, only for op=="delegated"
		errIs       error
		errContains string
	}
	apply := func(t *testing.T, ts *TrustedMetadata, s step) error {
		t.Helper()
		switch s.op {
		case "root":
			_, err := ts.UpdateRoot(allRoles[s.input])
			return err
		case "timestamp":
			_, err := ts.UpdateTimestamp(allRoles[s.input])
			return err
		case "snapshot":
			_, err := ts.UpdateSnapshot(allRoles[s.input], false)
			return err
		case "targets":
			_, err := ts.UpdateTargets(allRoles[s.input])
			return err
		case "delegated":
			_, err := ts.UpdateDelegatedTargets(allRoles[s.input], s.role, s.delegator)
			return err
		}
		t.Fatalf("unknown op %q", s.op)
		return nil
	}

	tests := []struct {
		name  string
		steps []step
		// finalCheck is run after all steps have been applied.
		finalCheck func(t *testing.T, ts *TrustedMetadata)
	}{
		{
			name: "happy path: root -> timestamp -> snapshot -> targets -> delegated chain",
			steps: []step{
				{op: "timestamp", input: metadata.TIMESTAMP},
				{op: "snapshot", input: metadata.SNAPSHOT},
				{op: "targets", input: metadata.TARGETS},
				{op: "delegated", input: "role1", role: "role1", delegator: metadata.TARGETS},
				{op: "delegated", input: "role2", role: "role2", delegator: "role1"},
			},
			finalCheck: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				assert.NotNil(t, ts.Root)
				assert.NotNil(t, ts.Timestamp)
				assert.NotNil(t, ts.Snapshot)
				assert.NotNil(t, ts.Targets)
			},
		},
		{
			name: "out of order: snapshot before timestamp / root after timestamp / targets before snapshot / timestamp after snapshot / delegated before targets / snapshot after targets",
			steps: []step{
				{op: "snapshot", input: metadata.SNAPSHOT, errIs: &metadata.ErrRuntime{Msg: "cannot update snapshot before timestamp"}},
				{op: "timestamp", input: metadata.TIMESTAMP},
				{op: "root", input: metadata.ROOT, errIs: &metadata.ErrRuntime{Msg: "cannot update root after timestamp"}},
				{op: "targets", input: metadata.TARGETS, errIs: &metadata.ErrRuntime{Msg: "cannot load targets before snapshot"}},
				{op: "snapshot", input: metadata.SNAPSHOT},
				{op: "timestamp", input: metadata.TIMESTAMP, errIs: &metadata.ErrRuntime{Msg: "cannot update timestamp after snapshot"}},
				{op: "delegated", input: "role1", role: "role1", delegator: metadata.TARGETS, errIs: &metadata.ErrRuntime{Msg: "cannot load targets before delegator"}},
				{op: "targets", input: metadata.TARGETS},
				{op: "snapshot", input: metadata.SNAPSHOT, errIs: &metadata.ErrRuntime{Msg: "cannot update snapshot after targets"}},
				{op: "delegated", input: "role1", role: "role1", delegator: metadata.TARGETS},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTrustedSetT(t)
			for i, s := range tt.steps {
				err := apply(t, ts, s)
				expectErr(t, err, s.errIs, s.errContains)
				_ = i
			}
			if tt.finalCheck != nil {
				tt.finalCheck(t, ts)
			}
		})
	}
}

// TestUpdateRootTable covers UpdateRoot scenarios:
//   - happy path with bumped version
//   - threshold bumped without enough sigs
//   - same version as trusted
//   - invalid JSON (empty / unsigned-bump / wrong type)
// Plus the cross-cutting "intermediate root can expire, final root cannot"
// flow.
func TestUpdateRootTable(t *testing.T) {
	tests := []struct {
		name string
		// rootBytes computes the bytes passed to UpdateRoot. Built per-case
		// so each subtest gets its own derived metadata.
		rootBytes   func(t *testing.T) []byte
		errIs       error
		errContains string
	}{
		{
			name: "valid new root version",
			rootBytes: func(t *testing.T) []byte {
				t.Helper()
				b, err := modifyRootMetadata(func(r *metadata.Metadata[metadata.RootType]) {
					r.Signed.Version += 1
				})
				require.NoError(t, err)
				return b
			},
		},
		{
			name: "threshold bumped without adding signing keys",
			rootBytes: func(t *testing.T) []byte {
				t.Helper()
				b, err := modifyRootMetadata(func(r *metadata.Metadata[metadata.RootType]) {
					r.Signed.Version += 1
					r.Signed.Roles[metadata.ROOT].Threshold += 1
				})
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 1, want 2"},
		},
		{
			name: "new root version equals trusted root version",
			rootBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.ROOT]
			},
			errIs: &metadata.ErrBadVersionNumber{Msg: "bad version number, expected 2, got 1"},
		},
		{
			name: "empty input is invalid JSON",
			rootBytes: func(t *testing.T) []byte {
				t.Helper()
				return []byte("")
			},
			errContains: "unexpected end of JSON input",
		},
		{
			name: "version-bumped root with no matching signature",
			rootBytes: func(t *testing.T) []byte {
				t.Helper()
				root, err := metadata.Root().FromBytes(allRoles[metadata.ROOT])
				require.NoError(t, err)
				root.Signed.Version += 1
				b, err := root.ToBytes(true)
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrUnsignedMetadata{Msg: "Verifying root failed, not enough signatures, got 0, want 1"},
		},
		{
			name: "wrong metadata type (snapshot bytes)",
			rootBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.SNAPSHOT]
			},
			errIs: &metadata.ErrValue{Msg: "expected metadata type root, got - snapshot"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTrustedSetT(t)
			_, err := ts.UpdateRoot(tt.rootBytes(t))
			expectErr(t, err, tt.errIs, tt.errContains)
		})
	}

	// "Expired final root" exercises UpdateTimestamp, since UpdateRoot
	// allows an expired intermediate root. Keep it adjacent for proximity
	// to the other root-expiry semantics.
	t.Run("expired final root is rejected on first UpdateTimestamp", func(t *testing.T) {
		rootBytes, err := modifyRootMetadata(func(r *metadata.Metadata[metadata.RootType]) {
			r.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
		})
		require.NoError(t, err)
		ts, err := New(rootBytes)
		require.NoError(t, err)
		_, err = ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
		assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "final root.json is expired"})
	})
}

// TestUpdateTimestampTable covers UpdateTimestamp scenarios.
func TestUpdateTimestampTable(t *testing.T) {
	tests := []struct {
		name string
		// preload runs before the timestamp under test is applied. nil
		// means "no preload — apply the case input to a fresh trust set".
		preload func(t *testing.T, ts *TrustedMetadata)
		// timestampBytes returns the input bytes for the timestamp call.
		timestampBytes func(t *testing.T) []byte
		errIs          error
		errContains    string
		// finalCheck runs after the UpdateTimestamp under test.
		finalCheck func(t *testing.T, ts *TrustedMetadata, snapshotOldRef *metadata.Metadata[metadata.TimestampType])
	}{
		{
			name: "empty input is invalid JSON",
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				return []byte("")
			},
			errContains: "unexpected end of JSON input",
		},
		{
			name: "version-bumped timestamp with no matching signature",
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				ts, err := metadata.Timestamp().FromBytes(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
				ts.Signed.Version += 1
				b, err := ts.ToBytes(true)
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrUnsignedMetadata{Msg: "Verifying timestamp failed, not enough signatures, got 0, want 1"},
		},
		{
			name: "wrong metadata type (root bytes)",
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.ROOT]
			},
			errIs: &metadata.ErrValue{Msg: "expected metadata type timestamp, got - root"},
		},
		{
			name: "new timestamp version below trusted version is rejected",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				b, err := modifyTimestamptMetadata(func(meta *metadata.Metadata[metadata.TimestampType]) {
					meta.Signed.Version = 3
				})
				require.NoError(t, err)
				_, err = ts.UpdateTimestamp(b)
				require.NoError(t, err)
			},
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.TIMESTAMP]
			},
			errIs: &metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 3"},
		},
		{
			name: "same timestamp version is rejected and trusted state is preserved",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
			},
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.TIMESTAMP]
			},
			errIs: &metadata.ErrEqualVersionNumber{Msg: "new timestamp version 1 equals the old one 1"},
			finalCheck: func(t *testing.T, ts *TrustedMetadata, initial *metadata.Metadata[metadata.TimestampType]) {
				t.Helper()
				// Trusted timestamp object pointer must be unchanged.
				assert.Equal(t, initial, ts.Timestamp)
			},
		},
		{
			name: "snapshot meta version regressing below trusted is rejected",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				b, err := modifyTimestamptMetadata(func(meta *metadata.Metadata[metadata.TimestampType]) {
					meta.Signed.Meta["snapshot.json"].Version = 2
					meta.Signed.Version += 1
				})
				require.NoError(t, err)
				_, err = ts.UpdateTimestamp(b)
				require.NoError(t, err)
			},
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.TIMESTAMP]
			},
			errIs: &metadata.ErrBadVersionNumber{Msg: "new timestamp version 1 must be >= 2"},
		},
		{
			name: "expired timestamp is loaded but raises ExpiredMetadata, then blocks snapshot",
			timestampBytes: func(t *testing.T) []byte {
				t.Helper()
				b, err := modifyTimestamptMetadata(func(meta *metadata.Metadata[metadata.TimestampType]) {
					meta.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
				})
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"},
			finalCheck: func(t *testing.T, ts *TrustedMetadata, _ *metadata.Metadata[metadata.TimestampType]) {
				t.Helper()
				// Subsequent snapshot update fails with the same error.
				_, err := ts.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
				assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "timestamp.json is expired"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTrustedSetT(t)
			if tt.preload != nil {
				tt.preload(t, ts)
			}
			// Snapshot the timestamp pointer before the operation for finalCheck.
			beforeTimestamp := ts.Timestamp
			_, err := ts.UpdateTimestamp(tt.timestampBytes(t))
			expectErr(t, err, tt.errIs, tt.errContains)
			if tt.finalCheck != nil {
				tt.finalCheck(t, ts, beforeTimestamp)
			}
		})
	}
}

// TestUpdateSnapshotTable covers UpdateSnapshot scenarios. Each case
// starts from a fresh trust set with the canonical timestamp already
// loaded (unless preload overrides that).
func TestUpdateSnapshotTable(t *testing.T) {
	tests := []struct {
		name string
		// preload customises the trusted set before the UpdateSnapshot
		// under test. The default (nil) is "load the canonical timestamp".
		preload func(t *testing.T, ts *TrustedMetadata)
		// snapshotBytes returns the bytes to pass to UpdateSnapshot.
		snapshotBytes func(t *testing.T) []byte
		errIs         error
		errContains   string
		// finalCheck runs after the operation under test.
		finalCheck func(t *testing.T, ts *TrustedMetadata)
	}{
		{
			name: "empty input is invalid JSON",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				return []byte("")
			},
			errContains: "unexpected end of JSON input",
		},
		{
			name: "version-bumped snapshot with no matching signature",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				s, err := metadata.Snapshot().FromBytes(allRoles[metadata.SNAPSHOT])
				require.NoError(t, err)
				s.Signed.Version += 1
				b, err := s.ToBytes(true)
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrUnsignedMetadata{Msg: "Verifying snapshot failed, not enough signatures, got 0, want 1"},
		},
		{
			name: "wrong metadata type (root bytes)",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.ROOT]
			},
			errIs: &metadata.ErrValue{Msg: "expected metadata type snapshot, got - root"},
		},
		{
			name: "snapshot length disagrees with timestamp meta",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				b, err := modifyTimestamptMetadata(func(meta *metadata.Metadata[metadata.TimestampType]) {
					meta.Signed.Meta["snapshot.json"].Length = 1
				})
				require.NoError(t, err)
				_, err = ts.UpdateTimestamp(b)
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.SNAPSHOT]
			},
			errIs: &metadata.ErrLengthOrHashMismatch{Msg: "length verification failed - expected 1, got 652"},
		},
		{
			name: "snapshot signed with cleared signatures fails threshold",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				s, err := metadata.Snapshot().FromBytes(allRoles[metadata.SNAPSHOT])
				require.NoError(t, err)
				s.ClearSignatures()
				b, err := s.ToBytes(true)
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrUnsignedMetadata{Msg: "Verifying snapshot failed, not enough signatures, got 0, want 1"},
		},
		{
			name: "snapshot version disagrees with timestamp meta blocks targets too",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				b, err := modifyTimestamptMetadata(func(meta *metadata.Metadata[metadata.TimestampType]) {
					meta.Signed.Meta["snapshot.json"].Version = 2
				})
				require.NoError(t, err)
				_, err = ts.UpdateTimestamp(b)
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.SNAPSHOT]
			},
			errIs: &metadata.ErrBadVersionNumber{Msg: "expected 2, got 1"},
			finalCheck: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTargets(allRoles[metadata.TARGETS])
				assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "expected 2, got 1"})
			},
		},
		{
			name: "new snapshot drops a meta entry present in trusted snapshot",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				err := updateAllBesidesTargets(ts, allRoles[metadata.TIMESTAMP], nil)
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				b, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
					delete(s.Signed.Meta, "targets.json")
				})
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrRepository{Msg: "new snapshot is missing info for targets.json"},
		},
		{
			name: "new snapshot's meta version regresses below trusted",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
				b, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
					s.Signed.Meta["targets.json"].Version += 1
				})
				require.NoError(t, err)
				_, err = ts.UpdateSnapshot(b, false)
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.SNAPSHOT]
			},
			errIs: &metadata.ErrBadVersionNumber{Msg: "expected targets.json version 1, got 2"},
		},
		{
			name: "expired snapshot is loaded but raises ExpiredMetadata, then blocks targets",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
				require.NoError(t, err)
			},
			snapshotBytes: func(t *testing.T) []byte {
				t.Helper()
				b, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
					s.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
				})
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrExpiredMetadata{Msg: "snapshot.json is expired"},
			finalCheck: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				_, err := ts.UpdateTargets(allRoles[metadata.TARGETS])
				assert.ErrorIs(t, err, &metadata.ErrExpiredMetadata{Msg: "snapshot.json is expired"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTrustedSetT(t)
			if tt.preload != nil {
				tt.preload(t, ts)
			}
			_, err := ts.UpdateSnapshot(tt.snapshotBytes(t), false)
			expectErr(t, err, tt.errIs, tt.errContains)
			if tt.finalCheck != nil {
				tt.finalCheck(t, ts)
			}
		})
	}

	// Rollback flow is a multi-step assertion that doesn't fit the
	// single-input table cleanly. Keep it as a dedicated subtest in this
	// file so all snapshot scenarios live together.
	t.Run("rollback flow: load local snapshot with mismatching version, then update to newer", func(t *testing.T) {
		ts := newTrustedSetT(t)
		_, err := ts.UpdateTimestamp(allRoles[metadata.TIMESTAMP])
		require.NoError(t, err)

		bumpedTimestamp, err := modifyTimestamptMetadata(func(meta *metadata.Metadata[metadata.TimestampType]) {
			meta.Signed.Meta["snapshot.json"].Version += 1
			meta.Signed.Version += 1
		})
		require.NoError(t, err)
		_, err = ts.UpdateTimestamp(bumpedTimestamp)
		require.NoError(t, err)

		// Local snapshot (version 1) is loaded but raises bad-version.
		_, err = ts.UpdateSnapshot(allRoles[metadata.SNAPSHOT], false)
		assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{Msg: "expected 2, got 1"})

		// New snapshot (version 2) succeeds.
		newSnapshot, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
			s.Signed.Version += 1
		})
		require.NoError(t, err)
		_, err = ts.UpdateSnapshot(newSnapshot, false)
		assert.NoError(t, err)

		// Targets update triggers the final snapshot meta version check.
		_, err = ts.UpdateTargets(allRoles[metadata.TARGETS])
		assert.NoError(t, err)
	})
}

// TestUpdateTargetsTable covers UpdateTargets scenarios. Each case
// preloads canonical timestamp + snapshot (customisable via preload).
func TestUpdateTargetsTable(t *testing.T) {
	tests := []struct {
		name          string
		preload       func(t *testing.T, ts *TrustedMetadata)
		targetsBytes  func(t *testing.T) []byte
		errIs         error
		errContains   string
	}{
		{
			name: "empty input is invalid JSON",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				err := updateAllBesidesTargets(ts, nil, nil)
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				return []byte("")
			},
			errContains: "unexpected end of JSON input",
		},
		{
			name: "version-bumped targets with no matching signature",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				err := updateAllBesidesTargets(ts, nil, nil)
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				tg, err := metadata.Targets().FromBytes(allRoles[metadata.TARGETS])
				require.NoError(t, err)
				tg.Signed.Version += 1
				b, err := tg.ToBytes(true)
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrUnsignedMetadata{Msg: "Verifying targets failed, not enough signatures, got 0, want 1"},
		},
		{
			name: "wrong metadata type (root bytes)",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				err := updateAllBesidesTargets(ts, nil, nil)
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.ROOT]
			},
			errIs: &metadata.ErrValue{Msg: "expected metadata type targets, got - root"},
		},
		{
			name: "snapshot has no meta entry for targets",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				cleared, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
					for k := range s.Signed.Meta {
						delete(s.Signed.Meta, k)
					}
				})
				require.NoError(t, err)
				err = updateAllBesidesTargets(ts, allRoles[metadata.TIMESTAMP], cleared)
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.TARGETS]
			},
			errIs: &metadata.ErrRepository{Msg: "snapshot does not contain information for targets"},
		},
		{
			name: "targets length disagrees with snapshot meta",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				broken, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
					for p := range s.Signed.Meta {
						s.Signed.Meta[p] = &metadata.MetaFiles{Version: 1, Length: 1}
					}
				})
				require.NoError(t, err)
				err = updateAllBesidesTargets(ts, allRoles[metadata.TIMESTAMP], broken)
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.TARGETS]
			},
			errIs: &metadata.ErrLengthOrHashMismatch{Msg: "length verification failed - expected 1, got 1266"},
		},
		{
			name: "targets version disagrees with snapshot meta version",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				bumped, err := modifySnapshotMetadata(func(s *metadata.Metadata[metadata.SnapshotType]) {
					for p := range s.Signed.Meta {
						s.Signed.Meta[p] = &metadata.MetaFiles{Version: 2}
					}
				})
				require.NoError(t, err)
				err = updateAllBesidesTargets(ts, allRoles[metadata.TIMESTAMP], bumped)
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				return allRoles[metadata.TARGETS]
			},
			errIs: &metadata.ErrBadVersionNumber{Msg: "expected targets version 2, got 1"},
		},
		{
			name: "new targets is expired",
			preload: func(t *testing.T, ts *TrustedMetadata) {
				t.Helper()
				err := updateAllBesidesTargets(ts, allRoles[metadata.TIMESTAMP], allRoles[metadata.SNAPSHOT])
				require.NoError(t, err)
			},
			targetsBytes: func(t *testing.T) []byte {
				t.Helper()
				b, err := modifyTargetsMetadata(func(tg *metadata.Metadata[metadata.TargetsType]) {
					tg.Signed.Expires = time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
				})
				require.NoError(t, err)
				return b
			},
			errIs: &metadata.ErrExpiredMetadata{Msg: "new targets is expired"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := newTrustedSetT(t)
			if tt.preload != nil {
				tt.preload(t, ts)
			}
			_, err := ts.UpdateTargets(tt.targetsBytes(t))
			expectErr(t, err, tt.errIs, tt.errContains)
		})
	}
}
