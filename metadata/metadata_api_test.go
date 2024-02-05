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

package metadata

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/testutils/testutils"
)

func TestMain(m *testing.M) {

	repoPath := "../testutils/repository_data/repository/metadata"
	targetsPath := "../testutils/repository_data/repository/targets"
	keystorePath := "../testutils/repository_data/keystore"
	err := testutils.SetupTestDirs(repoPath, targetsPath, keystorePath)
	defer testutils.Cleanup()

	if err != nil {
		log.Error(err, "failed to setup test dirs")
		os.Exit(1)
	}
	m.Run()
}

func TestGenericRead(t *testing.T) {
	// Assert that it chokes correctly on an unknown metadata type
	badMetadata := "{\"signed\": {\"_type\": \"bad-metadata\"}}"
	_, err := Root().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - bad-metadata"})
	_, err = Snapshot().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - bad-metadata"})
	_, err = Targets().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - bad-metadata"})
	_, err = Timestamp().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - bad-metadata"})

	badMetadataPath := filepath.Join(testutils.RepoDir, "bad-metadata.json")
	err = os.WriteFile(badMetadataPath, []byte(badMetadata), 0644)
	assert.NoError(t, err)
	assert.FileExists(t, badMetadataPath)

	_, err = Root().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - bad-metadata"})
	_, err = Snapshot().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - bad-metadata"})
	_, err = Targets().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - bad-metadata"})
	_, err = Timestamp().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - bad-metadata"})

	err = os.RemoveAll(badMetadataPath)
	assert.NoError(t, err)
	assert.NoFileExists(t, badMetadataPath)
}

func TestGenericReadFromMismatchingRoles(t *testing.T) {
	// Test failing to load other roles from root metadata
	_, err := Snapshot().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - root"})
	_, err = Timestamp().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - root"})
	_, err = Targets().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - root"})

	// Test failing to load other roles from targets metadata
	_, err = Snapshot().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - targets"})
	_, err = Timestamp().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - targets"})
	_, err = Root().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - targets"})

	// Test failing to load other roles from timestamp metadata
	_, err = Snapshot().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type snapshot, got - timestamp"})
	_, err = Targets().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - timestamp"})
	_, err = Root().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - timestamp"})

	// Test failing to load other roles from snapshot metadata
	_, err = Targets().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type targets, got - snapshot"})
	_, err = Timestamp().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type timestamp, got - snapshot"})
	_, err = Root().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.ErrorIs(t, err, &ErrValue{"expected metadata type root, got - snapshot"})
}

func TestMDReadWriteFileExceptions(t *testing.T) {
	// Test writing to a file with bad filename
	badMetadataPath := filepath.Join(testutils.RepoDir, "bad-metadata.json")
	_, err := Root().FromFile(badMetadataPath)
	expectedErr := fs.PathError{
		Op:   "open",
		Path: badMetadataPath,
		Err:  fs.ErrNotExist,
	}
	assert.ErrorIs(t, err, expectedErr.Err)

	// Test serializing to a file with bad filename
	root := Root(fixedExpire)
	err = root.ToFile("", false)
	expectedErr = fs.PathError{
		Op:   "open",
		Path: "",
		Err:  fs.ErrNotExist,
	}
	assert.ErrorIs(t, err, expectedErr.Err)
}

func TestCompareFromBytesFromFileToBytes(t *testing.T) {
	rootPath := filepath.Join(testutils.RepoDir, "root.json")
	rootBytesWant, err := os.ReadFile(rootPath)
	assert.NoError(t, err)
	root, err := Root().FromFile(rootPath)
	assert.NoError(t, err)
	rootBytesActual, err := root.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, rootBytesWant, rootBytesActual)

	targetsPath := filepath.Join(testutils.RepoDir, "targets.json")
	targetsBytesWant, err := os.ReadFile(targetsPath)
	assert.NoError(t, err)
	targets, err := Targets().FromFile(targetsPath)
	assert.NoError(t, err)
	targetsBytesActual, err := targets.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, targetsBytesWant, targetsBytesActual)

	snapshotPath := filepath.Join(testutils.RepoDir, "snapshot.json")
	snapshotBytesWant, err := os.ReadFile(snapshotPath)
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromFile(snapshotPath)
	assert.NoError(t, err)
	snapshotBytesActual, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, snapshotBytesWant, snapshotBytesActual)

	timestampPath := filepath.Join(testutils.RepoDir, "timestamp.json")
	timestampBytesWant, err := os.ReadFile(timestampPath)
	assert.NoError(t, err)
	timestamp, err := Timestamp().FromFile(timestampPath)
	assert.NoError(t, err)
	timestampBytesActual, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, timestampBytesWant, timestampBytesActual)
}

func TestRootReadWriteReadCompare(t *testing.T) {
	src := filepath.Join(testutils.RepoDir, "root.json")
	srcRoot, err := Root().FromFile(src)
	assert.NoError(t, err)

	dst := src + ".tmp"
	err = srcRoot.ToFile(dst, false)
	assert.NoError(t, err)

	dstRoot, err := Root().FromFile(dst)
	assert.NoError(t, err)

	srcBytes, err := srcRoot.ToBytes(false)
	assert.NoError(t, err)
	dstBytes, err := dstRoot.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, srcBytes, dstBytes)

	err = os.RemoveAll(dst)
	assert.NoError(t, err)
}

func TestSnapshotReadWriteReadCompare(t *testing.T) {
	path1 := filepath.Join(testutils.RepoDir, "snapshot.json")
	snaphot1, err := Snapshot().FromFile(path1)
	assert.NoError(t, err)

	path2 := path1 + ".tmp"
	err = snaphot1.ToFile(path2, false)
	assert.NoError(t, err)

	snapshot2, err := Snapshot().FromFile(path2)
	assert.NoError(t, err)

	bytes1, err := snaphot1.ToBytes(false)
	assert.NoError(t, err)
	bytes2, err := snapshot2.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, bytes1, bytes2)

	err = os.RemoveAll(path2)
	assert.NoError(t, err)
}

func TestTargetsReadWriteReadCompare(t *testing.T) {
	path1 := filepath.Join(testutils.RepoDir, "targets.json")
	targets1, err := Targets().FromFile(path1)
	assert.NoError(t, err)

	path2 := path1 + ".tmp"
	err = targets1.ToFile(path2, false)
	assert.NoError(t, err)

	targets2, err := Targets().FromFile(path2)
	assert.NoError(t, err)

	bytes1, err := targets1.ToBytes(false)
	assert.NoError(t, err)
	bytes2, err := targets2.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, bytes1, bytes2)

	err = os.RemoveAll(path2)
	assert.NoError(t, err)
}

func TestTimestampReadWriteReadCompare(t *testing.T) {
	path1 := filepath.Join(testutils.RepoDir, "timestamp.json")
	timestamp1, err := Timestamp().FromFile(path1)
	assert.NoError(t, err)

	path2 := path1 + ".tmp"
	err = timestamp1.ToFile(path2, false)
	assert.NoError(t, err)

	timestamp2, err := Timestamp().FromFile(path2)
	assert.NoError(t, err)

	bytes1, err := timestamp1.ToBytes(false)
	assert.NoError(t, err)
	bytes2, err := timestamp2.ToBytes(false)
	assert.NoError(t, err)
	assert.Equal(t, bytes1, bytes2)

	err = os.RemoveAll(path2)
	assert.NoError(t, err)
}

func TestToFromBytes(t *testing.T) {
	// ROOT
	rootPath := filepath.Join(testutils.RepoDir, "root.json")
	data, err := os.ReadFile(rootPath)
	assert.NoError(t, err)
	root, err := Root().FromBytes(data)
	assert.NoError(t, err)

	// Comparate that from_bytes/to_bytes doesn't change the content
	// for two cases for the serializer: noncompact and compact.

	// Case 1: test noncompact by overriding the default serializer.
	rootBytesWant, err := root.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, data, rootBytesWant)

	// Case 2: test compact by using the default serializer.
	root2, err := Root().FromBytes(rootBytesWant)
	assert.NoError(t, err)
	rootBytesActual, err := root2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, rootBytesWant, rootBytesActual)

	// SNAPSHOT
	data, err = os.ReadFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	snapshotBytesWant, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, data, snapshotBytesWant)

	// Case 2: test compact by using the default serializer.
	snapshot2, err := Snapshot().FromBytes(snapshotBytesWant)
	assert.NoError(t, err)
	snapshotBytesActual, err := snapshot2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, snapshotBytesWant, snapshotBytesActual)

	// TARGETS
	data, err = os.ReadFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	targets, err := Targets().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	targetsBytesWant, err := targets.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, data, targetsBytesWant)

	// Case 2: test compact by using the default serializer.
	targets2, err := Targets().FromBytes(targetsBytesWant)
	assert.NoError(t, err)
	targetsBytesActual, err := targets2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, targetsBytesWant, targetsBytesActual)

	// TIMESTAMP
	data, err = os.ReadFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.NoError(t, err)
	timestamp, err := Timestamp().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	timestampBytesWant, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, data, timestampBytesWant)

	// Case 2: test compact by using the default serializer.
	timestamp2, err := Timestamp().FromBytes(timestampBytesWant)
	assert.NoError(t, err)
	timestampBytesActual, err := timestamp2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, timestampBytesWant, timestampBytesActual)

}

func TestSignVerify(t *testing.T) {
	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)

	// Locate the public keys we need from root
	assert.NotEmpty(t, root.Signed.Roles[TARGETS].KeyIDs)
	targetsKeyID := root.Signed.Roles[TARGETS].KeyIDs[0]
	assert.NotEmpty(t, root.Signed.Roles[SNAPSHOT].KeyIDs)
	snapshotKeyID := root.Signed.Roles[SNAPSHOT].KeyIDs[0]
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	timestampKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]

	// Load sample metadata (targets) and assert ...
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	sig, _ := getSignatureByKeyID(targets.Signatures, targetsKeyID)
	data, err := targets.Signed.MarshalJSON()
	assert.NoError(t, err)

	// ... it has a single existing signature,
	assert.Equal(t, 1, len(targets.Signatures))

	// ... which is valid for the correct key.
	targetsKey := root.Signed.Keys[targetsKeyID]
	targetsPublicKey, err := targetsKey.ToPublicKey()
	assert.NoError(t, err)
	targetsHash := crypto.SHA256
	targetsVerifier, err := signature.LoadVerifier(targetsPublicKey, targetsHash)
	assert.NoError(t, err)
	err = targetsVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.NoError(t, err)

	// ... and invalid for an unrelated key
	snapshotKey := root.Signed.Keys[snapshotKeyID]
	snapshotPublicKey, err := snapshotKey.ToPublicKey()
	assert.NoError(t, err)
	snapshotHash := crypto.SHA256
	snapshotVerifier, err := signature.LoadVerifier(snapshotPublicKey, snapshotHash)
	assert.NoError(t, err)
	err = snapshotVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")

	// Append a new signature with the unrelated key and assert that ...
	signer, err := signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "snapshot_key"), crypto.SHA256, cryptoutils.SkipPassword)
	assert.NoError(t, err)
	snapshotSig, err := targets.Sign(signer)
	assert.NoError(t, err)
	// ... there are now two signatures, and
	assert.Equal(t, 2, len(targets.Signatures))
	// ... both are valid for the corresponding keys.
	err = targetsVerifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(data))
	assert.NoError(t, err)
	err = snapshotVerifier.VerifySignature(bytes.NewReader(snapshotSig.Signature), bytes.NewReader(data))
	assert.NoError(t, err)
	// ... the returned (appended) signature is for snapshot key
	assert.Equal(t, snapshotSig.KeyID, snapshotKeyID)

	// Clear all signatures and add a new signature with the unrelated key and assert that ...
	signer, err = signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "timestamp_key"), crypto.SHA256, cryptoutils.SkipPassword)
	assert.NoError(t, err)
	targets.ClearSignatures()
	assert.Equal(t, 0, len(targets.Signatures))
	timestampSig, err := targets.Sign(signer)
	assert.NoError(t, err)
	// ... there now is only one signature,
	assert.Equal(t, 1, len(targets.Signatures))
	// ... valid for that key.
	timestampKey := root.Signed.Keys[timestampKeyID]
	timestampPublicKey, err := timestampKey.ToPublicKey()
	assert.NoError(t, err)
	timestampHash := crypto.SHA256
	timestampVerifier, err := signature.LoadVerifier(timestampPublicKey, timestampHash)
	assert.NoError(t, err)

	err = timestampVerifier.VerifySignature(bytes.NewReader(timestampSig.Signature), bytes.NewReader(data))
	assert.NoError(t, err)
	err = targetsVerifier.VerifySignature(bytes.NewReader(timestampSig.Signature), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")
}

func TestKeyVerifyFailures(t *testing.T) {
	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)

	// Locate the timestamp public key we need from root
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	timestampKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]

	// Load sample metadata (timestamp)
	timestamp, err := Timestamp().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.NoError(t, err)

	timestampSig, _ := getSignatureByKeyID(timestamp.Signatures, timestampKeyID)
	data, err := timestamp.Signed.MarshalJSON()
	assert.NoError(t, err)

	// Test failure on unknown type
	// Originally this test should cover unknown scheme,
	// but in our case scheme changes do not affect any
	// further functionality
	timestampKey := root.Signed.Keys[timestampKeyID]
	ttype := timestampKey.Type
	timestampKey.Type = "foo"

	timestampPublicKey, err := timestampKey.ToPublicKey()
	assert.Error(t, err, "unsupported public key type")
	timestampHash := crypto.SHA256
	timestampVerifier, err := signature.LoadVerifier(timestampPublicKey, timestampHash)
	assert.Error(t, err, "unsupported public key type")
	assert.Nil(t, timestampVerifier)

	timestampKey.Type = ttype
	timestampPublicKey, err = timestampKey.ToPublicKey()
	assert.NoError(t, err)
	timestampHash = crypto.SHA256
	timestampVerifier, err = signature.LoadVerifier(timestampPublicKey, timestampHash)
	assert.NoError(t, err)
	err = timestampVerifier.VerifySignature(bytes.NewReader(timestampSig), bytes.NewReader(data))
	assert.NoError(t, err)
	timestampKey.Type = ttype

	// Test failure on broken public key data
	public := timestampKey.Value.PublicKey
	timestampKey.Value.PublicKey = "ffff"
	timestampBrokenPublicKey, err := timestampKey.ToPublicKey()
	assert.ErrorContains(t, err, "PEM decoding failed")
	timestampHash = crypto.SHA256
	timestampNilVerifier, err := signature.LoadVerifier(timestampBrokenPublicKey, timestampHash)
	assert.ErrorContains(t, err, "unsupported public key type")
	assert.Nil(t, timestampNilVerifier)
	timestampKey.Value.PublicKey = public

	// Test failure with invalid signature
	sigData := []byte("foo")
	h32 := sha256.Sum256(sigData)
	incorrectTimestampSig := h32[:]
	err = timestampVerifier.VerifySignature(bytes.NewReader(incorrectTimestampSig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")

	// Test failure with valid but incorrect signature
	anotherSig := root.Signatures[0]
	h32 = sha256.Sum256([]byte(anotherSig.Signature.String()))
	incorrectValidTimestampSig := h32[:]
	err = timestampVerifier.VerifySignature(bytes.NewReader(incorrectValidTimestampSig), bytes.NewReader(data))
	assert.ErrorContains(t, err, "crypto/rsa: verification error")
}

func TestMetadataSignedIsExpired(t *testing.T) {
	// Use of Snapshot is arbitrary, we're just testing the base class
	// features with real data
	snapshot, err := Snapshot().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	assert.Equal(t, time.Date(2030, 8, 15, 14, 30, 45, 100, time.UTC), snapshot.Signed.Expires)

	// Test IsExpired with reference time provided
	// In the Go implementation IsExpired tests >= rather than only >,
	// which results in snapshot.Signed.Expires IsExpired check
	// being false by default, so we skip the default assertion
	isExpired := snapshot.Signed.IsExpired(snapshot.Signed.Expires.Add(time.Microsecond))
	assert.True(t, isExpired)
	isExpired = snapshot.Signed.IsExpired(snapshot.Signed.Expires.Add(-time.Microsecond))
	assert.False(t, isExpired)
}

func TestMetadataVerifyDelegate(t *testing.T) {

	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	role1, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "role1.json"))
	assert.NoError(t, err)
	role2, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "role2.json"))
	assert.NoError(t, err)
	// Test the expected delegation tree
	err = root.VerifyDelegate(ROOT, root)
	assert.NoError(t, err)
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.NoError(t, err)
	err = root.VerifyDelegate(TARGETS, targets)
	assert.NoError(t, err)
	err = targets.VerifyDelegate("role1", role1)
	assert.NoError(t, err)
	err = role1.VerifyDelegate("role2", role2)
	assert.NoError(t, err)

	// Only root and targets can verify delegates
	err = snapshot.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrType{"call is valid only on delegator metadata (should be either root or targets)"})
	// Verify fails for roles that are not delegated by delegator
	err = root.VerifyDelegate("role1", role1)
	assert.ErrorIs(t, err, &ErrValue{"no delegation found for role1"})
	err = targets.VerifyDelegate(TARGETS, targets)
	assert.ErrorIs(t, err, &ErrValue{"no delegation found for targets"})
	// Verify fails when delegator has no delegations
	err = role2.VerifyDelegate("role1", role1)
	assert.ErrorIs(t, err, &ErrValue{"no delegations found"})

	// Verify fails when delegate content is modified
	expires := snapshot.Signed.Expires
	snapshot.Signed.Expires = snapshot.Signed.Expires.Add(time.Hour * 24)
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying snapshot failed, not enough signatures, got 0, want 1"})
	snapshot.Signed.Expires = expires

	// Verify fails with verification error
	// (in this case signature is malformed)
	keyID := root.Signed.Roles[SNAPSHOT].KeyIDs[0]
	goodSig, idx := getSignatureByKeyID(snapshot.Signatures, keyID)
	assert.NotEmpty(t, goodSig)
	snapshot.Signatures[idx].Signature = []byte("foo")
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying snapshot failed, not enough signatures, got 0, want 1"})
	snapshot.Signatures[idx].Signature = goodSig

	// Verify fails if roles keys do not sign the metadata
	err = root.VerifyDelegate(TIMESTAMP, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying timestamp failed, not enough signatures, got 0, want 1"})

	// Add a key to snapshot role, make sure the new sig fails to verify
	tsKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]
	err = root.Signed.AddKey(root.Signed.Keys[tsKeyID], SNAPSHOT)
	assert.NoError(t, err)
	newSig := Signature{
		KeyID:     tsKeyID,
		Signature: []byte(strings.Repeat("ff", 64)),
	}
	snapshot.Signatures = append(snapshot.Signatures, newSig)

	// Verify succeeds if threshold is reached even if some signatures
	// fail to verify
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.NoError(t, err)

	// Verify fails if threshold of signatures is not reached
	root.Signed.Roles[SNAPSHOT].Threshold = 2
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.ErrorIs(t, err, &ErrUnsignedMetadata{"Verifying snapshot failed, not enough signatures, got 1, want 2"})

	// Verify succeeds when we correct the new signature and reach the
	// threshold of 2 keys
	signer, err := signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "timestamp_key"), crypto.SHA256, cryptoutils.SkipPassword)
	assert.NoError(t, err)
	_, err = snapshot.Sign(signer)
	assert.NoError(t, err)
	err = root.VerifyDelegate(SNAPSHOT, snapshot)
	assert.NoError(t, err)
}

func TestRootAddKeyAndRevokeKey(t *testing.T) {
	root, err := Root().FromFile(filepath.Join(testutils.RepoDir, "root.json"))
	assert.NoError(t, err)

	// Create a new key
	signer, err := signature.LoadSignerFromPEMFile(filepath.Join(testutils.KeystoreDir, "root_key2"), crypto.SHA256, cryptoutils.SkipPassword)
	assert.NoError(t, err)
	key, err := signer.PublicKey()
	assert.NoError(t, err)
	rootKey2, err := KeyFromPublicKey(key)
	assert.NoError(t, err)

	// Assert that root does not contain the new key
	assert.NotContains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.NotContains(t, root.Signed.Keys, rootKey2.id)

	// Add new root key
	err = root.Signed.AddKey(rootKey2, ROOT)
	assert.NoError(t, err)

	// Assert that key is added
	assert.Contains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.Contains(t, root.Signed.Keys, rootKey2.id)

	// Confirm that the newly added key does not break
	// the object serialization
	_, err = root.Signed.MarshalJSON()
	assert.NoError(t, err)

	// Try adding the same key again and assert its ignored.
	preAddKeyIDs := make([]string, len(root.Signed.Roles[ROOT].KeyIDs))
	copy(preAddKeyIDs, root.Signed.Roles[ROOT].KeyIDs)
	err = root.Signed.AddKey(rootKey2, ROOT)
	assert.NoError(t, err)
	assert.Equal(t, preAddKeyIDs, root.Signed.Roles[ROOT].KeyIDs)

	// Add the same key to targets role as well
	err = root.Signed.AddKey(rootKey2, TARGETS)
	assert.NoError(t, err)

	// Add the same key to a nonexistent role.
	err = root.Signed.AddKey(rootKey2, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"role nosuchrole doesn't exist"})

	// Remove the key from root role (targets role still uses it)
	err = root.Signed.RevokeKey(rootKey2.id, ROOT)
	assert.NoError(t, err)
	assert.NotContains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.Contains(t, root.Signed.Keys, rootKey2.id)

	// Remove the key from targets as well
	err = root.Signed.RevokeKey(rootKey2.id, TARGETS)
	assert.NoError(t, err)
	assert.NotContains(t, root.Signed.Roles[ROOT].KeyIDs, rootKey2.id)
	assert.NotContains(t, root.Signed.Keys, rootKey2.id)

	err = root.Signed.RevokeKey("nosuchkey", ROOT)
	assert.ErrorIs(t, err, &ErrValue{"key with id nosuchkey is not used by root"})
	err = root.Signed.RevokeKey(rootKey2.id, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"role nosuchrole doesn't exist"})
}

func TestTargetsKeyAPI(t *testing.T) {
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)

	delegatedRole := DelegatedRole{
		Name:        "role2",
		Paths:       []string{"fn3", "fn4"},
		KeyIDs:      []string{},
		Terminating: false,
		Threshold:   1,
	}
	targets.Signed.Delegations.Roles = append(targets.Signed.Delegations.Roles, delegatedRole)

	key := &Key{
		Type:   "ed25519",
		Value:  KeyVal{PublicKey: "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"},
		Scheme: "ed25519",
	}

	// Assert that delegated role "role1" does not contain the new key
	assert.Equal(t, "role1", targets.Signed.Delegations.Roles[0].Name)
	assert.NotContains(t, targets.Signed.Delegations.Roles[0].KeyIDs, key.id)
	err = targets.Signed.AddKey(key, "role1")
	assert.NoError(t, err)

	// Assert that the new key is added to the delegated role "role1"
	assert.Contains(t, targets.Signed.Delegations.Roles[0].KeyIDs, key.id)

	// Try adding the same key again and assert its ignored.
	pastKeyIDs := make([]string, len(targets.Signed.Delegations.Roles[0].KeyIDs))
	copy(pastKeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)
	err = targets.Signed.AddKey(key, "role1")
	assert.NoError(t, err)
	assert.Equal(t, pastKeyIDs, targets.Signed.Delegations.Roles[0].KeyIDs)

	// Try adding a key to a delegated role that doesn't exists
	err = targets.Signed.AddKey(key, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"delegated role nosuchrole doesn't exist"})

	//  Add the same key to "role2" as well
	err = targets.Signed.AddKey(key, "role2")
	assert.NoError(t, err)

	// Remove the key from "role1" role ("role2" still uses it)
	err = targets.Signed.RevokeKey(key.id, "role1")
	assert.NoError(t, err)

	// Assert that delegated role "role1" doesn't contain the key.
	assert.Equal(t, "role1", targets.Signed.Delegations.Roles[0].Name)
	assert.Equal(t, "role2", targets.Signed.Delegations.Roles[1].Name)
	assert.NotContains(t, targets.Signed.Delegations.Roles[0].KeyIDs, key.id)
	assert.Contains(t, targets.Signed.Delegations.Roles[1].KeyIDs, key.id)

	// Remove the key from "role2" as well
	err = targets.Signed.RevokeKey(key.id, "role2")
	assert.NoError(t, err)
	assert.NotContains(t, targets.Signed.Delegations.Roles[1].KeyIDs, key.id)

	// Try remove key not used by "role1"
	err = targets.Signed.RevokeKey(key.id, "role1")
	assert.ErrorIs(t, err, &ErrValue{fmt.Sprintf("key with id %s is not used by role1", key.id)})

	// Try removing a key from delegated role that doesn't exists
	err = targets.Signed.RevokeKey(key.id, "nosuchrole")
	assert.ErrorIs(t, err, &ErrValue{"delegated role nosuchrole doesn't exist"})

	// Remove delegations as a whole
	targets.Signed.Delegations = nil

	//Test that calling add_key and revoke_key throws an error
	// and that delegations is still None after each of the api calls
	err = targets.Signed.AddKey(key, "role1")
	assert.ErrorIs(t, err, &ErrValue{"delegated role role1 doesn't exist"})
	err = targets.Signed.RevokeKey(key.id, "role1")
	assert.ErrorIs(t, err, &ErrValue{"delegated role role1 doesn't exist"})
	assert.Nil(t, targets.Signed.Delegations)
}

func TestTargetsKeyAPIWithSuccinctRoles(t *testing.T) {
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)

	// Remove delegated roles
	assert.NotNil(t, targets.Signed.Delegations)
	assert.NotNil(t, targets.Signed.Delegations.Roles)
	targets.Signed.Delegations.Roles = nil
	targets.Signed.Delegations.Keys = map[string]*Key{}

	// Add succinct roles information
	targets.Signed.Delegations.SuccinctRoles = &SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  8,
		NamePrefix: "foo",
	}
	assert.Equal(t, 0, len(targets.Signed.Delegations.Keys))
	assert.Equal(t, 0, len(targets.Signed.Delegations.SuccinctRoles.KeyIDs))

	// Add a key to succinct_roles and verify it's saved.
	key := &Key{
		Type:   "ed25519",
		Value:  KeyVal{PublicKey: "edcd0a32a07dce33f7c7873aaffbff36d20ea30787574ead335eefd337e4dacd"},
		Scheme: "ed25519",
	}
	err = targets.Signed.AddKey(key, "foo")
	assert.NoError(t, err)
	assert.Contains(t, targets.Signed.Delegations.Keys, key.id)
	assert.Contains(t, targets.Signed.Delegations.SuccinctRoles.KeyIDs, key.id)
	assert.Equal(t, 1, len(targets.Signed.Delegations.Keys))

	// Try adding the same key again and verify that noting is added.
	err = targets.Signed.AddKey(key, "foo")
	assert.NoError(t, err)
	assert.Equal(t, 1, len(targets.Signed.Delegations.Keys))

	// Remove the key and verify it's not stored anymore.
	err = targets.Signed.RevokeKey(key.id, "foo")
	assert.NoError(t, err)
	assert.NotContains(t, targets.Signed.Delegations.Keys, key.id)
	assert.NotContains(t, targets.Signed.Delegations.SuccinctRoles.KeyIDs, key.id)
	assert.Equal(t, 0, len(targets.Signed.Delegations.Keys))

	// Try removing it again.
	err = targets.Signed.RevokeKey(key.id, "foo")
	assert.ErrorIs(t, err, &ErrValue{fmt.Sprintf("key with id %s is not used by SuccinctRoles", key.id)})
}

func TestLengthAndHashValidation(t *testing.T) {
	// Test metadata files' hash and length verification.
	// Use timestamp to get a MetaFile object and snapshot
	// for untrusted metadata file to verify.

	timestamp, err := Timestamp().FromFile(filepath.Join(testutils.RepoDir, "timestamp.json"))
	assert.NoError(t, err)

	snapshotMetafile := timestamp.Signed.Meta["snapshot.json"]
	assert.NotNil(t, snapshotMetafile)

	snapshotData, err := os.ReadFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	h32 := sha256.Sum256(snapshotData)
	h := h32[:]
	snapshotMetafile.Hashes = map[string]HexBytes{
		"sha256": h,
	}
	snapshotMetafile.Length = 652

	data, err := os.ReadFile(filepath.Join(testutils.RepoDir, "snapshot.json"))
	assert.NoError(t, err)
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.NoError(t, err)

	// test exceptions
	originalLength := snapshotMetafile.Length
	snapshotMetafile.Length = 2345
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{fmt.Sprintf("length verification failed - expected %d, got %d", 2345, originalLength)})

	snapshotMetafile.Length = originalLength
	originalHashSHA256 := snapshotMetafile.Hashes["sha256"]
	snapshotMetafile.Hashes["sha256"] = []byte("incorrecthash")
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - mismatch for algorithm sha256"})

	snapshotMetafile.Hashes["sha256"] = originalHashSHA256
	snapshotMetafile.Hashes["unsupported-alg"] = []byte("72c5cabeb3e8079545a5f4d2b067f8e35f18a0de3c2b00d3cb8d05919c19c72d")
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - unknown hashing algorithm - unsupported-alg"})

	// test optional length and hashes
	snapshotMetafile.Length = 0
	snapshotMetafile.Hashes = nil
	err = snapshotMetafile.VerifyLengthHashes(data)
	assert.NoError(t, err)

	// Test target files' hash and length verification
	targets, err := Targets().FromFile(filepath.Join(testutils.RepoDir, "targets.json"))
	assert.NoError(t, err)
	targetFile := targets.Signed.Targets["file1.txt"]
	targetFileData, err := os.ReadFile(filepath.Join(testutils.TargetsDir, targetFile.Path))
	assert.NoError(t, err)

	// test exceptions
	originalLength = targetFile.Length
	targetFile.Length = 2345
	err = targetFile.VerifyLengthHashes(targetFileData)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{fmt.Sprintf("length verification failed - expected %d, got %d", 2345, originalLength)})

	targetFile.Length = originalLength
	targetFile.Hashes["sha256"] = []byte("incorrecthash")
	err = targetFile.VerifyLengthHashes(targetFileData)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - mismatch for algorithm sha256"})
}

func TestTargetFileFromFile(t *testing.T) {
	// Test with an existing file and valid hash algorithm
	targetFilePath := filepath.Join(testutils.TargetsDir, "file1.txt")
	targetFileFromFile, err := TargetFile().FromFile(targetFilePath, "sha256")
	assert.NoError(t, err)
	targetFileData, err := os.ReadFile(targetFilePath)
	assert.NoError(t, err)
	err = targetFileFromFile.VerifyLengthHashes(targetFileData)
	assert.NoError(t, err)

	// Test with mismatching target file data
	mismatchingTargetFilePath := filepath.Join(testutils.TargetsDir, "file2.txt")
	mismatchingTargetFileData, err := os.ReadFile(mismatchingTargetFilePath)
	assert.NoError(t, err)
	err = targetFileFromFile.VerifyLengthHashes(mismatchingTargetFileData)
	assert.ErrorIs(t, err, &ErrLengthOrHashMismatch{"hash verification failed - mismatch for algorithm sha256"})

	// Test with an unsupported algorithm
	_, err = TargetFile().FromFile(targetFilePath, "123")
	assert.ErrorIs(t, err, &ErrValue{"failed generating TargetFile - unsupported hashing algorithm - 123"})
}

func TestTargetFileCustom(t *testing.T) {
	// Test creating TargetFile and accessing custom.
	targetFile := TargetFile()
	customJSON := json.RawMessage([]byte(`{"foo":"bar"}`))
	targetFile.Custom = &customJSON
	custom, err := targetFile.Custom.MarshalJSON()
	assert.NoError(t, err)
	assert.Equal(t, "{\"foo\":\"bar\"}", string(custom))
}

func TestTargetFileFromBytes(t *testing.T) {
	data := []byte("Inline test content")
	path := filepath.Join(testutils.TargetsDir, "file1.txt")

	// Test with a valid hash algorithm
	targetFileFromData, err := TargetFile().FromBytes(path, data, "sha256")
	assert.NoError(t, err)
	err = targetFileFromData.VerifyLengthHashes(data)
	assert.NoError(t, err)

	// Test with no algorithms specified
	targetFileFromDataWithNoAlg, err := TargetFile().FromBytes(path, data)
	assert.NoError(t, err)
	err = targetFileFromDataWithNoAlg.VerifyLengthHashes(data)
	assert.NoError(t, err)
}

func TestIsDelegatedRole(t *testing.T) {
	// Test path matches
	role := &DelegatedRole{
		Name:        "",
		KeyIDs:      []string{},
		Threshold:   1,
		Terminating: false,
		Paths:       []string{"a/path", "otherpath", "a/path", "*/?ath"},
	}
	nonMatching, err := role.IsDelegatedPath("a/non-matching-path")
	assert.NoError(t, err)
	assert.False(t, nonMatching)
	matching, err := role.IsDelegatedPath("a/path")
	assert.NoError(t, err)
	assert.True(t, matching)

	// Test path hash prefix matches: sha256 sum of "a/path" is 927b0ecf9...
	role = &DelegatedRole{
		Name:             "",
		KeyIDs:           []string{},
		Threshold:        1,
		Terminating:      false,
		PathHashPrefixes: []string{"knsOz5xYT", "other prefix", "knsOz5xYT", "knsOz", "kn"},
	}
	nonMatching, err = role.IsDelegatedPath("a/non-matching-path")
	assert.NoError(t, err)
	assert.False(t, nonMatching)
	matching, err = role.IsDelegatedPath("a/path")
	assert.NoError(t, err)
	assert.True(t, matching)
}

func TestIsDelegatedRoleInSuccinctRoles(t *testing.T) {
	succinctRoles := &SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  5,
		NamePrefix: "bin",
	}

	falseRoleNmaeExamples := []string{
		"foo",
		"bin-",
		"bin-s",
		"bin-0t",
		"bin-20",
		"bin-100",
	}
	for _, roleName := range falseRoleNmaeExamples {
		res := succinctRoles.IsDelegatedRole(roleName)
		assert.False(t, res)
	}

	// Delegated role name suffixes are in hex format.
	trueNameExamples := []string{"bin-00", "bin-0f", "bin-1f"}
	for _, roleName := range trueNameExamples {
		res := succinctRoles.IsDelegatedRole(roleName)
		assert.True(t, res)
	}
}

func TestGetRolesInSuccinctRoles(t *testing.T) {
	succinctRoles := &SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  16,
		NamePrefix: "bin",
	}
	// bin names are in hex format and 4 hex digits are enough to represent
	// all bins between 0 and 2^16 - 1 meaning suffix_len must be 4
	expectedSuffixLength := 4
	suffixLen, _ := succinctRoles.GetSuffixLen()
	assert.Equal(t, expectedSuffixLength, suffixLen)

	allRoles := succinctRoles.GetRoles()
	for binNumer, roleName := range allRoles {
		// This adds zero-padding if the bin_numer is represented by a hex
		// number with a length less than expected_suffix_length.
		expectedBinSuffix := fmt.Sprintf("%0"+strconv.Itoa(expectedSuffixLength)+"x", binNumer)
		assert.Equal(t, fmt.Sprintf("bin-%s", expectedBinSuffix), roleName)
	}
}
