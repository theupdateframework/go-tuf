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

package metadata

import (
	"bytes"
	"crypto"
	"fmt"
	"io/fs"
	"os"
	"testing"

	testutils "github.com/rdimitrov/go-tuf-metadata/testutils/testutils"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {

	err := testutils.SetupTestDirs()
	defer testutils.Cleanup()

	if err != nil {
		log.Fatalf("failed to setup test dirs: %v", err)
	}
	m.Run()
}

func TestGenericRead(t *testing.T) {
	// Assert that it chokes correctly on an unknown metadata type
	badMetadata := "{\"signed\": {\"_type\": \"bad-metadata\"}}"
	_, err := Root().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type root, got - bad-metadata"})
	_, err = Snapshot().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type snapshot, got - bad-metadata"})
	_, err = Targets().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type targets, got - bad-metadata"})
	_, err = Timestamp().FromBytes([]byte(badMetadata))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type timestamp, got - bad-metadata"})

	badMetadataPath := fmt.Sprintf("%s/bad-metadata.json", testutils.RepoDir)
	err = os.WriteFile(badMetadataPath, []byte(badMetadata), 0644)
	assert.NoError(t, err)
	assert.FileExists(t, badMetadataPath)

	_, err = Root().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, ErrValue{"expected metadata type root, got - bad-metadata"})
	_, err = Snapshot().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, ErrValue{"expected metadata type snapshot, got - bad-metadata"})
	_, err = Targets().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, ErrValue{"expected metadata type targets, got - bad-metadata"})
	_, err = Timestamp().FromFile(badMetadataPath)
	assert.ErrorIs(t, err, ErrValue{"expected metadata type timestamp, got - bad-metadata"})

	err = os.RemoveAll(badMetadataPath)
	assert.NoError(t, err)
	assert.NoFileExists(t, badMetadataPath)
}

func TestGenericReadFromMismatchingRoles(t *testing.T) {
	// Test failing to load other roles from root metadata
	_, err := Snapshot().FromFile(fmt.Sprintf("%s/root.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type snapshot, got - root"})
	_, err = Timestamp().FromFile(fmt.Sprintf("%s/root.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type timestamp, got - root"})
	_, err = Targets().FromFile(fmt.Sprintf("%s/root.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type targets, got - root"})

	// Test failing to load other roles from targets metadata
	_, err = Snapshot().FromFile(fmt.Sprintf("%s/targets.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type snapshot, got - targets"})
	_, err = Timestamp().FromFile(fmt.Sprintf("%s/targets.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type timestamp, got - targets"})
	_, err = Root().FromFile(fmt.Sprintf("%s/targets.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type root, got - targets"})

	// Test failing to load other roles from timestamp metadata
	_, err = Snapshot().FromFile(fmt.Sprintf("%s/timestamp.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type snapshot, got - timestamp"})
	_, err = Targets().FromFile(fmt.Sprintf("%s/timestamp.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type targets, got - timestamp"})
	_, err = Root().FromFile(fmt.Sprintf("%s/timestamp.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type root, got - timestamp"})

	// Test failing to load other roles from snapshot metadata
	_, err = Targets().FromFile(fmt.Sprintf("%s/snapshot.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type targets, got - snapshot"})
	_, err = Timestamp().FromFile(fmt.Sprintf("%s/snapshot.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type timestamp, got - snapshot"})
	_, err = Root().FromFile(fmt.Sprintf("%s/snapshot.json", testutils.RepoDir))
	assert.ErrorIs(t, err, ErrValue{"expected metadata type root, got - snapshot"})
}

func TestMDReadWriteFileExceptions(t *testing.T) {
	// Test writing to a file with bad filename
	badMetadataPath := fmt.Sprintf("%s/bad-metadata.json", testutils.RepoDir)
	_, err := Root().FromFile(badMetadataPath)
	expectedErr := fs.PathError{
		Op:   "open",
		Path: badMetadataPath,
		Err:  unix.ENOENT,
	}
	assert.ErrorIs(t, err, expectedErr.Err)

	// Test serializing to a file with bad filename
	root := Root(fixedExpire)
	err = root.ToFile("", false)
	expectedErr = fs.PathError{
		Op:   "open",
		Path: "",
		Err:  unix.ENOENT,
	}
	assert.ErrorIs(t, err, expectedErr.Err)
}

func TestCompareFromBytesFromFileToBytes(t *testing.T) {
	rootBytesWant, err := os.ReadFile(fmt.Sprintf("%s/root.json", testutils.RepoDir))
	assert.NoError(t, err)
	root, err := Root().FromFile(fmt.Sprintf("%s/root.json", testutils.RepoDir))
	assert.NoError(t, err)
	rootBytesActual, err := root.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, rootBytesWant, rootBytesActual)

	targetsBytesWant, err := os.ReadFile(fmt.Sprintf("%s/targets.json", testutils.RepoDir))
	assert.NoError(t, err)
	targets, err := Targets().FromFile(fmt.Sprintf("%s/targets.json", testutils.RepoDir))
	assert.NoError(t, err)
	targetsBytesActual, err := targets.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, targetsBytesWant, targetsBytesActual)

	snapshotBytesWant, err := os.ReadFile(fmt.Sprintf("%s/snapshot.json", testutils.RepoDir))
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromFile(fmt.Sprintf("%s/snapshot.json", testutils.RepoDir))
	assert.NoError(t, err)
	snapshotBytesActual, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, snapshotBytesWant, snapshotBytesActual)

	timestampBytesWant, err := os.ReadFile(fmt.Sprintf("%s/timestamp.json", testutils.RepoDir))
	assert.NoError(t, err)
	timestamp, err := Timestamp().FromFile(fmt.Sprintf("%s/timestamp.json", testutils.RepoDir))
	assert.NoError(t, err)
	timestampBytesActual, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, timestampBytesWant, timestampBytesActual)
}

func TestRootReadWriteReadCompare(t *testing.T) {
	src := testutils.RepoDir + "/root.json"
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
	path1 := testutils.RepoDir + "/snapshot.json"
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
	path1 := testutils.RepoDir + "/targets.json"
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
	path1 := testutils.RepoDir + "/timestamp.json"
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
	data, err := os.ReadFile(testutils.RepoDir + "/root.json")
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
	data, err = os.ReadFile(testutils.RepoDir + "/snapshot.json")
	assert.NoError(t, err)
	snapshot, err := Snapshot().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	snapshotBytesWant, err := snapshot.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, string(data), string(snapshotBytesWant))

	// Case 2: test compact by using the default serializer.
	snapshot2, err := Snapshot().FromBytes(snapshotBytesWant)
	assert.NoError(t, err)
	snapshotBytesActual, err := snapshot2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, string(snapshotBytesWant), string(snapshotBytesActual))

	// TARGETS
	data, err = os.ReadFile(testutils.RepoDir + "/targets.json")
	assert.NoError(t, err)
	targets, err := Targets().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	targetsBytesWant, err := targets.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, string(data), string(targetsBytesWant))

	// Case 2: test compact by using the default serializer.
	targets2, err := Targets().FromBytes(targetsBytesWant)
	assert.NoError(t, err)
	targetsBytesActual, err := targets2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, string(targetsBytesWant), string(targetsBytesActual))

	// TIMESTAMP
	data, err = os.ReadFile(testutils.RepoDir + "/timestamp.json")
	assert.NoError(t, err)
	timestamp, err := Timestamp().FromBytes(data)
	assert.NoError(t, err)

	// Case 1: test noncompact by overriding the default serializer.
	timestampBytesWant, err := timestamp.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, string(data), string(timestampBytesWant))

	// Case 2: test compact by using the default serializer.
	timestamp2, err := Timestamp().FromBytes(timestampBytesWant)
	assert.NoError(t, err)
	timestampBytesActual, err := timestamp2.ToBytes(true)
	assert.NoError(t, err)
	assert.Equal(t, string(timestampBytesWant), string(timestampBytesActual))

}

func TestSignVerify(t *testing.T) {
	root, err := Root().FromFile(testutils.RepoDir + "/root.json")
	assert.NoError(t, err)

	// Locate the public keys we need from root
	assert.NotEmpty(t, root.Signed.Roles[TARGETS].KeyIDs)
	targetsKeyID := root.Signed.Roles[TARGETS].KeyIDs[0]
	assert.NotEmpty(t, root.Signed.Roles[SNAPSHOT].KeyIDs)
	snapshotKeyID := root.Signed.Roles[SNAPSHOT].KeyIDs[0]
	assert.NotEmpty(t, root.Signed.Roles[TIMESTAMP].KeyIDs)
	timestampKeyID := root.Signed.Roles[TIMESTAMP].KeyIDs[0]

	// Load sample metadata (targets) and assert ...
	targets, err := Targets().FromFile(testutils.RepoDir + "/targets.json")
	assert.NoError(t, err)
	sig := getSignatureByKeyID(targets.Signatures, targetsKeyID)
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
	signer, err := signature.LoadSignerFromPEMFile(testutils.KeystoreDir+"/snapshot_key", crypto.SHA256, cryptoutils.SkipPassword)
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
	signer, err = signature.LoadSignerFromPEMFile(testutils.KeystoreDir+"/timestamp_key", crypto.SHA256, cryptoutils.SkipPassword)
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
