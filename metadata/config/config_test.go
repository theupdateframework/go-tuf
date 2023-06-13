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

package config

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewUpdaterConfig(t *testing.T) {

	remoteURL := "somepath"
	rootBytes := []byte("somerootbytes")

	updaterConfig, err := New(remoteURL, rootBytes)

	assert.NoError(t, err)
	assert.NotNil(t, updaterConfig)
	assert.NotNil(t, updaterConfig.Fetcher)

	assert.Equal(t, 32, updaterConfig.MaxDelegations)
	assert.Equal(t, int64(32), updaterConfig.MaxRootRotations)
	assert.Equal(t, int64(512000), updaterConfig.RootMaxLength)
	assert.Equal(t, int64(16384), updaterConfig.TimestampMaxLength)
	assert.Equal(t, int64(2000000), updaterConfig.SnapshotMaxLength)
	assert.Equal(t, int64(5000000), updaterConfig.TargetsMaxLength)
	assert.Equal(t, false, updaterConfig.DisableLocalCache)
	assert.Equal(t, true, updaterConfig.PrefixTargetsWithHash)
	assert.Equal(t, updaterConfig.RemoteMetadataURL, remoteURL)
	assert.Equal(t, updaterConfig.LocalTrustedRoot, rootBytes)
	assert.Equal(t, updaterConfig.RemoteTargetsURL, remoteURL+"/targets")
	assert.Empty(t, updaterConfig.LocalMetadataDir)
	assert.Empty(t, updaterConfig.LocalTargetsDir)
}

func TestEnsurePathsExist(t *testing.T) {

	remoteURL := "somepath"
	rootBytes := []byte("somerootbytes")

	updaterConfig, err := New(remoteURL, rootBytes)
	assert.NoError(t, err)
	assert.NotNil(t, updaterConfig)

	err = updaterConfig.EnsurePathsExist()
	assert.Error(t, err, "mkdir : no such file or directory")

	tmp := os.TempDir()
	metadataPath := fmt.Sprintf("%s/metadata", tmp)
	targetsPath := fmt.Sprintf("%s/targets", tmp)

	assert.NoDirExists(t, metadataPath)
	assert.NoDirExists(t, targetsPath)

	updaterConfig.LocalMetadataDir = metadataPath
	updaterConfig.LocalTargetsDir = targetsPath

	updaterConfig.DisableLocalCache = true
	err = updaterConfig.EnsurePathsExist()
	assert.NoError(t, err)
	assert.NoDirExists(t, metadataPath)
	assert.NoDirExists(t, targetsPath)

	updaterConfig.DisableLocalCache = false
	err = updaterConfig.EnsurePathsExist()
	assert.NoError(t, err)

	assert.DirExists(t, metadataPath)
	assert.DirExists(t, targetsPath)

	err = os.RemoveAll(metadataPath)
	assert.NoError(t, err)
	assert.NoDirExists(t, metadataPath)

	err = os.RemoveAll(targetsPath)
	assert.NoError(t, err)
	assert.NoDirExists(t, targetsPath)
}
