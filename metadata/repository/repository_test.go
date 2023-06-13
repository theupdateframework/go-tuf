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

package repository

import (
	"testing"
	"time"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/stretchr/testify/assert"
)

func TestNewRepository(t *testing.T) {
	repo := New()

	now := time.Now().UTC()
	safeExpiry := now.Truncate(time.Second).AddDate(0, 0, 30)

	root := metadata.Root(safeExpiry)
	repo.SetRoot(root)
	assert.Equal(t, "root", repo.Root().Signed.Type)
	assert.Equal(t, int64(1), repo.Root().Signed.Version)
	assert.Equal(t, metadata.SPECIFICATION_VERSION, repo.Root().Signed.SpecVersion)

	targets := metadata.Targets(safeExpiry)
	repo.SetTargets("targets", targets)
	assert.Equal(t, "targets", repo.Targets("targets").Signed.Type)
	assert.Equal(t, int64(1), repo.Targets("targets").Signed.Version)
	assert.Equal(t, metadata.SPECIFICATION_VERSION, repo.Targets("targets").Signed.SpecVersion)

	timestamp := metadata.Timestamp(safeExpiry)
	repo.SetTimestamp(timestamp)
	// repo.SetRoot(root)
	assert.Equal(t, "timestamp", repo.Timestamp().Signed.Type)
	assert.Equal(t, int64(1), repo.Timestamp().Signed.Version)
	assert.Equal(t, metadata.SPECIFICATION_VERSION, repo.Timestamp().Signed.SpecVersion)

	snapshot := metadata.Snapshot(safeExpiry)
	repo.SetSnapshot(snapshot)
	assert.Equal(t, "snapshot", repo.Snapshot().Signed.Type)
	assert.Equal(t, int64(1), repo.Snapshot().Signed.Version)
	assert.Equal(t, metadata.SPECIFICATION_VERSION, repo.Snapshot().Signed.SpecVersion)
}
