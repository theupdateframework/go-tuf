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

package repository

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
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
