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
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, eehher express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0
//

package simulator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestLastIndex(t *testing.T) {
	// Test without delimiter
	dir, sep, file := lastIndex("filename.txt", "/")
	assert.Equal(t, "", dir)
	assert.Equal(t, "", sep)
	assert.Equal(t, "filename.txt", file)

	// Test with nested delimiter
	dir, sep, file = lastIndex("dir1/dir2/filename.txt", "/")
	assert.Equal(t, "dir1/dir2", dir)
	assert.Equal(t, "/", sep)
	assert.Equal(t, "filename.txt", file)
}

func TestHasSuffix(t *testing.T) {
	assert.True(t, hasSuffix("metadata/root.json", ".json"))
	assert.True(t, hasSuffix("metadata\\root.json", ".json"))
	assert.False(t, hasSuffix("metadata/root.txt", ".json"))
}

func TestFetchTarget_Routing(t *testing.T) {
	sim := NewRepository()
	sim.PrefixTargetsWithHash = false
	targetData := []byte("target payload")

	// Add targets
	sim.AddTarget(metadata.TARGETS, targetData, "flat.txt")
	sim.AddTarget(metadata.TARGETS, targetData, "nested/dir/file.txt")

	t.Run("flat target fetch without prefix", func(t *testing.T) {
		data, err := sim.fetch("/targets/flat.txt")
		assert.NoError(t, err)
		assert.Equal(t, targetData, data)
	})

	t.Run("nested target fetch without prefix", func(t *testing.T) {
		data, err := sim.fetch("/targets/nested/dir/file.txt")
		assert.NoError(t, err)
		assert.Equal(t, targetData, data)
	})

	t.Run("target fetch with hash prefix", func(t *testing.T) {
		sim.PrefixTargetsWithHash = true
		target := sim.TargetFiles["flat.txt"]
		hash := target.TargetFile.Hashes["sha256"].String()
		data, err := sim.fetch("/targets/" + hash + ".flat.txt")
		assert.NoError(t, err)
		assert.Equal(t, targetData, data)
	})

	t.Run("nested target fetch with hash prefix", func(t *testing.T) {
		sim.PrefixTargetsWithHash = true
		target := sim.TargetFiles["nested/dir/file.txt"]
		hash := target.TargetFile.Hashes["sha256"].String()
		data, err := sim.fetch("/targets/nested/dir/" + hash + ".file.txt")
		assert.NoError(t, err)
		assert.Equal(t, targetData, data)
	})

	t.Run("metadata fetch routing", func(t *testing.T) {
		data, err := sim.fetch("/metadata/1.root.json")
		assert.NoError(t, err)
		assert.NotEmpty(t, data)
	})

	t.Run("nonexistent target fetch", func(t *testing.T) {
		_, err := sim.fetch("/targets/nonexistent.txt")
		assert.Error(t, err)
	})
}
