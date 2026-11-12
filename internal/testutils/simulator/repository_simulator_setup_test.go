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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)


func TestNewTestEnv(t *testing.T) {
	t.Parallel()

	env1, err := NewTestEnv(t)
	assert.NoError(t, err)
	assert.NotNil(t, env1)
	assert.NotNil(t, env1.Sim)
	assert.NotEmpty(t, env1.RootBytes)
	assert.False(t, env1.PastDateTime.IsZero())

	// Verify directories exist

_, err = os.Stat(env1.MetadataDir)
	assert.NoError(t, err)
	_, err = os.Stat(env1.TargetsDir)
	assert.NoError(t, err)

	// Verify root.json was written
	rootPath := filepath.Join(env1.MetadataDir, "root.json")
	data, err := os.ReadFile(rootPath)
	assert.NoError(t, err)
	assert.Equal(t, env1.RootBytes, data)

	// Verify isolation: create a second environment and confirm distinct paths
	env2, err := NewTestEnv(t)
	assert.NoError(t, err)
	assert.NotEqual(t, env1.MetadataDir, env2.MetadataDir)
	assert.NotEqual(t, env1.TargetsDir, env2.TargetsDir)
}


func TestNewTestEnv_ParallelIsolation(t *testing.T) {
	t.Parallel()

	for i := 0; i < 3; i++ {
		t.Run("parallel_instance", func(t *testing.T) {
			t.Parallel()
			env, err := NewTestEnv(t)
			assert.NoError(t, err)
			assert.NotNil(t, env)
			assert.NotEmpty(t, env.RootBytes)

			// Mutate local state in this environment
			testFile := filepath.Join(env.MetadataDir, "custom.json")
			err = os.WriteFile(testFile, []byte("test"), 0600)
			assert.NoError(t, err)

			// Ensure the file exists in this environment
			_, err = os.Stat(testFile)
			assert.NoError(t, err)
		})
	}
}
