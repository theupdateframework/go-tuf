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

package fixtures

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func copyFixtures(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.CopyFS(dir, os.DirFS("../repository_data")))
	return dir
}

func metadataBytes(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	base := filepath.Join(dir, "repository", "metadata")
	entries, err := os.ReadDir(base)
	require.NoError(t, err)
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(base, entry.Name()))
		require.NoError(t, err)
		result[entry.Name()] = string(data)
	}
	return result
}

func TestRegenerateValidFixturesIsNoOp(t *testing.T) {
	dir := copyFixtures(t)
	before := metadataBytes(t, dir)
	require.NoError(t, Verify(dir))
	require.NoError(t, Regenerate(dir))
	require.Equal(t, before, metadataBytes(t, dir))
}

func TestRegenerateRepairsDependencyChain(t *testing.T) {
	dir := copyFixtures(t)
	before := metadataBytes(t, dir)
	base := filepath.Join(dir, "repository", "metadata")
	// Change both a top-level role and a delegated target, including data on disk.
	for _, role := range []string{metadata.TARGETS, "role1"} {
		path := filepath.Join(base, role+".json")
		md, err := metadata.Targets().FromFile(path)
		require.NoError(t, err)
		md.Signed.Version = 2
		require.NoError(t, md.ToFile(path, false))
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "repository", "targets", "file3.txt"), []byte("updated delegated fixture"), 0o644))
	// Exercise optional hashes and lengths, too. Stale values must be rebuilt
	// against the final serialized bytes, including newly generated signatures.
	snapshot, err := metadata.Snapshot().FromFile(filepath.Join(base, "snapshot.json"))
	require.NoError(t, err)
	snapshot.Signed.Version = 3
	for _, info := range snapshot.Signed.Meta {
		info.Length = 1
		info.Hashes = metadata.Hashes{"sha256": {0}, "sha512": {0}}
	}
	require.NoError(t, snapshot.ToFile(filepath.Join(base, "snapshot.json"), false))
	timestamp, err := metadata.Timestamp().FromFile(filepath.Join(base, "timestamp.json"))
	require.NoError(t, err)
	timestamp.Signed.Meta["snapshot.json"].Length = 1
	timestamp.Signed.Meta["snapshot.json"].Hashes = metadata.Hashes{"sha256": {0}}
	require.NoError(t, timestamp.ToFile(filepath.Join(base, "timestamp.json"), false))
	require.Error(t, Verify(dir))
	require.NoError(t, Regenerate(dir))
	require.NoError(t, Verify(dir))
	r, err := readRepository(dir)
	require.NoError(t, err)
	require.EqualValues(t, 2, r.snapshot.Signed.Meta["targets.json"].Version)
	require.EqualValues(t, 2, r.snapshot.Signed.Meta["role1.json"].Version)
	require.EqualValues(t, 3, r.timestamp.Signed.Meta["snapshot.json"].Version)
	after := metadataBytes(t, dir)
	require.Equal(t, before["1.root.json"], after["1.root.json"], "historical parse-only fixture must be preserved")
	require.NoError(t, Regenerate(dir))
	require.Equal(t, after, metadataBytes(t, dir), "second regeneration must not churn signatures")
}

func TestRegenerateFailureDoesNotWriteMetadata(t *testing.T) {
	for _, mode := range []string{"missing target", "invalid key", "unsupported threshold"} {
		t.Run(mode, func(t *testing.T) {
			dir := copyFixtures(t)
			path := filepath.Join(dir, "repository", "metadata", "targets.json")
			md, err := metadata.Targets().FromFile(path)
			require.NoError(t, err)
			md.Signed.Version++
			if mode == "unsupported threshold" {
				md.Signed.Delegations.Roles[0].Threshold = 2
			}
			require.NoError(t, md.ToFile(path, false))
			if mode == "missing target" {
				require.NoError(t, os.Remove(filepath.Join(dir, "repository", "targets", "file1.txt")))
			}
			if mode == "invalid key" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "keystore", "root_key"), []byte("invalid PEM"), 0o600))
			}
			before := metadataBytes(t, dir)
			require.Error(t, Regenerate(dir))
			require.Equal(t, before, metadataBytes(t, dir))
		})
	}
}
