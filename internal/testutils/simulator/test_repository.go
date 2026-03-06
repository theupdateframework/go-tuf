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

package simulator

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
)

// TestRepository encapsulates all test state for an isolated repository (no globals)
type TestRepository struct {
	Simulator   *RepositorySimulator
	MetadataDir string
	TargetsDir  string
	RootBytes   []byte
	LocalDir    string
	t           *testing.T
	pastTime    time.Time
}

// NewTestRepository creates an isolated test repository with a fresh simulator
func NewTestRepository(t *testing.T) *TestRepository {
	t.Helper()

	repo := &TestRepository{
		t:        t,
		pastTime: time.Now().UTC().Truncate(24 * time.Hour).Add(-5 * 24 * time.Hour),
	}

	repo.initializeRepository()
	return repo
}

// NewTestRepositoryWithBuilder creates an isolated test repository using a SimulatorBuilder
func NewTestRepositoryWithBuilder(t *testing.T, builder *SimulatorBuilder) *TestRepository {
	t.Helper()

	repo := &TestRepository{
		t:        t,
		pastTime: time.Now().UTC().Truncate(24 * time.Hour).Add(-5 * 24 * time.Hour),
	}

	repo.initializeRepositoryWithBuilder(builder)
	return repo
}

func (r *TestRepository) initializeRepository() {
	r.t.Helper()

	// t.TempDir() creates a temporary directory that is automatically removed
	// when the test and all its subtests complete.
	tmpDir := r.t.TempDir()
	r.LocalDir = tmpDir

	metadataDir := filepath.Join(tmpDir, "metadata")
	if err := os.MkdirAll(metadataDir, 0750); err != nil {
		r.t.Fatalf("failed to create metadata dir: %v", err)
	}
	r.MetadataDir = metadataDir

	targetsDir := filepath.Join(tmpDir, "targets")
	if err := os.MkdirAll(targetsDir, 0750); err != nil {
		r.t.Fatalf("failed to create targets dir: %v", err)
	}
	r.TargetsDir = targetsDir

	// Create and configure the simulator
	r.Simulator = NewRepository()
	r.Simulator.LocalDir = tmpDir

	// Write initial root metadata
	rootPath := filepath.Join(metadataDir, "root.json")
	if err := os.WriteFile(rootPath, r.Simulator.SignedRoots[0], 0644); err != nil {
		r.t.Fatalf("failed to write root.json: %v", err)
	}

	// Read root bytes for config
	var err error
	r.RootBytes, err = os.ReadFile(rootPath)
	if err != nil {
		r.t.Fatalf("failed to read root bytes: %v", err)
	}
}

func (r *TestRepository) initializeRepositoryWithBuilder(builder *SimulatorBuilder) {
	r.t.Helper()

	tmpDir := r.t.TempDir()
	r.LocalDir = tmpDir

	metadataDir := filepath.Join(tmpDir, "metadata")
	if err := os.MkdirAll(metadataDir, 0750); err != nil {
		r.t.Fatalf("failed to create metadata dir: %v", err)
	}
	r.MetadataDir = metadataDir

	targetsDir := filepath.Join(tmpDir, "targets")
	if err := os.MkdirAll(targetsDir, 0750); err != nil {
		r.t.Fatalf("failed to create targets dir: %v", err)
	}
	r.TargetsDir = targetsDir

	// Build the simulator with the provided configuration
	r.Simulator = builder.Build(r.t)
	r.Simulator.LocalDir = tmpDir

	// Write initial root metadata
	rootPath := filepath.Join(metadataDir, "root.json")
	if len(r.Simulator.SignedRoots) > 0 {
		if err := os.WriteFile(rootPath, r.Simulator.SignedRoots[0], 0644); err != nil {
			r.t.Fatalf("failed to write root.json: %v", err)
		}
	}

	var err error
	r.RootBytes, err = os.ReadFile(rootPath)
	if err != nil {
		r.t.Fatalf("failed to read root bytes: %v", err)
	}
}

// Cleanup is a no-op: the temporary directory is removed automatically when
// the test completes because it was created with t.TempDir(). It is kept for
// call-site compatibility.
func (r *TestRepository) Cleanup() {}

// GetUpdaterConfig returns an UpdaterConfig configured to use this test repository
func (r *TestRepository) GetUpdaterConfig() (*config.UpdaterConfig, error) {
	cfg, err := config.New(r.MetadataDir, r.RootBytes)
	if err != nil {
		return nil, err
	}
	cfg.Fetcher = r.Simulator
	cfg.LocalMetadataDir = r.MetadataDir
	cfg.LocalTargetsDir = r.TargetsDir
	return cfg, nil
}

// GetUnsafeUpdaterConfig returns an UpdaterConfig with UnsafeLocalMode enabled
func (r *TestRepository) GetUnsafeUpdaterConfig() (*config.UpdaterConfig, error) {
	cfg, err := r.GetUpdaterConfig()
	if err != nil {
		return nil, err
	}
	cfg.UnsafeLocalMode = true
	return cfg, nil
}

// PublishRoot signs and publishes a new root
func (r *TestRepository) PublishRoot() {
	r.Simulator.PublishRoot()
}

// SetExpired marks a role's metadata as expired
func (r *TestRepository) SetExpired(role string) {
	r.SetExpiresAt(role, r.pastTime)
}

// SetExpiresAt sets the expiration time for a role's metadata
func (r *TestRepository) SetExpiresAt(role string, expires time.Time) {
	switch role {
	case metadata.ROOT:
		r.Simulator.MDRoot.Signed.Expires = expires
	case metadata.TARGETS:
		r.Simulator.MDTargets.Signed.Expires = expires
	case metadata.SNAPSHOT:
		r.Simulator.MDSnapshot.Signed.Expires = expires
	case metadata.TIMESTAMP:
		r.Simulator.MDTimestamp.Signed.Expires = expires
	}
}

// SetVersion changes version for a role
func (r *TestRepository) SetVersion(role string, version int64) {
	switch role {
	case metadata.ROOT:
		r.Simulator.MDRoot.Signed.Version = version
	case metadata.TARGETS:
		r.Simulator.MDTargets.Signed.Version = version
	case metadata.SNAPSHOT:
		r.Simulator.MDSnapshot.Signed.Version = version
	case metadata.TIMESTAMP:
		r.Simulator.MDTimestamp.Signed.Version = version
	}
}

// GetVersion returns the current version for a role
func (r *TestRepository) GetVersion(role string) int64 {
	switch role {
	case metadata.ROOT:
		return r.Simulator.MDRoot.Signed.Version
	case metadata.TARGETS:
		return r.Simulator.MDTargets.Signed.Version
	case metadata.SNAPSHOT:
		return r.Simulator.MDSnapshot.Signed.Version
	case metadata.TIMESTAMP:
		return r.Simulator.MDTimestamp.Signed.Version
	}
	return 0
}

// BumpVersion increments version for a role
func (r *TestRepository) BumpVersion(role string) {
	switch role {
	case metadata.ROOT:
		r.Simulator.MDRoot.Signed.Version++
		r.Simulator.PublishRoot()
	case metadata.TARGETS:
		r.Simulator.MDTargets.Signed.Version++
	case metadata.SNAPSHOT:
		r.Simulator.MDSnapshot.Signed.Version++
	case metadata.TIMESTAMP:
		r.Simulator.MDTimestamp.Signed.Version++
	}
}

// RemoveSigners removes signers for a role (for testing unsigned metadata)
func (r *TestRepository) RemoveSigners(role string) {
	delete(r.Simulator.Signers, role)
}

// RotateKeys rotates keys for a role
func (r *TestRepository) RotateKeys(role string) {
	r.Simulator.RotateKeys(role)
}

// AddTarget adds a target file to the repository
func (r *TestRepository) AddTarget(role string, content []byte, path string) {
	r.Simulator.AddTarget(role, content, path)
}

// UpdateSnapshot updates snapshot metadata and timestamp
func (r *TestRepository) UpdateSnapshot() {
	r.Simulator.UpdateSnapshot()
}

// UpdateTimestamp updates only timestamp metadata
func (r *TestRepository) UpdateTimestamp() {
	r.Simulator.UpdateTimestamp()
}

// EnableComputeHashesAndLength enables hash/length computation for meta files
func (r *TestRepository) EnableComputeHashesAndLength() {
	r.Simulator.ComputeMetafileHashesAndLength = true
}

// DisableComputeHashesAndLength disables hash/length computation for meta files
func (r *TestRepository) DisableComputeHashesAndLength() {
	r.Simulator.ComputeMetafileHashesAndLength = false
}

// PastTime returns a time in the past for expiration testing
func (r *TestRepository) PastTime() time.Time {
	return r.pastTime
}

// SetSnapshotMeta sets the meta information for a role in snapshot
func (r *TestRepository) SetSnapshotMeta(role string, version int64) {
	r.Simulator.MDSnapshot.Signed.Meta[fmt.Sprintf("%s.json", role)].Version = version
}

// SetTimestampSnapshotMeta sets the snapshot meta information in timestamp
func (r *TestRepository) SetTimestampSnapshotMeta(version int64) {
	r.Simulator.MDTimestamp.Signed.Meta["snapshot.json"].Version = version
}

// AssertFilesExist asserts that local metadata files exist for the given roles
func (r *TestRepository) AssertFilesExist(roles []string) {
	r.t.Helper()

	expectedFiles := make(map[string]bool)
	for _, role := range roles {
		expectedFiles[fmt.Sprintf("%s.json", role)] = true
	}

	files, err := os.ReadDir(r.MetadataDir)
	if err != nil {
		r.t.Fatalf("failed to read metadata dir: %v", err)
	}

	actualFiles := make(map[string]bool)
	for _, f := range files {
		actualFiles[f.Name()] = true
	}

	for expected := range expectedFiles {
		if !actualFiles[expected] {
			r.t.Errorf("expected file %s not found in metadata dir", expected)
		}
	}
}

// AssertFilesExact asserts that exactly these files exist in the metadata dir
func (r *TestRepository) AssertFilesExact(roles []string) {
	r.t.Helper()

	expectedFiles := make(map[string]bool)
	for _, role := range roles {
		expectedFiles[fmt.Sprintf("%s.json", role)] = true
	}

	files, err := os.ReadDir(r.MetadataDir)
	if err != nil {
		r.t.Fatalf("failed to read metadata dir: %v", err)
	}

	actualFiles := make(map[string]bool)
	for _, f := range files {
		actualFiles[f.Name()] = true
	}

	if len(expectedFiles) != len(actualFiles) {
		r.t.Errorf("expected %d files, got %d", len(expectedFiles), len(actualFiles))
	}

	for expected := range expectedFiles {
		if !actualFiles[expected] {
			r.t.Errorf("expected file %s not found", expected)
		}
	}

	for actual := range actualFiles {
		if !expectedFiles[actual] {
			r.t.Errorf("unexpected file %s found", actual)
		}
	}
}

// AssertVersionEquals asserts that a local metadata file has the expected version
func (r *TestRepository) AssertVersionEquals(role string, expectedVersion int64) {
	r.t.Helper()

	path := filepath.Join(r.MetadataDir, fmt.Sprintf("%s.json", role))

	switch role {
	case metadata.ROOT:
		md, err := r.Simulator.MDRoot.FromFile(path)
		if err != nil {
			r.t.Fatalf("failed to load %s: %v", role, err)
		}
		if md.Signed.Version != expectedVersion {
			r.t.Errorf("expected %s version %d, got %d", role, expectedVersion, md.Signed.Version)
		}
	case metadata.TARGETS:
		md, err := r.Simulator.MDTargets.FromFile(path)
		if err != nil {
			r.t.Fatalf("failed to load %s: %v", role, err)
		}
		if md.Signed.Version != expectedVersion {
			r.t.Errorf("expected %s version %d, got %d", role, expectedVersion, md.Signed.Version)
		}
	case metadata.TIMESTAMP:
		md, err := r.Simulator.MDTimestamp.FromFile(path)
		if err != nil {
			r.t.Fatalf("failed to load %s: %v", role, err)
		}
		if md.Signed.Version != expectedVersion {
			r.t.Errorf("expected %s version %d, got %d", role, expectedVersion, md.Signed.Version)
		}
	case metadata.SNAPSHOT:
		md, err := r.Simulator.MDSnapshot.FromFile(path)
		if err != nil {
			r.t.Fatalf("failed to load %s: %v", role, err)
		}
		if md.Signed.Version != expectedVersion {
			r.t.Errorf("expected %s version %d, got %d", role, expectedVersion, md.Signed.Version)
		}
	}
}

// AssertContentEquals asserts that local file content matches the simulator's metadata
func (r *TestRepository) AssertContentEquals(role string, version *int) {
	r.t.Helper()

	expectedContent, err := r.Simulator.FetchMetadata(role, version)
	if err != nil {
		r.t.Fatalf("failed to fetch expected metadata: %v", err)
	}

	actualContent, err := os.ReadFile(filepath.Join(r.MetadataDir, fmt.Sprintf("%s.json", role)))
	if err != nil {
		r.t.Fatalf("failed to read actual metadata: %v", err)
	}

	if string(expectedContent) != string(actualContent) {
		r.t.Errorf("content mismatch for %s", role)
	}
}

// ReloadRootBytes reloads the root bytes from the metadata directory
func (r *TestRepository) ReloadRootBytes() error {
	rootPath := filepath.Join(r.MetadataDir, "root.json")
	bytes, err := os.ReadFile(rootPath)
	if err != nil {
		return err
	}
	r.RootBytes = bytes
	return nil
}

// WriteRoot writes root metadata to the metadata directory
func (r *TestRepository) WriteRoot(version int) error {
	if version < 1 || version > len(r.Simulator.SignedRoots) {
		return fmt.Errorf("invalid root version: %d", version)
	}
	rootPath := filepath.Join(r.MetadataDir, "root.json")
	return os.WriteFile(rootPath, r.Simulator.SignedRoots[version-1], 0644)
}
