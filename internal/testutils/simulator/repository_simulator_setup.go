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
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Deprecated: Global simulator variables cause race conditions when tests run in parallel
// and leak mutable state across tests. Use NewTestEnv(tb) instead for hermetic test isolation.
var (
	MetadataURL = "https://jku.github.io/tuf-demo/metadata"
	TargetsURL  = "https://jku.github.io/tuf-demo/targets"

	MetadataDir  string
	RootBytes    []byte
	PastDateTime time.Time
	Sim          *RepositorySimulator

	metadataPath = "/metadata"
	targetsPath  = "/targets"
	LocalDir     string
	DumpDir      string
)

// InitLocalEnv initializes local environment directory.
//
// Deprecated: Use NewTestEnv(tb) which automatically provisions isolated temporary
// directories via tb.TempDir() without mutating package globals.
func InitLocalEnv() error {
	tmp := os.TempDir()

	tmpDir, err := os.MkdirTemp(tmp, "0750")
	if err != nil {
		slog.Error("Failed to create temporary directory", "err", err)
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}

	if err = os.Mkdir(filepath.Join(tmpDir, metadataPath), 0750); err != nil {
		slog.Error("Repository simulator: failed to create dir", "err", err)
		return fmt.Errorf("failed to create metadata dir: %w", err)
	}

	if err = os.Mkdir(filepath.Join(tmpDir, targetsPath), 0750); err != nil {
		slog.Error("Repository simulator: failed to create dir", "err", err)
		return fmt.Errorf("failed to create targets dir: %w", err)
	}

	LocalDir = tmpDir

	return nil
}

// InitMetadataDir initializes metadata and targets directory with root metadata.
//
// Deprecated: Use NewTestEnv(tb) for isolated, hermetic testing.
func InitMetadataDir() (*RepositorySimulator, string, string, error) {
	if err := InitLocalEnv(); err != nil {
		slog.Error("Failed to initialize environment", "err", err)
		return nil, "", "", err
	}

	metadataDir := filepath.Join(LocalDir, metadataPath)

	sim := NewRepository()

	f, err := os.Create(filepath.Join(metadataDir, "root.json"))
	if err != nil {
		slog.Error("Failed to create root", "err", err)
		return nil, "", "", fmt.Errorf("failed to create root.json: %w", err)
	}
	defer f.Close()

	if _, err = f.Write(sim.SignedRoots[0]); err != nil {
		slog.Error("Repository simulator setup: failed to write signed roots", "err", err)
		return nil, "", "", fmt.Errorf("failed to write root.json: %w", err)
	}

	targetsDir := filepath.Join(LocalDir, targetsPath)
	sim.LocalDir = LocalDir
	return sim, metadataDir, targetsDir, nil
}

func GetRootBytes(localMetadataDir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(localMetadataDir, "root.json"))
}

func RepositoryCleanup(tmpDir string) {
	slog.Info("Cleaning temporary directory", "dir", tmpDir)
	os.RemoveAll(tmpDir)
}

// TestEnv encapsulates an isolated, hermetic simulator test environment
// that does not rely on shared package-level globals.
type TestEnv struct {
	Sim          *RepositorySimulator
	MetadataDir  string
	TargetsDir   string
	RootBytes    []byte
	PastDateTime time.Time
}

// NewTestEnv returns an isolated test environment with fresh metadata and targets
// directories, cleaned up automatically when the test finishes.
func NewTestEnv(tb testing.TB) (*TestEnv, error) {
	tb.Helper()
	tmpDir := tb.TempDir()

	metadataDir := filepath.Join(tmpDir, metadataPath)
	targetsDir := filepath.Join(tmpDir, targetsPath)

	if err := os.MkdirAll(metadataDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create metadata dir: %w", err)
	}
	if err := os.MkdirAll(targetsDir, 0750); err != nil {
		return nil, fmt.Errorf("failed to create targets dir: %w", err)
	}

	sim := NewRepository()
	sim.LocalDir = tmpDir

	rootPath := filepath.Join(metadataDir, "root.json")
	if err := os.WriteFile(rootPath, sim.SignedRoots[0], 0600); err != nil {
		return nil, fmt.Errorf("failed to write root.json: %w", err)
	}

	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root.json: %w", err)
	}

	return &TestEnv{
		Sim:          sim,
		MetadataDir:  metadataDir,
		TargetsDir:   targetsDir,
		RootBytes:    rootBytes,
		PastDateTime: time.Now().UTC().Truncate(24 * time.Hour).Add(-5 * 24 * time.Hour),
	}, nil
}
