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
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

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

func InitLocalEnv() error {
	tmp := os.TempDir()

	tmpDir, err := os.MkdirTemp(tmp, "0750")
	if err != nil {
		slog.Error("Failed to create temporary directory", "err", err)
		os.Exit(1)
	}

	if err = os.Mkdir(filepath.Join(tmpDir, metadataPath), 0750); err != nil {
		slog.Error("Repository simulator: failed to create dir", "err", err)
	}

	if err = os.Mkdir(filepath.Join(tmpDir, targetsPath), 0750); err != nil {
		slog.Error("Repository simulator: failed to create dir", "err", err)
	}

	LocalDir = tmpDir

	return nil
}

func InitMetadataDir() (*RepositorySimulator, string, string, error) {
	if err := InitLocalEnv(); err != nil {
		slog.Error("Failed to initialize environment", "err", err)
		os.Exit(1)
	}

	metadataDir := filepath.Join(LocalDir, metadataPath)

	sim := NewRepository()

	f, err := os.Create(filepath.Join(metadataDir, "root.json"))
	if err != nil {
		slog.Error("Failed to create root", "err", err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err = f.Write(sim.SignedRoots[0]); err != nil {
		slog.Error("Repository simulator setup: failed to write signed roots", "err", err)
	}

	targetsDir := filepath.Join(LocalDir, targetsPath)
	sim.LocalDir = LocalDir
	return sim, metadataDir, targetsDir, err
}

func GetRootBytes(localMetadataDir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(localMetadataDir, "root.json"))
}

func RepositoryCleanup(tmpDir string) {
	slog.Info("Cleaning temporary directory", "dir", tmpDir)
	os.RemoveAll(tmpDir)
}
