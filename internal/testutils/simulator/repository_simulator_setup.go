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
	"os"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
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
		log.Fatal("failed to create temporary directory: ", err)
	}

	err = os.Mkdir(tmpDir+metadataPath, 0750)
	if err != nil {
		log.Debugf("repository simulator: failed to create dir: %v", err)
	}
	err = os.Mkdir(tmpDir+targetsPath, 0750)
	if err != nil {
		log.Debugf("repository simulator: failed to create dir: %v", err)
	}
	LocalDir = tmpDir
	return nil
}

func InitMetadataDir() (*RepositorySimulator, string, string, error) {
	err := InitLocalEnv()
	if err != nil {
		log.Fatal("failed to initialize environment: ", err)
	}
	metadataDir := filepath.Join(LocalDir, metadataPath)

	sim := NewRepository()

	f, err := os.Create(filepath.Join(metadataDir, "root.json"))
	if err != nil {
		log.Fatalf("failed to create root: %v", err)
	}

	_, err = f.Write(sim.SignedRoots[0])
	if err != nil {
		log.Debugf("repository simulator setup: failed to write signed roots: %v", err)
	}
	targetsDir := filepath.Join(LocalDir, targetsPath)
	sim.LocalDir = LocalDir
	return sim, metadataDir, targetsDir, err
}

func GetRootBytes(localMetadataDir string) ([]byte, error) {
	return os.ReadFile(filepath.Join(localMetadataDir, "root.json"))
}

func RepositoryCleanup(tmpDir string) {
	log.Printf("Cleaning temporary directory: %s\n", tmpDir)
	os.RemoveAll(tmpDir)
}
