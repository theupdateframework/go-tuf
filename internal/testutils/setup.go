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

package testutils

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

var (
	TempDir     string
	RepoDir     string
	TargetsDir  string
	KeystoreDir string
)

func SetupTestDirs(repoPath string, targetsPath string, keystorePath string) error {
	tmp := os.TempDir()
	var err error
	TempDir, err = os.MkdirTemp(tmp, "0750")
	if err != nil {
		return fmt.Errorf("failed to create temporary directory: %w", err)
	}

	RepoDir = filepath.Join(TempDir, "repository_data", "repository")
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	err = Copy(absPath, RepoDir)
	if err != nil {
		return fmt.Errorf("failed to copy metadata to %s: %w", RepoDir, err)
	}

	TargetsDir = filepath.Join(TempDir, "repository_data", "repository", "targets")
	targetsAbsPath, err := filepath.Abs(targetsPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute targets path: %w", err)
	}
	err = Copy(targetsAbsPath, TargetsDir)
	if err != nil {
		return fmt.Errorf("failed to copy metadata to %s: %w", RepoDir, err)
	}

	KeystoreDir = filepath.Join(TempDir, "keystore")
	err = os.Mkdir(KeystoreDir, 0750)
	if err != nil {
		return fmt.Errorf("failed to create keystore dir %s: %w", KeystoreDir, err)
	}
	absPath, err = filepath.Abs(keystorePath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	err = Copy(absPath, KeystoreDir)
	if err != nil {
		return fmt.Errorf("failed to copy keystore to %s: %w", KeystoreDir, err)
	}

	return nil
}

func Copy(fromPath string, toPath string) error {
	err := os.MkdirAll(toPath, 0750)
	if err != nil {
		return fmt.Errorf("failed to create directory %s: %w", toPath, err)
	}
	files, err := os.ReadDir(fromPath)
	if err != nil {
		return fmt.Errorf("failed to read path %s: %w", fromPath, err)
	}
	for _, file := range files {
		data, err := os.ReadFile(filepath.Join(fromPath, file.Name()))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file.Name(), err)
		}
		filePath := filepath.Join(toPath, file.Name())
		err = os.WriteFile(filePath, data, 0750)
		if err != nil {
			return fmt.Errorf("failed to write file %s: %w", filePath, err)
		}
	}
	return nil
}

func Cleanup() {
	log.Printf("cleaning temporary directory: %s\n", TempDir)
	err := os.RemoveAll(TempDir)
	if err != nil {
		log.Fatalf("failed to cleanup test directories: %v", err)
	}
}
