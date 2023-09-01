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

	RepoDir = fmt.Sprintf("%s/repository_data/repository", TempDir)
	absPath, err := filepath.Abs(repoPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	err = Copy(absPath, RepoDir)
	if err != nil {
		return fmt.Errorf("failed to copy metadata to %s: %w", RepoDir, err)
	}

	TargetsDir = fmt.Sprintf("%s/repository_data/repository/targets", TempDir)
	targetsAbsPath, err := filepath.Abs(targetsPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute targets path: %w", err)
	}
	err = Copy(targetsAbsPath, TargetsDir)
	if err != nil {
		return fmt.Errorf("failed to copy metadata to %s: %w", RepoDir, err)
	}

	KeystoreDir = fmt.Sprintf("%s/keystore", TempDir)
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
		data, err := os.ReadFile(fmt.Sprintf("%s/%s", fromPath, file.Name()))
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file.Name(), err)
		}
		filePath := fmt.Sprintf("%s/%s", toPath, file.Name())
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
