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
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"
)

var (
	TempDir     string
	RepoDir     string
	TargetsDir  string
	KeystoreDir string
)

func SetupTestDirs() error {
	tmp := os.TempDir()
	var err error
	TempDir, err = os.MkdirTemp(tmp, "0750")
	if err != nil {
		log.Fatal("failed to create temporary directory: ", err)
		return err
	}

	RepoDir = fmt.Sprintf("%s/repository_data/repository", TempDir)
	absPath, err := filepath.Abs("../testutils/repository_data/repository/metadata")
	if err != nil {
		log.Debugf("failed to get absolute path: %v", err)
	}
	err = Copy(absPath, RepoDir)
	if err != nil {
		log.Debugf("failed to copy metadata to %s: %v", RepoDir, err)
		return err
	}

	TargetsDir = fmt.Sprintf("%s/repository_data/repository/targets", TempDir)
	targetsPath, err := filepath.Abs("../testutils/repository_data/repository/targets")
	if err != nil {
		log.Debugf("failed to get absolute targets path: %v", err)
	}
	err = Copy(targetsPath, TargetsDir)
	if err != nil {
		log.Debugf("failed to copy metadata to %s: %v", RepoDir, err)
		return err
	}

	KeystoreDir = fmt.Sprintf("%s/keystore", TempDir)
	err = os.Mkdir(KeystoreDir, 0750)
	if err != nil {
		log.Debugf("failed to create keystore dir %s: %v", KeystoreDir, err)
	}
	absPath, err = filepath.Abs("../testutils/repository_data/keystore")
	if err != nil {
		log.Debugf("failed to get absolute path: %v", err)
	}
	err = Copy(absPath, KeystoreDir)
	if err != nil {
		log.Debugf("failed to copy keystore to %s: %v", KeystoreDir, err)
		return err
	}

	return nil
}

func Copy(fromPath string, toPath string) error {
	err := os.MkdirAll(toPath, 0750)
	if err != nil {
		log.Debugf("failed to create directory %s: %v", toPath, err)
	}
	files, err := os.ReadDir(fromPath)
	if err != nil {
		log.Debugf("failed to read path %s: %v", fromPath, err)
		return err
	}
	for _, file := range files {
		data, err := os.ReadFile(fmt.Sprintf("%s/%s", fromPath, file.Name()))
		if err != nil {
			log.Debugf("failed to read file %s: %v", file.Name(), err)
		}
		filePath := fmt.Sprintf("%s/%s", toPath, file.Name())
		err = os.WriteFile(filePath, data, 0750)
		if err != nil {
			log.Debugf("failed to write file %s: %v", filePath, err)
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
