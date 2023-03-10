// Copyright 2022-2023 VMware, Inc.
//
// This product is licensed to you under the BSD-2 license (the "License").
// You may not use this product except in compliance with the BSD-2 License.
// This product may include a number of subcomponents with separate copyright
// notices and license terms. Your use of these subcomponents is subject to
// the terms and conditions of the subcomponent's license, as noted in the
// LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/rdimitrov/go-tuf-metadata/metadata/config"
	"github.com/rdimitrov/go-tuf-metadata/metadata/updater"
)

// The following config is used to fetch a target from Jussi's GitHub repository example
const (
	baseURL            = "https://jku.github.io/tuf-demo"
	baseURLMetadataDir = "metadata"
	baseURLTargetsDir  = "targets"
	targetName         = "demo/succinctly-delegated-5.txt"
	verbosity          = log.InfoLevel
)

// The following config is used to fetch a target from a local RSTUF deployment
// const (
// 	baseURL            = "http://127.0.0.1:8080"
// 	baseURLMetadataDir = ""
// 	baseURLTargetsDir  = ""
// 	targetName         = "file2.tar.gz"
// 	verbosity          = log.InfoLevel
// )

func main() {
	// set debug level
	log.SetLevel(verbosity)

	// initialize environment - temporary folders, etc.
	localMetadataDir, err := InitEnvironment()
	if err != nil {
		log.Fatal("Failed to initialize environment: ", err)
	}

	// initialize client with Trust-On-First-Use
	err = InitTrustOnFirstUse(localMetadataDir)
	if err != nil {
		log.Fatal("Trust-On-First-Use failed: ", err)
	}

	// download the desired target
	err = DownloadTarget(localMetadataDir, targetName)
	if err != nil {
		log.Fatal("Download failed: ", err)
	}
}

// InitEnvironment prepares the local environment - temporary folders, etc.
func InitEnvironment() (string, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}

	// create a temporary folder for storing the demo artifacts
	tmpDir, err := os.MkdirTemp(cwd, "tmp")
	if err != nil {
		return "", fmt.Errorf("failed to create a temporary folder: %w", err)
	}

	// create a destination folder for storing the downloaded target
	err = os.Mkdir(filepath.Join(tmpDir, "download"), 0750)
	if err != nil {
		return "", fmt.Errorf("failed to create a download folder: %w", err)
	}
	return tmpDir, nil
}

// InitTrustOnFirstUse initialize local trusted metadata (Trust-On-First-Use)
func InitTrustOnFirstUse(metadataDir string) error {
	// download the initial root metadata so we can bootstrap Trust-On-First-Use
	rootURL, err := url.JoinPath(baseURL, baseURLMetadataDir, "1.root.json")
	if err != nil {
		return fmt.Errorf("failed to create URL path for 1.root.json: %w", err)
	}

	req, err := http.NewRequest("GET", rootURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	client := http.DefaultClient

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to executed the http request: %w", err)
	}

	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("failed to read the http request body: %w", err)
	}

	// write the downloaded root metadata to file
	err = os.WriteFile(filepath.Join(metadataDir, "root.json"), data, 0644)
	if err != nil {
		return fmt.Errorf("failed to write root.json metadata: %w", err)
	}

	return nil
}

// DownloadTarget downloads the target file using Updater. The Updater refreshes the top-level metadata,
// get the target information, verifies if the target is already cached, and in case it
// is not cached, downloads the target file.
func DownloadTarget(localMetadataDir, target string) error {
	metadataBaseURL, _ := url.JoinPath(baseURL, baseURLMetadataDir)
	targetsBaseURL, _ := url.JoinPath(baseURL, baseURLTargetsDir)

	// create updater configuration
	cfg := config.New(localMetadataDir) // default config
	// cfg.LocalTrustedRootPath = localMetadataDir
	cfg.LocalMetadataDir = localMetadataDir
	cfg.LocalTargetsDir = filepath.Join(localMetadataDir, "download")
	cfg.RemoteMetadataURL = metadataBaseURL
	cfg.RemoteTargetsURL = targetsBaseURL
	cfg.PrefixTargetsWithHash = false // do not use hash-prefixed target files with consistent snapshots

	// create a new Updater instance
	up, err := updater.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create Updater instance: %w", err)
	}

	// try to build the top-level metadata
	err = up.Refresh()
	if err != nil {
		return fmt.Errorf("failed to refresh trusted metadata: %w", err)
	}

	// search if the desired target is available
	targetInfo, err := up.GetTargetInfo(target)
	if err != nil {
		return fmt.Errorf("target %s not found: %w", target, err)
	}

	// target is available, so let's see if the target is already present locally
	path, err := up.FindCachedTarget(targetInfo, "")
	if err != nil {
		return fmt.Errorf("failed while finding a cached target: %w", err)
	}
	if path != "" {
		log.Infof("Target %s is already present at - %s", target, path)
	}

	// target is not present locally, so let's try to download it
	path, err = up.DownloadTarget(targetInfo, "", "")
	if err != nil {
		return fmt.Errorf("failed to download target file %s - %w", target, err)
	}

	log.Infof("Successfully downloaded target %s at - %s", target, path)

	return nil
}
