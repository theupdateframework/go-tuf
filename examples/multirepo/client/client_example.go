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
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/rdimitrov/go-tuf-metadata/metadata/config"
	"github.com/rdimitrov/go-tuf-metadata/metadata/multirepo"
	"github.com/rdimitrov/go-tuf-metadata/metadata/updater"
)

const (
	metadataURL = "https://raw.githubusercontent.com/rdimitrov/go-tuf-metadata/main/examples/multirepo/repository/metadata"
	targetsURL  = "https://raw.githubusercontent.com/rdimitrov/go-tuf-metadata/main/examples/multirepo/repository/targets"
	verbosity   = log.InfoLevel
)

func main() {
	// set debug level
	log.SetLevel(verbosity)

	// Bootstrap TUF
	fmt.Printf("Bootstrapping the initial TUF repo - fetching map.json file and necessary trusted root files\n\n")
	targetsDir, err := BootstrapTUF() // returns the path to map.json and the trusted root files
	if err != nil {
		panic(err)
	}

	// Initialize the multi-repository TUF client
	fmt.Printf("Initializing the multi-repository TUF client with the given map.json file\n\n")
	client, err := InitMultiRepoTUF(targetsDir)
	if err != nil {
		panic(err)
	}

	// Refresh all repositories
	fmt.Printf("Refreshing each TUF client (updating metadata/client update workflow)\n\n")
	err = client.Refresh()
	if err != nil {
		panic(err)
	}

	// Get target info for the given target
	fmt.Printf("Searching for a target using the multi-repository TUF client\n\n")
	targetInfo, repositories, err := client.GetTargetInfo("fulcio_v1.crt.pem") // rekor.pub
	if err != nil {
		panic(err)
	}

	// Download the target using that target info
	fmt.Println("Downloading a target using the multi-repository TUF client")
	_, _, err = client.DownloadTarget(repositories, targetInfo, "", "")
	if err != nil {
		panic(err)
	}
}

func BootstrapTUF() (string, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}

	targetsDir := filepath.Join(cwd, "bootstrap/targets")
	// ensure the necessary folder layout
	err = os.MkdirAll(targetsDir, os.ModePerm)
	if err != nil {
		return "", err
	}

	// read the trusted root metadata
	rootBytes, err := os.ReadFile(filepath.Join(cwd, "root.json"))
	if err != nil {
		return "", err
	}

	// create updater configuration
	cfg, err := config.New(metadataURL, rootBytes) // default config
	if err != nil {
		return "", err
	}
	cfg.LocalMetadataDir = filepath.Join(cwd, "bootstrap")
	cfg.LocalTargetsDir = targetsDir
	cfg.RemoteTargetsURL = targetsURL

	// create a new Updater instance
	up, err := updater.New(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create Updater instance: %w", err)
	}

	// try to build the top-level metadata
	err = up.Refresh()
	if err != nil {
		return "", fmt.Errorf("failed to refresh trusted metadata: %w", err)
	}
	for name, targetInfo := range up.GetTopLevelTargets() {
		// see if the target is already present locally
		path, _, err := up.FindCachedTarget(targetInfo, "")
		if err != nil {
			return "", fmt.Errorf("failed while finding a cached target: %w", err)
		}
		if path != "" {
			log.Infof("Target %s is already present at - %s", name, path)
		}
		// target is not present locally, so let's try to download it
		// keeping the same path layout as its target path
		expectedTargetLocation := filepath.Join(targetsDir, name)
		dirName, _ := filepath.Split(expectedTargetLocation)
		err = os.MkdirAll(dirName, os.ModePerm)
		if err != nil {
			return "", err
		}
		// download targets
		path, _, err = up.DownloadTarget(targetInfo, expectedTargetLocation, "")
		if err != nil {
			return "", fmt.Errorf("failed to download target file %s - %w", name, err)
		}
		log.Infof("Successfully downloaded target %s at - %s", name, path)
	}
	return cfg.LocalTargetsDir, nil
}

func InitMultiRepoTUF(bootstrapDir string) (*multirepo.MultiRepoClient, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	// create a new configuration for a multi-repository client
	cfg, err := multirepo.NewConfig(bootstrapDir)
	if err != nil {
		return nil, err
	}
	cfg.LocalMetadataDir = filepath.Join(cwd, "metadata")
	cfg.LocalTargetsDir = filepath.Join(cwd, "download")

	// create a new instance of a multi-repository TUF client
	return multirepo.New(cfg)
}
