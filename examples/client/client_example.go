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

package main

import (
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/go-logr/stdr"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// The following config is used to fetch a target from Jussi's GitHub repository example
const (
	metadataURL          = "https://jku.github.io/tuf-demo/metadata"
	targetsURL           = "https://jku.github.io/tuf-demo/targets"
	targetName           = "rdimitrov/artifact-example.md"
	verbosity            = 4
	generateRandomFolder = false
)

func main() {
	// set logger to stdout with info level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "client_example", stdlog.LstdFlags)))
	stdr.SetVerbosity(verbosity)

	log := metadata.GetLogger()

	// initialize environment - temporary folders, etc.
	metadataDir, err := InitEnvironment()
	if err != nil {
		log.Error(err, "Failed to initialize environment")
	}

	// initialize client with Trust-On-First-Use
	err = InitTrustOnFirstUse(metadataDir)
	if err != nil {
		log.Error(err, "Trust-On-First-Use failed")
	}

	// download the desired target
	err = DownloadTarget(metadataDir, targetName)
	if err != nil {
		log.Error(err, "Download failed")
	}
}

// InitEnvironment prepares the local environment - temporary folders, etc.
func InitEnvironment() (string, error) {
	var tmpDir string
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	if !generateRandomFolder {
		tmpDir = filepath.Join(cwd, "tmp")
		// create a temporary folder for storing the demo artifacts
		os.Mkdir(tmpDir, 0750)
	} else {
		// create a temporary folder for storing the demo artifacts
		tmpDir, err = os.MkdirTemp(cwd, "tmp")
		if err != nil {
			return "", fmt.Errorf("failed to create a temporary folder: %w", err)
		}
	}

	// create a destination folder for storing the downloaded target
	os.Mkdir(filepath.Join(tmpDir, "download"), 0750)
	return tmpDir, nil
}

// InitTrustOnFirstUse initialize local trusted metadata (Trust-On-First-Use)
func InitTrustOnFirstUse(metadataDir string) error {
	// check if there's already a local root.json available for bootstrapping trust
	_, err := os.Stat(filepath.Join(metadataDir, "root.json"))
	if err == nil {
		return nil
	}

	// download the initial root metadata so we can bootstrap Trust-On-First-Use
	rootURL, err := url.JoinPath(metadataURL, "1.root.json")
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
	log := metadata.GetLogger()

	rootBytes, err := os.ReadFile(filepath.Join(localMetadataDir, "root.json"))
	if err != nil {
		return err
	}
	// create updater configuration
	cfg, err := config.New(metadataURL, rootBytes) // default config
	if err != nil {
		return err
	}
	cfg.LocalMetadataDir = localMetadataDir
	cfg.LocalTargetsDir = filepath.Join(localMetadataDir, "download")
	cfg.RemoteTargetsURL = targetsURL
	cfg.PrefixTargetsWithHash = true

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
	path, _, err := up.FindCachedTarget(targetInfo, "")
	if err != nil {
		return fmt.Errorf("failed while finding a cached target: %w", err)
	}
	if path != "" {
		log.Info("Target is already present", "target", target, "path", path)
	}

	// target is not present locally, so let's try to download it
	path, _, err = up.DownloadTarget(targetInfo, "", "",cfg.Timeout)
	if err != nil {
		return fmt.Errorf("failed to download target file %s - %w", target, err)
	}

	log.Info("Successfully downloaded target", "target", target, "path", path)

	return nil
}
