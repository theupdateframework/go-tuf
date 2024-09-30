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
	stdlog "log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-logr/stdr"

	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/multirepo"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

const (
	metadataURL = "https://raw.githubusercontent.com/theupdateframework/go-tuf/master/examples/multirepo/repository/metadata"
	targetsURL  = "https://raw.githubusercontent.com/theupdateframework/go-tuf/master/examples/multirepo/repository/targets"
	verbosity   = 4
)

func main() {
	// set logger to stdout with info level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "multirepo_client_example", stdlog.LstdFlags)))
	stdr.SetVerbosity(verbosity)

	// Bootstrap TUF
	fmt.Printf("Bootstrapping the initial TUF repo - fetching map.json file and necessary trusted root files\n\n")
	mapBytes, trustedRoots, err := BootstrapTUF() // returns the map.json and the trusted root files
	if err != nil {
		panic(err)
	}

	// Initialize the multi-repository TUF client
	fmt.Printf("Initializing the multi-repository TUF client with the given map.json file\n\n")
	client, err := InitMultiRepoTUF(mapBytes, trustedRoots)
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
	targetInfo, repositories, err := client.GetTargetInfo("rekor.pub") // rekor.pub trusted_root.json fulcio_v1.crt.pem
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

// BootstrapTUF returns the map file and the related trusted root metadata files
func BootstrapTUF() ([]byte, map[string][]byte, error) {
	log := metadata.GetLogger()

	trustedRoots := map[string][]byte{}
	mapBytes := []byte{}
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get current working directory: %w", err)
	}
	targetsDir := filepath.Join(cwd, "bootstrap/targets")

	// ensure the necessary folder layout
	err = os.MkdirAll(targetsDir, os.ModePerm)
	if err != nil {
		return nil, nil, err
	}

	// read the trusted root metadata
	rootBytes, err := os.ReadFile(filepath.Join(cwd, "root.json"))
	if err != nil {
		return nil, nil, err
	}

	// create updater configuration
	cfg, err := config.New(metadataURL, rootBytes) // default config
	if err != nil {
		return nil, nil, err
	}
	cfg.LocalMetadataDir = filepath.Join(cwd, "bootstrap")
	cfg.LocalTargetsDir = targetsDir
	cfg.RemoteTargetsURL = targetsURL

	// create a new Updater instance
	up, err := updater.New(cfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create Updater instance: %w", err)
	}

	// build the top-level metadata
	err = up.Refresh()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to refresh trusted metadata: %w", err)
	}

	// download all target files
	for name, targetInfo := range up.GetTopLevelTargets() {
		// see if the target is already present locally
		path, _, err := up.FindCachedTarget(targetInfo, "")
		if err != nil {
			return nil, nil, fmt.Errorf("failed while finding a cached target: %w", err)
		}
		if path != "" {
			log.Info("Target is already present", "target", name, "path", path)
		}

		// target is not present locally, so let's try to download it
		// keeping the same path layout as its target path
		expectedTargetLocation := filepath.Join(targetsDir, name)
		dirName, _ := filepath.Split(expectedTargetLocation)
		err = os.MkdirAll(dirName, os.ModePerm)
		if err != nil {
			return nil, nil, err
		}

		// download targets (we don't have to actually store them other than for the sake of the example)
		path, bytes, err := up.DownloadTarget(targetInfo, expectedTargetLocation, "")
		if err != nil {
			return nil, nil, fmt.Errorf("failed to download target file %s - %w", name, err)
		}

		// populate the return values
		if name == "map.json" {
			mapBytes = bytes
		} else {
			// Target names uses forwardslash even on Windows
			repositoryName := strings.Split(name, "/")
			trustedRoots[repositoryName[0]] = bytes
		}
		log.Info("Successfully downloaded target", "target", name, "path", path)
	}

	return mapBytes, trustedRoots, nil
}

func InitMultiRepoTUF(mapBytes []byte, trustedRoots map[string][]byte) (*multirepo.MultiRepoClient, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get current working directory: %w", err)
	}

	// create a new configuration for a multi-repository client
	cfg, err := multirepo.NewConfig(mapBytes, trustedRoots)
	if err != nil {
		return nil, err
	}
	cfg.LocalMetadataDir = filepath.Join(cwd, "metadata")
	cfg.LocalTargetsDir = filepath.Join(cwd, "download")

	// create a new instance of a multi-repository TUF client
	return multirepo.New(cfg)
}
