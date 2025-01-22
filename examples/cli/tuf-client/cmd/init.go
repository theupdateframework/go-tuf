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

package cmd

import (
	"fmt"
	"io"
	stdlog "log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/go-logr/stdr"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

var rootPath string

var initCmd = &cobra.Command{
	Use:     "init",
	Aliases: []string{"i"},
	Short:   "Initialize the client with trusted root.json metadata",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		if RepositoryURL == "" {
			fmt.Println("Error: required flag(s) \"url\" not set")
			os.Exit(1)
		}
		return InitializeCmd()
	},
}

func init() {
	initCmd.Flags().StringVarP(&rootPath, "file", "f", "", "location of the trusted root metadata file")
	rootCmd.AddCommand(initCmd)
}

func InitializeCmd() error {
	copyTrusted := true
	// set logger and debug verbosity level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "ini_cmd", stdlog.LstdFlags)))
	if Verbosity {
		stdr.SetVerbosity(5)
	}

	// prepare the local environment
	localMetadataDir, err := prepareEnvironment()
	if err != nil {
		return err
	}

	// if there's no root.json file passed, try to download the 1.root.json from the repository URL
	if rootPath == "" {

		fmt.Printf("No root.json file was provided. Trying to download one from %s\n", RepositoryURL)
		rootPath, err = fetchTrustedRoot(localMetadataDir)
		if err != nil {
			return err
		}
		rootPath = filepath.Join(rootPath, fmt.Sprintf("%s.json", metadata.ROOT))
		// no need to copy root.json to the metadata folder as we already download it in the expected location
		copyTrusted = false
	}

	// read the content of root.json
	rootBytes, err := os.ReadFile(rootPath)
	if err != nil {
		return err
	}

	// verify the content
	_, err = trustedmetadata.New(rootBytes)
	if err != nil {
		return err
	}

	// Save the trusted root.json file to the metadata folder so it is available for future operations (if we haven't downloaded it)
	if copyTrusted {
		err = os.WriteFile(filepath.Join(localMetadataDir, rootPath), rootBytes, 0644)
		if err != nil {
			return err
		}
	}

	fmt.Println("Initialization successful")

	return nil
}

// prepareEnvironment prepares the local environment
func prepareEnvironment() (string, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get current working directory: %w", err)
	}
	metadataPath := filepath.Join(cwd, DefaultMetadataDir)
	downloadPath := filepath.Join(cwd, DefaultDownloadDir)

	// create a folder for storing the artifacts
	err = os.Mkdir(metadataPath, 0750)
	if err != nil {
		return "", fmt.Errorf("failed to create local metadata folder: %w", err)
	}

	// create a destination folder for storing the downloaded target
	err = os.Mkdir(downloadPath, 0750)
	if err != nil {
		return "", fmt.Errorf("failed to create download folder: %w", err)
	}
	return metadataPath, nil
}

// fetchTrustedRoot downloads the initial root metadata
func fetchTrustedRoot(metadataDir string) (string, error) {
	// download the initial root metadata so we can bootstrap Trust-On-First-Use
	rootURL, err := url.JoinPath(RepositoryURL, "1.root.json")
	if err != nil {
		return "", fmt.Errorf("failed to create URL path for 1.root.json: %w", err)
	}

	req, err := http.NewRequest("GET", rootURL, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create http request: %w", err)
	}

	client := http.DefaultClient

	res, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to executed the http request: %w", err)
	}

	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read the http request body: %w", err)
	}

	// write the downloaded root metadata to file
	err = os.WriteFile(filepath.Join(metadataDir, "root.json"), data, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write root.json metadata: %w", err)
	}
	return metadataDir, nil
}
