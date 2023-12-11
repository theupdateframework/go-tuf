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
	stdlog "log"
	"os"
	"path/filepath"

	"github.com/go-logr/stdr"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

var targetsURL string
var useNonHashPrefixedTargetFiles bool

type localConfig struct {
	MetadataDir string
	DownloadDir string
	MetadataURL string
	TargetsURL  string
}

var getCmd = &cobra.Command{
	Use:     "get",
	Aliases: []string{"g"},
	Short:   "Download a target file",
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if RepositoryURL == "" {
			fmt.Println("Error: required flag(s) \"url\" not set")
			os.Exit(1)
		}
		return GetCmd(args[0])
	},
}

func init() {
	getCmd.Flags().StringVarP(&targetsURL, "turl", "t", "", "URL of where the target files are hosted")
	getCmd.Flags().BoolVarP(&useNonHashPrefixedTargetFiles, "nonprefixed", "", false, "Do not use hash-prefixed target files with consistent snapshots")
	rootCmd.AddCommand(getCmd)
}

func GetCmd(target string) error {
	// set logger and debug verbosity level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "get_cmd", stdlog.LstdFlags)))
	if Verbosity {
		stdr.SetVerbosity(5)
	}

	// verify the client environment was initialized and fetch path names
	env, err := verifyEnv()
	if err != nil {
		return err
	}
	// read the trusted root metadata
	rootBytes, err := os.ReadFile(filepath.Join(env.MetadataDir, "root.json"))
	if err != nil {
		return err
	}

	// updater configuration
	cfg, err := config.New(env.MetadataURL, rootBytes) // default config
	if err != nil {
		return err
	}
	cfg.LocalMetadataDir = env.MetadataDir
	cfg.LocalTargetsDir = env.DownloadDir
	cfg.RemoteTargetsURL = env.TargetsURL
	cfg.PrefixTargetsWithHash = !useNonHashPrefixedTargetFiles

	// create an Updater instance
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
		fmt.Printf("Target %s is already present at - %s\n", target, path)
		return nil
	}

	// target is not present locally, so let's try to download it
	path, _, err = up.DownloadTarget(targetInfo, "", "")
	if err != nil {
		return fmt.Errorf("failed to download target file %s - %w", target, err)
	}

	fmt.Printf("Successfully downloaded target %s at - %s\n", target, path)

	return nil
}

func verifyEnv() (*localConfig, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	// if no targetsURL is set, we expect that the target files are located at the same location where the metadata is
	if targetsURL == "" {
		targetsURL = RepositoryURL
	}
	// start populating what we need
	env := &localConfig{
		MetadataDir: filepath.Join(cwd, DefaultMetadataDir),
		DownloadDir: filepath.Join(cwd, DefaultDownloadDir),
		MetadataURL: RepositoryURL,
		TargetsURL:  targetsURL,
	}

	// verify there's local metadata folder
	_, err = os.Stat(env.MetadataDir)
	if err != nil {
		return nil, fmt.Errorf("no local metadata folder: %w", err)
	}
	// verify there's local download folder
	_, err = os.Stat(env.DownloadDir)
	if err != nil {
		return nil, fmt.Errorf("no local download folder: %w", err)
	}
	// verify there's a local root.json available for bootstrapping trust
	_, err = os.Stat(filepath.Join(env.MetadataDir, fmt.Sprintf("%s.json", metadata.ROOT)))
	if err != nil {
		return nil, fmt.Errorf("no local download folder: %w", err)
	}
	return env, nil
}
