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

package multirepo

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/metadata/config"
	"github.com/rdimitrov/go-tuf-metadata/metadata/updater"
	log "github.com/sirupsen/logrus"
)

// The following represent the map file described in TAP 4
type Mapping struct {
	Paths        []string `json:"paths"`
	Repositories []string `json:"repositories"`
	Threshold    int      `json:"threshold"`
	Terminating  bool     `json:"terminating"`
}

type MultiRepoMapType struct {
	Repositories map[string][]string `json:"repositories"`
	Mapping      []*Mapping          `json:"mapping"`
}

// MultiRepoConfig represents the configuration for a set of trusted TUF clients
type MultiRepoConfig struct {
	RepoMap           *MultiRepoMapType
	TrustedRoots      map[string][]byte
	LocalMetadataDir  string
	LocalTargetsDir   string
	DisableLocalCache bool
}

// MultiRepoClient represents a multi-repository TUF client
type MultiRepoClient struct {
	TUFClients map[string]*updater.Updater
	Config     *MultiRepoConfig
}

// NewConfig returns configuration for a multi-repo TUF client
func NewConfig(repoMap []byte, roots map[string][]byte) (*MultiRepoConfig, error) {
	// error if we don't have the necessary arguments
	if len(repoMap) == 0 || len(roots) == 0 {
		return nil, fmt.Errorf("failed to create multi-repository config: no map file and/or trusted root metadata is provided")
	}

	// unmarshal the map file (note: should we expect/support unrecognized values here?)
	var mapFile *MultiRepoMapType
	if err := json.Unmarshal(repoMap, &mapFile); err != nil {
		return nil, err
	}

	// make sure we have enough trusted root metadata files provided based on the repository list
	for repo := range mapFile.Repositories {
		// check if we have a trusted root metadata for this repository
		_, ok := roots[repo]
		if !ok {
			return nil, fmt.Errorf("no trusted root metadata provided for repository - %s", repo)
		}
	}

	return &MultiRepoConfig{
		RepoMap:      mapFile,
		TrustedRoots: roots,
	}, nil
}

// New returns a multi-repository TUF client. All repositories described in the provided map file are initialized too
func New(config *MultiRepoConfig) (*MultiRepoClient, error) {
	// create a multi repo client instance
	client := &MultiRepoClient{
		Config:     config,
		TUFClients: map[string]*updater.Updater{},
	}

	// create TUF clients for each repository listed in the map file
	if err := client.initTUFClients(); err != nil {
		return nil, err
	}
	return client, nil
}

// initTUFClients loop through all repositories listed in the map file and create a TUF client for each
func (client *MultiRepoClient) initTUFClients() error {

	// loop through each repository listed in the map file and initialize it
	for repoName, repoURL := range client.Config.RepoMap.Repositories {
		log.Infof("Initializing %s - %s", repoName, repoURL[0])

		// get the trusted root file from the location specified in the map file relevant to its path
		// NOTE: the root.json file is expected to be in a folder named after the repository it corresponds to placed in the same folder as the map file
		// i.e <client.cfg.BootstrapDir>/<repo-name>/root.json
		rootBytes, ok := client.Config.TrustedRoots[repoName]
		if !ok {
			return fmt.Errorf("failed to get trusted root metadata from config for repository - %s", repoName)
		}

		// path of where each of the repository's metadata files will be persisted
		metadataDir := filepath.Join(client.Config.LocalMetadataDir, repoName)

		// location of where the target files will be downloaded (propagated to each client from the multi-repo config)
		// WARNING: Do note that using a single folder for storing targets from various repositories as it might lead to a conflict
		targetsDir := client.Config.LocalTargetsDir
		if len(client.Config.LocalTargetsDir) == 0 {
			// if it was not set, create a targets folder under each repository so there's no chance of conflict
			targetsDir = filepath.Join(metadataDir, "targets")
		}

		// ensure paths exist, doesn't do anything if caching is disabled
		err := client.Config.EnsurePathsExist()
		if err != nil {
			return err
		}

		// default config for a TUF Client
		cfg, err := config.New(repoURL[0], rootBytes) // support only one mirror for the time being
		if err != nil {
			return err
		}
		cfg.LocalMetadataDir = metadataDir
		cfg.LocalTargetsDir = targetsDir
		cfg.DisableLocalCache = client.Config.DisableLocalCache // propagate global cache policy

		// create a new Updater instance for each repository
		repoTUFClient, err := updater.New(cfg)
		if err != nil {
			return fmt.Errorf("failed to create Updater instance: %w", err)
		}

		// save the client
		client.TUFClients[repoName] = repoTUFClient
		log.Debugf("Successfully initialized %s - %s", repoName, repoURL)
	}
	return nil
}

// Refresh refreshes all repository clients
func (client *MultiRepoClient) Refresh() error {
	// loop through each initialized TUF client and refresh it
	for name, repoTUFClient := range client.TUFClients {
		log.Infof("Refreshing %s", name)
		err := repoTUFClient.Refresh()
		if err != nil {
			return err
		}
	}
	return nil
}

// GetTopLevelTargets returns the top-level target files for all repositories
func (client *MultiRepoClient) GetTopLevelTargets() (map[string]*metadata.TargetFiles, error) {
	// collection of all target files for all clients
	result := map[string]*metadata.TargetFiles{}

	// loop through each repository
	for _, tufClient := range client.TUFClients {
		// loop through the top level targets for each repository
		for targetName := range tufClient.GetTopLevelTargets() {
			// see if this target should be kept, this goes through the TAP4 search algorithm\
			targetInfo, _, err := client.GetTargetInfo(targetName)
			if err != nil {
				// we skip saving this target since there's no way/policy do download it with this map.json file
				// possible causes like not enough repositories for that threshold, target info mismatch, etc.
				return nil, err
			}
			// check if this target file is already present in the collection
			if val, ok := result[targetName]; ok {
				// target file is already present
				if !val.Equal(*targetInfo) {
					// target files have the same target name but have different target infos
					// this means the map.json file allows downloading two different target infos mapped to the same target name
					// TODO: confirm if this should raise an error
					return nil, fmt.Errorf("target name conflict")
				}
				// same target info, no need to do anything
			} else {
				// save the target
				result[targetName] = targetInfo
			}
		}
	}
	return result, nil
}

// GetTargetInfo returns metadata.TargetFiles instance with information
// for targetPath and a list of repositories that serve the matching target.
// It implements the TAP 4 search algorithm.
func (client *MultiRepoClient) GetTargetInfo(targetPath string) (*metadata.TargetFiles, []string, error) {
	terminated := false
	// loop through each mapping
	for _, eachMap := range client.Config.RepoMap.Mapping {
		// loop through each path for this mapping
		for _, pathPattern := range eachMap.Paths {
			// check if the targetPath matches each path mapping
			patternMatched, err := filepath.Match(pathPattern, targetPath)
			if err != nil {
				// error looking for a match
				return nil, nil, err
			} else {
				if patternMatched {
					// if there's a pattern match, loop through all of the repositories listed for that mapping
					// and verify if all serve the same target infos
					var targetInfo *metadata.TargetFiles
					var repositories []string
					threshold := 0
					for _, repoName := range eachMap.Repositories {
						newTargetInfo, err := client.TUFClients[repoName].GetTargetInfo(targetPath)
						if err != nil {
							// failed to get target info for the given target
							// there's probably no such target
							// skip the rest and proceed trying to get target info from the next repository
							continue
						}
						// if there's no target info saved yet, save it
						if targetInfo == nil && newTargetInfo != nil {
							targetInfo = newTargetInfo
							threshold += 1
							repositories = append(repositories, repoName)
							continue
						}
						// compare the existing one with what we got
						if targetInfo.Equal(*newTargetInfo) {
							// they are equal, so we just bump the threshold counter
							threshold += 1
							repositories = append(repositories, repoName)
							// try to do an early exit
							if eachMap.Threshold <= threshold {
								// we have enough repositories with matching target infos so safely return
								return targetInfo, repositories, nil
							}
							continue
						}
						// at this point there was a target info with that name in this repository but it didn't match
						// proceed with searching for this target in the next repository
					}
					// we went through all repositories listed in that mapping
					// exit if we have matched the threshold
					if eachMap.Threshold <= threshold {
						// we have enough repositories with matching target infos so safely return
						return targetInfo, repositories, nil
					}
					// if we are here, we haven't found enough target infos to match the threshold number
					// for this mapping
					if eachMap.Terminating {
						// stop the search if this was a terminating map
						terminated = eachMap.Terminating
						break
					}
				}
			}
			// no match, continue looking at the next path pattern from this mapping
		}
		// stop the search if this was a terminating map, otherwise continue with the next mapping
		if terminated {
			break
		}
	}
	// looped through all mappings and there was nothing, not even a terminating one
	return nil, nil, fmt.Errorf("target info not found")
}

// DownloadTarget downloads the target file specified by targetFile
func (client *MultiRepoClient) DownloadTarget(repos []string, targetFile *metadata.TargetFiles, filePath, targetBaseURL string) (string, []byte, error) {
	for _, repoName := range repos {
		// see if the target is already present locally
		targetPath, targetBytes, err := client.TUFClients[repoName].FindCachedTarget(targetFile, filePath)
		if err != nil {
			return "", nil, err
		}
		if len(targetPath) != 0 && len(targetBytes) != 0 {
			// we already got the target for this target info cached locally, so return it
			log.Info(fmt.Sprintf("Target %s already present locally from %s", targetFile.Path, repoName))
			return targetPath, targetBytes, nil
		}
		// not present locally, so let's try to download it
		targetPath, targetBytes, err = client.TUFClients[repoName].DownloadTarget(targetFile, filePath, targetBaseURL)
		if err != nil {
			// TODO: decide if we should error if one repository serves the expected target info, but we fail to download the actual target
			// try downloading the target from the next available repository
			continue
		}
		// we got the target for this target info, so return it
		log.Info(fmt.Sprintf("Downloaded target %s from %s", targetFile.Path, repoName))
		return targetPath, targetBytes, nil
	}
	// error out as we haven't succeeded downloading the target file
	return "", nil, fmt.Errorf("failed to download target file %s", targetFile.Path)
}

func (cfg *MultiRepoConfig) EnsurePathsExist() error {
	if cfg.DisableLocalCache {
		return nil
	}
	for _, path := range []string{cfg.LocalMetadataDir, cfg.LocalTargetsDir} {
		err := os.MkdirAll(path, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}
