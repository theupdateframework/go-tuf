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

const (
	DefaultRepoMapFileName = "map.json"
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
	BootstrapDir      string
	LocalMetadataDir  string
	LocalTargetsDir   string
	DisableLocalCache bool
}

// MultiRepoClient represents a multi-repository TUF client
type MultiRepoClient struct {
	TUFClients map[string]*updater.Updater
	cfg        *MultiRepoConfig
}

type MultiRepoTargetFiles struct {
	Repositories []string
	TargetFile   *metadata.TargetFiles
}

// NewConfig returns configuration for a multi-repo TUF client
func NewConfig(bootstrapDir string) (*MultiRepoConfig, error) {
	// verify the provided path is a directory
	fileInfo, err := os.Stat(bootstrapDir)
	if err != nil {
		return nil, err
	}
	if !fileInfo.IsDir() {
		return nil, fmt.Errorf("provided bootstrap path is not a directory")
	}
	return &MultiRepoConfig{
		BootstrapDir: bootstrapDir,
	}, nil
}

// New returns a multi-repository TUF client. All repositories described in the provided map file are initialized too
func New(config *MultiRepoConfig) (*MultiRepoClient, error) {
	// make sure the bootstrap path was provided (location of the map file and trusted root files for each repository)
	if len(config.BootstrapDir) == 0 {
		return nil, fmt.Errorf("no bootstrap directory provided")
	}

	// create a multi repo client instance
	client := &MultiRepoClient{
		cfg:        config,
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
	// read and load the map file into config
	err := client.loadMap()
	if err != nil {
		return err
	}
	// loop through each repository listed in the map file and initialize it
	for repoName, repoURL := range client.cfg.RepoMap.Repositories {
		log.Infof("Initializing %s - %s", repoName, repoURL[0])

		// get the trusted root file from the location specified in the map file relevant to its path
		// NOTE: the root.json file is expected to be in a folder named after the repository it corresponds to placed in the same folder as the map file
		// i.e <client.cfg.BootstrapDir>/<repo-name>/root.json
		rootBytes, err := client.getRoot(repoName)
		if err != nil {
			return err
		}

		// path of where each of the repository's metadata files will be persisted
		metadataDir := filepath.Join(client.cfg.LocalMetadataDir, repoName)

		// location of where the target files will be downloaded (propagated to each client from the multi-repo config)
		// WARNING: Do note that using a single folder for storing targets from various repositories as it might lead to a conflict
		targetsDir := client.cfg.LocalTargetsDir
		if len(client.cfg.LocalTargetsDir) == 0 {
			// if it was not set, create a targets folder under each repository so there's no chance of conflict
			targetsDir = filepath.Join(metadataDir, "targets")
		}

		// ensure paths exist, doesn't do anything if caching is disabled
		err = client.cfg.EnsurePathsExist()
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
		cfg.DisableLocalCache = client.cfg.DisableLocalCache // propagate global cache policy

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
func (client *MultiRepoClient) GetTopLevelTargets() (map[string]*MultiRepoTargetFiles, error) {
	// collection of all target files for all clients
	result := map[string]*MultiRepoTargetFiles{}
	// loop through each repository
	for repo, tufClient := range client.TUFClients {
		// get top level targets for each repository
		targetFiles := tufClient.GetTopLevelTargets()
		// loop through all top level targets for this client
		for targetName, targetFile := range targetFiles {
			// check if this target file is already present in the collection
			if val, ok := result[targetName]; ok {
				// target file is already present
				if val.TargetFile.Equal(*targetFile) {
					// same target file present in multiple repositories
					// update the repo list only
					val.Repositories = append(val.Repositories, repo)
				} else {
					// target files have the same target name but have different target infos
					// TODO: decide if this should raise an error
					return nil, fmt.Errorf("target name conflict")
				}
			} else {
				// new target file, so save it
				result[targetName] = &MultiRepoTargetFiles{
					Repositories: []string{repo},
					TargetFile:   targetFile,
				}
			}
		}
	}
	// went over all clients, so the collection should be complete
	return result, nil
}

// GetTargetInfo returns metadata.TargetFiles instance with information
// for targetPath and a list of repositories that serve the matching target.
// It implements the TAP 4 search algorithm.
func (client *MultiRepoClient) GetTargetInfo(targetPath string) (*metadata.TargetFiles, []string, error) {
	terminated := false
	// loop through each mapping
	for _, eachMap := range client.cfg.RepoMap.Mapping {
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
		targetPath, targetBytes, err := client.TUFClients[repoName].DownloadTarget(targetFile, filePath, targetBaseURL)
		if err != nil {
			// try downloading the target from the next available repository
			continue
		}
		log.Info(fmt.Sprintf("Downloaded target %s from %s", targetFile.Path, repoName))
		// we got the target for this target info, so return it
		return targetPath, targetBytes, nil
	}
	// error out as we haven't succeeded downloading the target file
	return "", nil, fmt.Errorf("failed to download target file %s", targetFile.Path)
}

func (client *MultiRepoClient) getRoot(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(client.cfg.BootstrapDir, name, "root.json"))
}

func (client *MultiRepoClient) loadMap() error {
	// read the map file
	mapBytes, err := os.ReadFile(filepath.Join(client.cfg.BootstrapDir, DefaultRepoMapFileName))
	if err != nil {
		return err
	}
	// unmarshal the map file
	if err := json.Unmarshal(mapBytes, &client.cfg.RepoMap); err != nil {
		return err
	}
	return nil
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
