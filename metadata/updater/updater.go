package updater

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/metadata/config"
	"github.com/rdimitrov/go-tuf-metadata/metadata/fetcher"
	"github.com/rdimitrov/go-tuf-metadata/metadata/trustedmetadata"
)

// Client update workflow implementation
// The "Updater" provides an implementation of the `TUF client workflow
// <https://theupdateframework.github.io/specification/latest/#detailed-client-workflow>`_.
// "Updater" provides an API to query available targets and to download them in a
// secure manner: All downloaded files are verified by signed metadata.
// High-level description of "Updater" functionality:
//   * Initializing an "Updater" loads and validates the trusted local root
//     metadata: This root metadata is used as the source of trust for all other
//     metadata.
//   * "Refresh()"" can optionally be called to update and load all top-level
//     metadata as described in the specification, using both locally cached
//     metadata and metadata downloaded from the remote repository. If refresh is
//     not done explicitly, it will happen automatically during the first target
//     info lookup.
//   * "Updater" can be used to download targets. For each target:
//       * "GetTargetInfo()"" is first used to find information about a
//         specific target. This will load new targets metadata as needed (from
//         local cache or remote repository).
//       * "FindCachedTarget()"" can optionally be used to check if a
//         target file is already locally cached.
//       * "DownloadTarget()" downloads a target file and ensures it is
//         verified correct by the metadata.

type Updater struct {
	metadataDir     string
	metadataBaseUrl string
	targetDir       string
	targetBaseUrl   string
	trusted         *trustedmetadata.TrustedMetadata
	config          *config.UpdaterConfig
	fetcher         fetcher.Fetcher
}

// loadTimestamp load local and remote timestamp metadata
func (up *Updater) loadTimestamp() error {
	data, err := up.loadLocalMetadata(metadata.TIMESTAMP)
	if err != nil {
		return err
	}
	temp, err := up.trusted.UpdateTimestamp(data)
	if err != nil {
		if temp == nil {
			return err
		}
		fmt.Printf("Local timestamp not valid as final: %s", err)
	}
	// Load from remote (whether local load succeeded or not)
	data, err = up.downloadMetadata(metadata.TIMESTAMP, up.config.TimestampMaxLength, "")
	if err != nil {
		return err
	}
	_, err = up.trusted.UpdateTimestamp(data)
	// TODO: If the new timestamp version is the same as current, discard the
	// new timestamp. This is normal and it shouldn't raise any error.
	if err != nil {
		return err
	}
	err = up.persistMetadata(metadata.TIMESTAMP, data)
	if err != nil {
		return err
	}
	return nil
}

// loadSnapshot load local (and if needed remote) snapshot metadata
func (up *Updater) loadSnapshot() error {
	data, err := up.loadLocalMetadata(metadata.SNAPSHOT)
	if err != nil {
		return err
	}
	_, err = up.trusted.UpdateSnapshot(data, true)
	if err != nil {
		return err
	} else {
		fmt.Println("Local snapshot is valid: not downloading new one")
	}
	// Local snapshot not valid as final
	snapshotMeta := up.trusted.Timestamp.Signed.Meta[fmt.Sprintf("%s.json", metadata.SNAPSHOT)]
	length := snapshotMeta.Length
	if length == 0 {
		length = up.config.SnapshotMaxLength
	}
	version := ""
	if up.trusted.Root.Signed.ConsistentSnapshot {
		version = strconv.FormatInt(snapshotMeta.Version, 10)
	}
	data, err = up.downloadMetadata(metadata.SNAPSHOT, length, version)
	if err != nil {
		return err
	}
	_, err = up.trusted.UpdateSnapshot(data, false)
	if err != nil {
		return err
	}
	err = up.persistMetadata(metadata.TIMESTAMP, data)
	if err != nil {
		return err
	}
	return nil
}

// loadTargets load local (and if needed remote) metadata for roleName.
func (up *Updater) loadTargets(roleName, parentName string) (*metadata.Metadata[metadata.TargetsType], error) {
	// avoid loading 'roleName' more than once during "GetTargetInfo"
	role, ok := up.trusted.Targets[roleName]
	if ok {
		return role, nil
	}
	data, err := up.loadLocalMetadata(roleName)
	if err != nil {
		return nil, err
	}
	delegatedTargets, err := up.trusted.UpdateDelegatedTargets(data, roleName, parentName)
	if err == nil {
		fmt.Printf("Local %s is valid: not downloading new one\n", roleName)
		return delegatedTargets, nil
	} else {
		// local 'role' does not exist or is invalid: update from remote
		if up.trusted.Snapshot != nil {
			metaInfo := up.trusted.Snapshot.Signed.Meta[fmt.Sprintf("%s.json", roleName)]
			length := metaInfo.Length
			if length != 0 {
				length = up.config.TargetsMaxLength
			}
			version := ""
			if up.trusted.Root.Signed.ConsistentSnapshot {
				version = strconv.FormatInt(metaInfo.Version, 10)
			}
			data, err := up.downloadMetadata(roleName, length, version)
			if err != nil {
				return nil, err
			}
			delegatedTargets, err := up.trusted.UpdateDelegatedTargets(data, roleName, parentName)
			if err != nil {
				return nil, err
			}
			err = up.persistMetadata(roleName, data)
			if err != nil {
				return nil, err
			}
			return delegatedTargets, nil
		}
		return nil, err
	}
}

// preOrderDepthFirstWalk interrogates the tree of target delegations
// in order of appearance (which implicitly order trustworthiness),
// and returns the matching target found in the most trusted role.
func (up *Updater) preOrderDepthFirstWalk(targetFilePath string) (*metadata.TargetFiles, error) {
	// list of delegations to be interrogated. A (role, parent role) pair
	// is needed to load and verify the delegated targets metadata.
	delegationsToVisit := []string{metadata.TARGETS, metadata.ROOT}
	visitedRoleNames := map[string]bool{}

	// pre-order depth-first traversal of the graph of target delegations.
	for len(visitedRoleNames) <= up.config.MaxDelegations && len(delegationsToVisit) > 0 {
		// pop the role name from the top of the stack.

	}
	return nil, nil
}

// loadRoot load remote root metadata. Sequentially load and
// persist on local disk every newer root metadata version
// available on the remote.
func (up *Updater) loadRoot() error {
	// calculate boundaries
	lowerBound := up.trusted.Root.Signed.Version + 1
	upperBound := lowerBound + up.config.MaxRootRotations

	// loop until we find the latest available version of root
	for nextVersion := lowerBound; nextVersion <= upperBound; nextVersion++ {
		data, err := up.downloadMetadata(metadata.ROOT, up.config.RootMaxLength, strconv.FormatInt(nextVersion, 10))
		if err != nil {
			// if err has status codes 403 or 404 it means current root is newest available
			if strings.Contains(err.Error(), "403") || strings.Contains(err.Error(), "404") {
				break
			}
			return err
		}
		// verify and load the root data
		_, err = up.trusted.UpdateRoot(data)
		if err != nil {
			return err
		}
		// write root to disk
		err = up.persistMetadata(metadata.ROOT, data)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetTargetInfo returns “metadata.TargetFiles“ instance with information
// for targetPath. The return value can be used as an argument to
// “DownloadTarget()“ and “FindCachedTarget()“.
// If “Refresh()“ has not been called before calling
// “GetTargetInfo()“, the refresh will be done implicitly.
// As a side-effect this method downloads all the additional (delegated
// targets) metadata it needs to return the target information.
func (up *Updater) GetTargetInfo(targetPath string) (*metadata.TargetFiles, error) {
	// do a Refresh() in case there's no trusted targets.json yet
	if up.trusted.Targets[metadata.TARGETS] == nil {
		err := up.Refresh()
		if err != nil {
			return nil, err
		}
	}
	return up.preOrderDepthFirstWalk(targetPath)
}

// DownloadTarget downloads the target file specified by “targetinfo“
func (up *Updater) DownloadTarget(targetFile *metadata.TargetFiles, filePath, targetBaseURL string) (string, error) {
	var err error
	if filePath == "" {
		filePath, err = up.generateTargetFilePath(targetFile)
		if err != nil {
			return "", err
		}
	}
	if targetBaseURL == "" {
		if up.targetBaseUrl == "" {
			return "", fmt.Errorf("targetBaseURL must be set in either DownloadTarget() or the Updater struct")
		}
		targetBaseURL = up.targetBaseUrl
	} else {
		targetBaseURL = ensureTrailingSlash(targetBaseURL)
	}
	targetFilePath := targetFile.Path
	consistentSnapshot := up.trusted.Root.Signed.ConsistentSnapshot
	if consistentSnapshot && up.config.PrefixTargetsWithHash {
		hashes := ""
		// get first hex value of hashes
		for _, v := range targetFile.Hashes {
			hashes = hex.EncodeToString(v)
			break
		}
		dirName, baseName, ok := strings.Cut(targetFilePath, "/")
		if !ok {
			return "", fmt.Errorf("error handling targetFilePath %s, no separator found", targetFilePath)
		}
		targetFilePath = fmt.Sprintf("%s/%s.%s", dirName, hashes, baseName)
	}
	fullURL := fmt.Sprintf("%s%s", targetBaseURL, targetFilePath)
	data, err := up.fetcher.DownloadFile(fullURL, targetFile.Length)
	if err != nil {
		return "", err
	}
	err = targetFile.VerifyLengthHashes(data)
	if err != nil {
		return "", err
	}
	// write the data content to the temporary file
	err = os.WriteFile(filePath, data, 0644)
	if err != nil {
		return "", err
	}
	fmt.Printf("Downloaded target %s\n", targetFile.Path)
	return filePath, nil
}

// FindCachedTarget checks whether a local file is an up to date target
func (up *Updater) FindCachedTarget(targetFile *metadata.TargetFiles, filePath string) (string, error) {
	var err error
	targetFilePath := ""
	// get its path if not provided
	if filePath == "" {
		targetFilePath, err = up.generateTargetFilePath(targetFile)
		if err != nil {
			return "", err
		}
	} else {
		targetFilePath = filePath
	}
	// open the file
	in, err := os.Open(targetFilePath)
	if err != nil {
		return "", fmt.Errorf("error opening target file - %s", targetFilePath)
	}
	defer in.Close()
	// read its data
	data, err := io.ReadAll(in)
	if err != nil {
		return "", fmt.Errorf("error reading target bytes from file - %s", targetFilePath)
	}
	// verify if this local target file is an up-to-date target
	err = targetFile.VerifyLengthHashes(data)
	if err != nil {
		return "", err
	}
	// if all okay, return its path
	return targetFilePath, nil
}

// persistMetadata writes metadata to disk atomically to avoid data loss.
func (up *Updater) persistMetadata(roleName string, data []byte) error {
	fileName := filepath.Join(up.metadataDir, fmt.Sprintf("%s.json", url.QueryEscape(roleName)))
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	// create a temporary file
	file, err := os.CreateTemp(cwd, "tuf_tmp")
	if err != nil {
		return err
	}
	// write the data content to the temporary file
	err = os.WriteFile(file.Name(), data, 0644)
	if err != nil {
		// delete the temporary file if there was an error while writing
		os.Remove(file.Name())
		return err
	}
	// if all okay, rename the temporary file to the desired one
	err = os.Rename(file.Name(), fileName)
	if err != nil {
		return err
	}
	return nil
}

// Refresh refreshes top-level metadata.
// Downloads, verifies, and loads metadata for the top-level roles in the
// specified order (root -> timestamp -> snapshot -> targets) implementing
// all the checks required in the TUF client workflow.
// A Refresh()“ can be done only once during the lifetime of an Updater.
// If Refresh()“ has not been explicitly called before the first
// “GetTargetInfo()“ call, it will be done implicitly at that time.
// The metadata for delegated roles is not updated by Refresh()“:
// that happens on demand during GetTargetInfo()“. However, if the
// repository uses `consistent_snapshot
// <https://theupdateframework.github.io/specification/latest/#consistent-snapshots>`_,
// then all metadata downloaded by the Updater will use the same consistent
// repository state.
func (up *Updater) Refresh() error {
	err := up.loadRoot()
	if err != nil {
		return err
	}
	err = up.loadTimestamp()
	if err != nil {
		return err
	}
	err = up.loadSnapshot()
	if err != nil {
		return err
	}
	_, err = up.loadTargets(metadata.TARGETS, metadata.ROOT)
	if err != nil {
		return err
	}
	return nil
}

// New creates a new “Updater“ instance and loads trusted root metadata.
func New(metadataDir, metadataBaseUrl, targetDir, targetBaseUrl string, f fetcher.Fetcher) (*Updater, error) {
	// use the built-in download fetcher if nothing is provided
	if f == nil {
		f = &fetcher.DefaultFetcher{}
	}
	// create an updater instance
	updater := &Updater{
		metadataDir:     metadataDir,
		metadataBaseUrl: ensureTrailingSlash(metadataBaseUrl),
		targetDir:       targetDir,
		targetBaseUrl:   ensureTrailingSlash(targetBaseUrl),
		config:          config.New(),
		fetcher:         f,
	}
	// load the root metadata file used for bootstrapping trust
	rootBytes, err := updater.loadLocalMetadata(metadata.ROOT)
	if err != nil {
		return nil, err
	}
	// create a new trusted metadata instance
	trustedMetadataSet, err := trustedmetadata.New(rootBytes)
	if err != nil {
		return nil, err
	}
	updater.trusted = trustedMetadataSet
	return updater, nil
}

// downloadMetadata download a metadata file and return it as bytes
func (up *Updater) downloadMetadata(roleName string, length int64, version string) ([]byte, error) {
	urlPath := up.metadataBaseUrl
	// build urlPath
	if version == "" {
		urlPath = fmt.Sprintf("%s%s.json", urlPath, url.QueryEscape(roleName))
	} else {
		urlPath = fmt.Sprintf("%s%s.%s.json", urlPath, version, url.QueryEscape(roleName))
	}
	return up.fetcher.DownloadFile(urlPath, length)
}

// generateTargetFilePath generates path from TargetFiles
func (up *Updater) generateTargetFilePath(tf *metadata.TargetFiles) (string, error) {
	if up.targetDir == "" {
		return "", fmt.Errorf("target_dir must be set if filepath is not given")
	}
	// Use URL encoded target path as filename
	return url.JoinPath(up.targetDir, url.QueryEscape(tf.Path))
}

// loadLocalMetadata reads a local <roleName>.json file and returns its bytes
func (up *Updater) loadLocalMetadata(roleName string) ([]byte, error) {
	roleName = fmt.Sprintf("%s.json", url.QueryEscape(roleName))
	in, err := os.Open(roleName)
	if err != nil {
		return nil, fmt.Errorf("error opening metadata file - %s", roleName)
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, fmt.Errorf("error reading metadata bytes from file - %s", roleName)
	}
	return data, nil
}

// ensureTrailingSlash ensures url ends with a slash
func ensureTrailingSlash(url string) string {
	if strings.HasSuffix(url, "/") {
		return url
	}
	return url + "/"
}
