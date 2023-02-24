package tufclient

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/metadata/trustedmetadata"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootPath string

var initCmd = &cobra.Command{
	Use:     "init",
	Aliases: []string{"i"},
	Short:   "Initialize the client with trusted root.json metadata (Trust-On-First-Use)",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return InitializeCmd()
	},
}

func init() {
	initCmd.Flags().StringVarP(&rootPath, "file", "f", "", "location of the trusted root metadata file")
	rootCmd.AddCommand(initCmd)
}

func InitializeCmd() error {
	copyTrusted := true
	// handle verbosity level
	if Verbosity {
		log.SetLevel(log.DebugLevel)
	}

	// prepare the local environment
	localMetadataDir, err := prepareEnvironment()
	if err != nil {
		return err
	}

	// if there's no root.json file passed, try to download the 1.root.json from the repository URL
	if rootPath == "" {
		fmt.Printf("No root.json file was provided. Let's try to download one from %s\n", RepositoryURL)
		rootPath, err = fetchTrustedRoot(localMetadataDir)
		if err != nil {
			return err
		}
		rootPath = fmt.Sprintf("%s/%s.json", rootPath, metadata.ROOT)
		// no need to copy root.json to the metadata folder as we already download it in the expected location
		copyTrusted = false
	}

	// read the content of root.json
	rootBytes, err := ReadFile(rootPath)
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
	metadataPath := filepath.Join(cwd, "metadata")
	downloadPath := filepath.Join(cwd, "download")

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
