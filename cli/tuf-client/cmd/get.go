package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/metadata/updater"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var targetsURL string

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
		return GetCmd(args[0])
	},
}

func init() {
	getCmd.Flags().StringVarP(&targetsURL, "targetsURL", "t", "", "URL of where the target files are hosted")
	rootCmd.AddCommand(getCmd)
}

func GetCmd(target string) error {
	// handle verbosity level
	if Verbosity {
		log.SetLevel(log.DebugLevel)
	}

	// verify the client environment was initialized and fetch path names
	env, err := verifyEnv()
	if err != nil {
		return err
	}

	// create an Updater instance
	up, err := updater.New(
		env.MetadataDir,
		env.MetadataURL,
		env.TargetsURL,
		env.DownloadDir,
		env.MetadataDir,
		nil)
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
		fmt.Printf("Target %s is already present at - %s\n", target, path)
		return nil
	}

	// target is not present locally, so let's try to download it
	path, err = up.DownloadTarget(targetInfo, "", "")
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
		MetadataDir: filepath.Join(cwd, "metadata"),
		DownloadDir: filepath.Join(cwd, "download"),
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
	_, err = os.Stat(fmt.Sprintf("%s/%s.json", env.MetadataDir, metadata.ROOT))
	if err != nil {
		return nil, fmt.Errorf("no local download folder: %w", err)
	}
	return env, nil
}
