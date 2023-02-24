package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var resetCmd = &cobra.Command{
	Use:     "reset",
	Aliases: []string{"r"},
	Short:   "Resets the local environment. Warning: this deletes both the metadata and download folders and all of their contents",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return ResetCmd()
	},
}

func init() {
	rootCmd.AddCommand(resetCmd)
}

func ResetCmd() error {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	// folders to delete
	metadataPath := filepath.Join(cwd, "metadata")
	downloadPath := filepath.Join(cwd, "download")

	// warning: deletes the metadata folder and all of its contents
	fmt.Printf("Warning: Are you sure you want to delete the \"%s\" folder and all of its contents? (y/n)\n", metadataPath)
	if askForConfirmation() {
		os.RemoveAll(metadataPath)
		fmt.Printf("Folder %s was successfully deleted\n", metadataPath)
	} else {
		fmt.Printf("Folder \"%s\" was not deleted\n", metadataPath)
	}

	// warning: deletes the download folder and all of its contents
	fmt.Printf("Warning: Are you sure you want to delete the \"%s\" folder and all of its contents? (y/n)\n", downloadPath)
	if askForConfirmation() {
		os.RemoveAll(downloadPath)
		fmt.Printf("Folder %s was successfully deleted\n", downloadPath)
	} else {
		fmt.Printf("Folder \"%s\" was not deleted\n", downloadPath)
	}

	return nil
}

func askForConfirmation() bool {
	var response string
	_, err := fmt.Scanln(&response)
	if err != nil {
		log.Fatal(err)
	}
	switch strings.ToLower(response) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		fmt.Println("I'm sorry but I didn't get what you meant, please type (y)es or (n)o and then press enter:")
		return askForConfirmation()
	}
}
