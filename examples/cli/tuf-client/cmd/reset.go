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
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var ForceDelete bool

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
	resetCmd.Flags().BoolVarP(&ForceDelete, "force", "f", false, "force delete without waiting for confirmation")
	rootCmd.AddCommand(resetCmd)
}

func ResetCmd() error {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current working directory: %w", err)
	}

	// folders to delete
	metadataPath := filepath.Join(cwd, DefaultMetadataDir)
	downloadPath := filepath.Join(cwd, DefaultDownloadDir)

	// warning: deletes the metadata folder and all of its contents
	fmt.Printf("Warning: Are you sure you want to delete the \"%s\" folder and all of its contents? (y/n)\n", metadataPath)
	if ForceDelete || askForConfirmation() {
		os.RemoveAll(metadataPath)
		fmt.Printf("Folder %s was successfully deleted\n", metadataPath)
	} else {
		fmt.Printf("Folder \"%s\" was not deleted\n", metadataPath)
	}

	// warning: deletes the download folder and all of its contents
	fmt.Printf("Warning: Are you sure you want to delete the \"%s\" folder and all of its contents? (y/n)\n", downloadPath)
	if ForceDelete || askForConfirmation() {
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
		fmt.Println(err)
		os.Exit(1)
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
