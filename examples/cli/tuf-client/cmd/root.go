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
	"os"

	"github.com/spf13/cobra"
)

const (
	DefaultMetadataDir = "tuf_metadata"
	DefaultDownloadDir = "tuf_download"
)

var Verbosity bool
var RepositoryURL string

var rootCmd = &cobra.Command{
	Use:   "tuf-client",
	Short: "tuf-client - a client-side CLI tool for The Update Framework (TUF)",
	Long: `tuf-client is a CLI tool that implements the client workflow specified by The Update Framework (TUF) specification.
   
The tuf-client can be used to query for available targets and to download them in a secure manner.

All downloaded files are verified by signed metadata.`,
	Run: func(cmd *cobra.Command, args []string) {
		// show the help message if no command has been used
		if len(args) == 0 {
			_ = cmd.Help()
			os.Exit(0)
		}
	},
}

func Execute() {
	rootCmd.PersistentFlags().BoolVarP(&Verbosity, "verbose", "v", false, "verbose output")
	rootCmd.PersistentFlags().StringVarP(&RepositoryURL, "url", "u", "", "URL of the TUF repository")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
