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

package cmd

import (
	"io"
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

// ReadFile reads the content of a file and return its bytes
func ReadFile(name string) ([]byte, error) {
	in, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer in.Close()
	data, err := io.ReadAll(in)
	if err != nil {
		return nil, err
	}
	return data, nil
}
