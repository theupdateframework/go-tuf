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

var Verbosity bool

var rootCmd = &cobra.Command{
	Use:   "tuf",
	Short: "tuf - a repository-side CLI tool for The Update Framework (TUF)",
	Long:  "tuf - a repository-side CLI tool for The Update Framework (TUF)",
	Run: func(cmd *cobra.Command, args []string) {

	},
}

func Execute() {
	rootCmd.PersistentFlags().BoolVarP(&Verbosity, "verbose", "v", false, "verbose output")

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
