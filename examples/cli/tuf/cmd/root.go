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
