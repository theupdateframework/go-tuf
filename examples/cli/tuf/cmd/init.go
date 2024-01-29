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
	stdlog "log"
	"os"

	"github.com/go-logr/stdr"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

var initCmd = &cobra.Command{
	Use:     "init",
	Aliases: []string{"i"},
	Short:   "Initialize a repository",
	Args:    cobra.ExactArgs(0),
	RunE: func(cmd *cobra.Command, args []string) error {
		return InitializeCmd()
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func InitializeCmd() error {
	// set logger and debug verbosity level
	metadata.SetLogger(stdr.New(stdlog.New(os.Stdout, "ini_cmd", stdlog.LstdFlags)))
	if Verbosity {
		stdr.SetVerbosity(5)
	}

	fmt.Println("Initialization successful")

	return nil
}
