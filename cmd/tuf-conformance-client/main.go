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

// tuf-conformance-client is the client-under-test executable required by the
// tuf-conformance test suite (https://github.com/theupdateframework/tuf-conformance).
//
// It implements the three-command CLI protocol described in CLIENT-CLI.md:
//
//	init     <trusted-root>  – bootstrap trusted metadata from a root.json file
//	refresh                  – update top-level metadata from the repository
//	download                 – download and verify a target artifact
//
// The tool exits with code 0 on success and code 1 on any failure.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	stdlog "log"

	"github.com/go-logr/stdr"
	"github.com/spf13/cobra"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

// currentTime returns the reference time the updater should use.
//
// Go binaries on Linux read the clock via VDSO and are not affected by
// libfaketime's LD_PRELOAD interception. The tuf-conformance harness drives
// time via the faketime CLI, which exports the requested timestamp through
// the FAKETIME env var; we parse it here so Updater.UnsafeSetRefTime can
// honour it. Falls back to time.Now() when FAKETIME is unset or unparseable.
func currentTime() time.Time {
	raw := os.Getenv("FAKETIME")
	if raw == "" {
		return time.Now().UTC()
	}
	// Ubuntu's faketime CLI (libfaketime 0.9.10) converts an absolute
	// datetime arg into a signed integer second offset, e.g.
	// "+691200" for +8 days. Honour that format first.
	if len(raw) > 1 && (raw[0] == '+' || raw[0] == '-') {
		if secs, err := strconv.ParseInt(raw, 10, 64); err == nil {
			return time.Now().UTC().Add(time.Duration(secs) * time.Second)
		}
	}
	// Otherwise fall back to absolute timestamp formats libfaketime
	// itself accepts when FAKETIME is set directly.
	abs := strings.TrimPrefix(raw, "@")
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999-07:00", // Python str(datetime) with tz
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05",
		time.RFC3339Nano,
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, abs); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}

func main() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}

// flags shared across all sub-commands.
var (
	metadataDir string
	metadataURL string
	verbose     bool
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "tuf-conformance-client",
		Short: "TUF client-under-test for the tuf-conformance test suite",
		Long: `tuf-conformance-client implements the client-under-test CLI protocol required
by the tuf-conformance test suite.

See https://github.com/theupdateframework/tuf-conformance/blob/main/CLIENT-CLI.md`,
		SilenceUsage: true,
	}

	root.PersistentFlags().StringVar(&metadataDir, "metadata-dir", "", "directory for trusted local metadata (required)")
	root.PersistentFlags().StringVar(&metadataURL, "metadata-url", "", "URL of the repository metadata store")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false, "enable verbose logging")

	root.AddCommand(newInitCmd())
	root.AddCommand(newRefreshCmd())
	root.AddCommand(newDownloadCmd())

	return root
}

// configureLogger sets up the go-tuf logger at an appropriate verbosity level.
func configureLogger(prefix string) {
	logger := stdr.New(stdlog.New(os.Stderr, prefix+": ", stdlog.LstdFlags))
	metadata.SetLogger(logger)
	if verbose {
		stdr.SetVerbosity(5)
	}
}

// newInitCmd returns the `init` sub-command.
//
// Usage: tuf-conformance-client --metadata-dir DIR init TRUSTED_ROOT
//
// It copies the provided root.json file into METADATA_DIR as "root.json"
// without contacting the network.
func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init <trusted-root>",
		Short: "Bootstrap trusted metadata from a root.json file",
		Long: `Initialize the client by copying the provided trusted root.json into
--metadata-dir. No network requests are made during this step.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			configureLogger("init")

			if metadataDir == "" {
				return fmt.Errorf("--metadata-dir is required")
			}

			trustedRoot := args[0]

			rootBytes, err := os.ReadFile(trustedRoot)
			if err != nil {
				return fmt.Errorf("read trusted root %q: %w", trustedRoot, err)
			}

			if err := os.MkdirAll(metadataDir, 0750); err != nil {
				return fmt.Errorf("create metadata dir %q: %w", metadataDir, err)
			}

			dest := filepath.Join(metadataDir, "root.json")
			if err := os.WriteFile(dest, rootBytes, 0644); err != nil {
				return fmt.Errorf("write root.json to %q: %w", dest, err)
			}

			fmt.Fprintln(os.Stderr, "init: trusted root written to", dest)
			return nil
		},
	}
}

// newRefreshCmd returns the `refresh` sub-command.
//
// Usage: tuf-conformance-client --metadata-dir DIR --metadata-url URL refresh
//
// It runs the TUF client workflow to update top-level metadata and writes the
// trusted metadata files (root.json, targets.json, snapshot.json,
// timestamp.json) into METADATA_DIR using non-versioned filenames.
func newRefreshCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "refresh",
		Short: "Update top-level metadata from the repository",
		Long: `Fetch and verify the TUF top-level metadata (root, targets, snapshot,
timestamp) from --metadata-url, storing the trusted copies in --metadata-dir
using non-versioned filenames.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			configureLogger("refresh")

			if metadataDir == "" {
				return fmt.Errorf("--metadata-dir is required")
			}
			if metadataURL == "" {
				return fmt.Errorf("--metadata-url is required")
			}

			rootBytes, err := os.ReadFile(filepath.Join(metadataDir, "root.json"))
			if err != nil {
				return fmt.Errorf("read local root.json: %w", err)
			}

			cfg, err := config.New(metadataURL, rootBytes)
			if err != nil {
				return fmt.Errorf("create updater config: %w", err)
			}
			cfg.LocalMetadataDir = metadataDir
			// refresh doesn't fetch targets, but Updater.New calls
			// EnsurePathsExist on both dirs; supply metadataDir as a
			// harmless writable placeholder so the empty default doesn't
			// trip os.MkdirAll.
			cfg.LocalTargetsDir = metadataDir

			up, err := updater.New(cfg)
			if err != nil {
				return fmt.Errorf("create updater: %w", err)
			}
			up.UnsafeSetRefTime(currentTime())

			if err := up.Refresh(); err != nil {
				return fmt.Errorf("refresh: %w", err)
			}

			fmt.Fprintln(os.Stderr, "refresh: metadata updated successfully")
			return nil
		},
	}
}

// newDownloadCmd returns the `download` sub-command.
//
// Usage:
//
//	tuf-conformance-client \
//	  --metadata-dir DIR \
//	  --metadata-url URL \
//	  --target-name PATH \
//	  --target-base-url URL \
//	  --target-dir DIR \
//	  download
//
// It refreshes top-level metadata, looks up the target, checks the local
// cache, and downloads the artifact into --target-dir if not already present.
func newDownloadCmd() *cobra.Command {
	var (
		targetName    string
		targetBaseURL string
		targetDir     string
	)

	cmd := &cobra.Command{
		Use:   "download",
		Short: "Download and verify a target artifact",
		Long: `Refresh metadata, then download the artifact identified by --target-name from
--target-base-url and store it in --target-dir.

If the artifact is already cached with matching hashes it will not be
re-downloaded.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			configureLogger("download")

			if metadataDir == "" {
				return fmt.Errorf("--metadata-dir is required")
			}
			if metadataURL == "" {
				return fmt.Errorf("--metadata-url is required")
			}
			if targetName == "" {
				return fmt.Errorf("--target-name is required")
			}
			if targetBaseURL == "" {
				return fmt.Errorf("--target-base-url is required")
			}
			if targetDir == "" {
				return fmt.Errorf("--target-dir is required")
			}

			rootBytes, err := os.ReadFile(filepath.Join(metadataDir, "root.json"))
			if err != nil {
				return fmt.Errorf("read local root.json: %w", err)
			}

			cfg, err := config.New(metadataURL, rootBytes)
			if err != nil {
				return fmt.Errorf("create updater config: %w", err)
			}
			cfg.LocalMetadataDir = metadataDir
			cfg.LocalTargetsDir = targetDir
			cfg.RemoteTargetsURL = targetBaseURL

			up, err := updater.New(cfg)
			if err != nil {
				return fmt.Errorf("create updater: %w", err)
			}
			up.UnsafeSetRefTime(currentTime())

			if err := up.Refresh(); err != nil {
				return fmt.Errorf("refresh: %w", err)
			}

			info, err := up.GetTargetInfo(targetName)
			if err != nil {
				return fmt.Errorf("get target info %q: %w", targetName, err)
			}

			// Check if the artifact is already cached.
			if path, _, err := up.FindCachedTarget(info, ""); err == nil && path != "" {
				fmt.Fprintln(os.Stderr, "download: target already cached at", path)
				return nil
			}

			path, _, err := up.DownloadTarget(info, "", "")
			if err != nil {
				return fmt.Errorf("download target %q: %w", targetName, err)
			}

			fmt.Fprintln(os.Stderr, "download: stored target at", path)
			return nil
		},
	}

	cmd.Flags().StringVar(&targetName, "target-name", "", "TUF targetpath of the artifact (required)")
	cmd.Flags().StringVar(&targetBaseURL, "target-base-url", "", "base URL for the target store (required)")
	cmd.Flags().StringVar(&targetDir, "target-dir", "", "directory to store downloaded artifacts (required)")

	return cmd
}
