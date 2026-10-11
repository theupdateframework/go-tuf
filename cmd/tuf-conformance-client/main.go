// Copyright 2026 The Update Framework Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"github.com/theupdateframework/go-tuf/v2/metadata/config"
	"github.com/theupdateframework/go-tuf/v2/metadata/updater"
)

type targetNames []string

func (t *targetNames) String() string {
	return fmt.Sprint([]string(*t))
}

func (t *targetNames) Set(value string) error {
	*t = append(*t, value)
	return nil
}

type options struct {
	metadataURL   string
	metadataDir   string
	targetBaseURL string
	targetDir     string
	targetNames   targetNames
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	opts := &options{}
	flags := flag.NewFlagSet("tuf-conformance-client", flag.ContinueOnError)
	flags.StringVar(&opts.metadataURL, "metadata-url", "", "repository metadata URL")
	flags.StringVar(&opts.metadataDir, "metadata-dir", "", "local metadata directory")
	flags.StringVar(&opts.targetBaseURL, "target-base-url", "", "repository target base URL")
	flags.StringVar(&opts.targetDir, "target-dir", "", "local target directory")
	flags.Var(&opts.targetNames, "target-name", "target name to download, may be repeated")

	if err := flags.Parse(args); err != nil {
		return err
	}

	remaining := flags.Args()
	if len(remaining) == 0 {
		return errors.New("missing command")
	}

	switch remaining[0] {
	case "init":
		if len(remaining) != 2 {
			return errors.New("init requires trusted root path")
		}
		return initClient(opts.metadataDir, remaining[1])
	case "refresh":
		if len(remaining) != 1 {
			return errors.New("refresh does not accept arguments")
		}
		return refresh(opts)
	case "download":
		if len(remaining) != 1 {
			return errors.New("download does not accept arguments")
		}
		return download(opts)
	default:
		return fmt.Errorf("unknown command %q", remaining[0])
	}
}

func initClient(metadataDir, trustedRoot string) error {
	if metadataDir == "" {
		return errors.New("missing --metadata-dir")
	}

	rootBytes, err := os.ReadFile(trustedRoot)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(metadataDir, "root.json"), rootBytes, 0o644)
}

func refresh(opts *options) error {
	up, err := newUpdater(opts)
	if err != nil {
		return err
	}
	return up.Refresh()
}

func download(opts *options) error {
	if len(opts.targetNames) == 0 {
		return errors.New("missing --target-name")
	}
	if opts.targetBaseURL == "" {
		return errors.New("missing --target-base-url")
	}
	if opts.targetDir == "" {
		return errors.New("missing --target-dir")
	}

	up, err := newUpdater(opts)
	if err != nil {
		return err
	}
	if err := up.Refresh(); err != nil {
		return err
	}

	for _, targetName := range opts.targetNames {
		targetInfo, err := up.GetTargetInfo(targetName)
		if err != nil {
			return fmt.Errorf("target %q not found: %w", targetName, err)
		}

		localPath := filepath.Join(opts.targetDir, url.QueryEscape(targetName))
		cachedPath, _, err := up.FindCachedTarget(targetInfo, localPath)
		if err != nil {
			return fmt.Errorf("failed to find cached target %q: %w", targetName, err)
		}
		if cachedPath != "" {
			continue
		}

		if _, _, err = up.DownloadTarget(targetInfo, localPath, opts.targetBaseURL); err != nil {
			return fmt.Errorf("failed to download target %q: %w", targetName, err)
		}
	}

	return nil
}

func newUpdater(opts *options) (*updater.Updater, error) {
	if opts.metadataURL == "" {
		return nil, errors.New("missing --metadata-url")
	}
	if opts.metadataDir == "" {
		return nil, errors.New("missing --metadata-dir")
	}

	rootBytes, err := os.ReadFile(filepath.Join(opts.metadataDir, "root.json"))
	if err != nil {
		return nil, err
	}

	cfg, err := config.New(opts.metadataURL, rootBytes)
	if err != nil {
		return nil, err
	}
	cfg.LocalMetadataDir = opts.metadataDir
	cfg.LocalTargetsDir = opts.targetDir
	if cfg.LocalTargetsDir == "" {
		cfg.LocalTargetsDir = opts.metadataDir
	}
	cfg.RemoteTargetsURL = opts.targetBaseURL

	up, err := updater.New(cfg)
	if err != nil {
		return nil, err
	}

	refTime, err := currentFaketime()
	if err != nil {
		return nil, err
	}
	up.UnsafeSetRefTime(refTime)

	return up, nil
}

func currentFaketime() (time.Time, error) {
	out, err := exec.Command("date", "+%s").Output()
	if err != nil {
		return time.Time{}, fmt.Errorf("calling date failed: %w", err)
	}
	seconds, err := strconv.ParseInt(string(out[:len(out)-1]), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to parse date output: %w", err)
	}
	return time.Unix(seconds, 0), nil
}
