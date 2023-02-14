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

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/rdimitrov/go-tuf-metadata/metadata/updater"
)

const (
	// To experiment with a local repository you can build one with the basic_repository.go example and serve it using a python file server
	baseURL            = "http://localhost:8000" // "https://jku.github.io/tuf-demo"
	baseURLMetadataDir = "metadata"
	baseURLTargetsDir  = ""
	targetName         = "basic_repository.go"
	verbosity          = log.InfoLevel
)

func main() {
	// set debug level
	log.SetLevel(verbosity)

	// initialize client with Trust-On-First-Use
	localMetadataDir, err := InitTofu()
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to initialize Trust-On-First-Use", err))
	}

	// download the desired target
	err = Download(localMetadataDir, targetName)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to download target file", err))
	}

}

// InitTofu initialize local trusted metadata (Trust-On-First-Use) and create a
// directory for downloads
func InitTofu() (string, error) {
	// get working directory
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to get current working directory", err))
	}

	// create a temporary folder for storing the demo artifacts
	tmpDir, err := os.MkdirTemp(cwd, "tmp")
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to create a temporary folder", err))
	}

	// create a destination folder for storing the downloaded target
	err = os.Mkdir(filepath.Join(tmpDir, "download"), 0750)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to create a download folder", err))
	}

	// download the initial root metadata so we can bootstrap Trust-On-First-Use
	rootURL, _ := url.JoinPath(baseURL, baseURLMetadataDir, "1.root.json")
	req, err := http.NewRequest("GET", rootURL, nil)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to create http request", err))
	}

	client := http.DefaultClient

	res, err := client.Do(req)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to executed the http request", err))
	}

	defer res.Body.Close()

	data, err := io.ReadAll(res.Body)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to read the http request body", err))
	}

	// write the downloaded data content to file
	err = os.WriteFile("root.json", data, 0644)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to write root.json metadata", err))
	}

	log.Info("client_example.go: initialized new root in: ", tmpDir)

	return tmpDir, nil
}

// Download the target file using Updater. The Updater refreshes the top-level metadata,
// get the target information, verifies if the target is already cached, and in case it
// is not cached, downloads the target file.
func Download(localMetadataDir, target string) error {
	metadataBaseURL, _ := url.JoinPath(baseURL, baseURLMetadataDir)
	targetsBaseURL, _ := url.JoinPath(baseURL, baseURLTargetsDir)
	// create a new Updater instance
	up, err := updater.New(
		localMetadataDir,
		metadataBaseURL,
		targetsBaseURL,
		filepath.Join(localMetadataDir, "download"),
		nil)
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to create Updater instance", err))
	}

	log.Info("client_example.go: created a new Updater instance")

	// try to build the top-level metadata
	err = up.Refresh()
	if err != nil {
		panic(fmt.Sprintln("client_example.go:", "failed to Updater.Refresh()", err))
	}

	log.Info("client_example.go: updater.Refresh() succeeded")

	// search if the desired target is available
	targetInfo, err := up.GetTargetInfo(target)
	if err != nil {
		panic(fmt.Sprintf("client_example.go: target %s not found - %s\n", target, err))
	}

	// target is available, so let's see if the target is already present locally
	path, err := up.FindCachedTarget(targetInfo, "")
	if err != nil {
		panic(fmt.Sprintln("client_example.go: FindCachedTarget failed", err))
	}
	if path != "" {
		log.Infof("client_example.go: target %s is already present at - %s\n", target, path)
	}

	// target is not present locally, so let's try to download it
	path, err = up.DownloadTarget(targetInfo, "", "")
	if err != nil {
		panic(fmt.Sprintf("client_example.go: failed to download target %s - %s\n", target, err))
	}
	if path != "" {
		log.Infof("client_example.go: successfully downloaded target %s at - %s\n", target, path)
		return nil
	}
	return nil
}
