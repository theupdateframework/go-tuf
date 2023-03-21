// Copyright 2023 VMware, Inc.
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
	"crypto"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/metadata/repository"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/crypto/ed25519"
)

func main() {
	// Create top-level metadata
	roles := repository.New()
	keys := map[string]ed25519.PrivateKey{}

	// Create Targets metadata
	targets := metadata.Targets(helperExpireIn(60))
	roles.SetTargets("targets", targets)

	// Add each target to Targets metadata
	for _, targetName := range []string{"targets/map.json", "targets/sigstore-tuf-root/root.json", "targets/staging/root.json"} {
		targetPath, localPath := helperGetPathForTarget(targetName)
		targetFileInfo, err := metadata.TargetFile().FromFile(localPath, "sha256")
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "generating target file info failed", err))
		}
		roles.Targets("targets").Signed.Targets[strings.TrimPrefix(targetPath, "targets/")] = targetFileInfo
		for _, eachHashValue := range targetFileInfo.Hashes {
			err := copyHashPrefixed(localPath, eachHashValue.String())
			if err != nil {
				panic(err)
			}
		}
	}

	// Create Snapshot metadata
	snapshot := metadata.Snapshot(helperExpireIn(60))
	roles.SetSnapshot(snapshot)

	// Create Timestamp metadata
	timestamp := metadata.Timestamp(helperExpireIn(60))
	roles.SetTimestamp(timestamp)

	// Create Root metadata
	root := metadata.Root(helperExpireIn(365))
	roles.SetRoot(root)

	// For this example, we generate one private key of type 'ed25519' for each top-level role
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "key generation failed", err))
		}
		keys[name] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "key conversion failed", err))
		}
		err = roles.Root().Signed.AddKey(key, name)
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "adding key to root failed", err))
		}
	}

	// Sign top-level metadata (in-band)
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		key := keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "loading a signer failed", err))
		}
		switch name {
		case "targets":
			_, err = roles.Targets("targets").Sign(signer)
		case "snapshot":
			_, err = roles.Snapshot().Sign(signer)
		case "timestamp":
			_, err = roles.Timestamp().Sign(signer)
		case "root":
			_, err = roles.Root().Sign(signer)
		}
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "metadata signing failed", err))
		}
	}

	// Persist metadata (consistent snapshot)
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("generate_metadata.go:", "getting cwd failed", err))
	}
	// Save to metadata folder
	cwd = filepath.Join(cwd, "metadata")
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		switch name {
		case "targets":
			filename := fmt.Sprintf("%d.%s.json", roles.Targets("targets").Signed.Version, name)
			err = roles.Targets("targets").ToFile(filepath.Join(cwd, filename), true)
		case "snapshot":
			filename := fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(cwd, filename), true)
		case "timestamp":
			filename := fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(cwd, filename), true)
		case "root":
			filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, name)
			err = roles.Root().ToFile(filepath.Join(cwd, filename), true)
		}
		if err != nil {
			panic(fmt.Sprintln("generate_metadata.go:", "saving metadata to file failed", err))
		}
	}

	// Verify that metadata is signed correctly
	// Verify root
	err = roles.Root().VerifyDelegate("root", roles.Root())
	if err != nil {
		panic(fmt.Sprintln("generate_metadata.go:", "verifying root metadata failed", err))
	}

	// Verify targets
	err = roles.Root().VerifyDelegate("targets", roles.Targets("targets"))
	if err != nil {
		panic(fmt.Sprintln("generate_metadata.go:", "verifying targets metadata failed", err))
	}

	// Verify snapshot
	err = roles.Root().VerifyDelegate("snapshot", roles.Snapshot())
	if err != nil {
		panic(fmt.Sprintln("generate_metadata.go:", "verifying snapshot metadata failed", err))
	}

	// Verify timestamp
	err = roles.Root().VerifyDelegate("timestamp", roles.Timestamp())
	if err != nil {
		panic(fmt.Sprintln("generate_metadata.go:", "verifying timestamp metadata failed", err))
	}

	fmt.Println("Done! Metadata files location:", cwd)
}

// helperExpireIn returns time offset by days
func helperExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}

// helperGetPathForTarget returns local and target paths for target
func helperGetPathForTarget(name string) (string, string) {
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("generate_metadata.go:", "getting cwd failed", err))
	}
	// _, dir := filepath.Split(cwd)
	// return filepath.Join(dir, name), filepath.Join(cwd, name)
	return name, filepath.Join(cwd, name)
}

func copyHashPrefixed(src string, hash string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	dirName, fileName := filepath.Split(src)
	err = os.WriteFile(filepath.Join(dirName, fmt.Sprintf("%s.%s", hash, fileName)), data, 0644)
	if err != nil {
		return err
	}
	return nil
}
