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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rdimitrov/go-tuf-metadata/metadata"
	"github.com/rdimitrov/go-tuf-metadata/metadata/repository"
	"github.com/sigstore/sigstore/pkg/signature"
	"golang.org/x/crypto/ed25519"
)

// A TUF repository example using the low-level TUF Metadata API.

// The example code in this file demonstrates how to *manually* create and
// maintain repository metadata using the low-level Metadata API.
// Contents:
//  * creation of top-level metadata
//  * target file handling
//  * consistent snapshots
//  * key management
//  * top-level delegation and signing thresholds
//  * metadata verification
//  * target delegation
//  * in-band and out-of-band metadata signing
//  * writing and reading metadata files
//  * root key rotation

// NOTE: Metadata files will be written to a 'tmp*'-directory in CWD.

func main() {
	// Create top-level metadata
	// =========================
	// Every TUF repository has at least four roles, i.e. the top-level roles
	// 'targets', 'snapshot', 'timestamp' and 'root'. Below we will discuss their
	// purpose, show how to create the corresponding metadata, and how to use them
	// to provide integrity, consistency and freshness for the files TUF aims to
	// protect, i.e. target files.

	// Define containers for metadata objects and cryptographic keys created below. This
	// allows us to sign and write metadata in a batch more easily. The repository.New() instance
	// doesn't provide anything else yet other than serving as a placeholder for all metadata.
	roles := repository.New()
	keys := map[string]ed25519.PrivateKey{}

	// Targets (integrity)
	// -------------------
	// The targets role guarantees integrity for the files that TUF aims to protect,
	// i.e. target files. It does so by listing the relevant target files, along
	// with their hash and length.
	targets := metadata.Targets(helperExpireIn(7))
	roles.SetTargets("targets", targets)

	// For the purpose of this example we use the top-level targets role to protect
	// the integrity of this very example script. The metadata entry contains the
	// hash and length of this file at the local path. In addition, it specifies the
	// 'target path', which a client uses to locate the target file relative to a
	// configured mirror base URL.
	//     |----base URL---||--------target path--------|
	// e.g. tuf-examples.org/examples/basic_repository.py
	targetPath, localPath := helperGetPathForTarget("basic_repository.go")
	targetFileInfo, err := metadata.TargetFile().FromFile(localPath, "sha256")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "generating target file info failed", err))
	}
	roles.Targets("targets").Signed.Targets[targetPath] = targetFileInfo

	// Snapshot (consistency)
	// ----------------------
	// The snapshot role guarantees consistency of the entire repository. It does so
	// by listing all available targets metadata files at their latest version. This
	// becomes relevant, when there are multiple targets metadata files in a
	// repository and we want to protect the client against mix-and-match attacks.
	snapshot := metadata.Snapshot(helperExpireIn(7))
	roles.SetSnapshot(snapshot)

	// Timestamp (freshness)
	// ---------------------
	// The timestamp role guarantees freshness of the repository metadata. It does
	// so by listing the latest snapshot (which in turn lists all the latest
	// targets) metadata. A short expiration interval requires the repository to
	// regularly issue new timestamp metadata and thus protects the client against
	// freeze attacks.
	// Note that snapshot and timestamp use the same generic wireline metadata
	// format.
	timestamp := metadata.Timestamp(helperExpireIn(1))
	roles.SetTimestamp(timestamp)

	// Root (root of trust)
	// --------------------
	// The root role serves as root of trust for all top-level roles, including
	// itself. It does so by mapping cryptographic keys to roles, i.e. the keys that
	// are authorized to sign any top-level role metadata, and signing thresholds,
	// i.e. how many authorized keys are required for a given role (see 'roles'
	// field). This is called top-level delegation.

	// In addition, root provides all public keys to verify these signatures (see
	// 'keys' field), and a configuration parameter that describes whether a
	// repository uses consistent snapshots (see section 'Persist metadata' below
	// for more details).

	// Create root metadata object
	root := metadata.Root(helperExpireIn(365))
	roles.SetRoot(root)

	// For this example, we generate one private key of type 'ed25519' for each top-level role
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		_, private, err := ed25519.GenerateKey(nil)
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "key generation failed", err))
		}
		keys[name] = private
		key, err := metadata.KeyFromPublicKey(private.Public())
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "key conversion failed", err))
		}
		err = roles.Root().Signed.AddKey(key, name)
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "adding key to root failed", err))
		}
	}
	// NOTE: We only need the public part to populate root, so it is possible to use
	// out-of-band mechanisms to generate key pairs and only expose the public part
	// to whoever maintains the root role. As a matter of fact, the very purpose of
	// signature thresholds is to avoid having private keys all in one place.

	// Signature thresholds
	// --------------------
	// Given the importance of the root role, it is highly recommended to require a
	// threshold of multiple keys to sign root metadata. For this example we
	// generate another root key (you can pretend it's out-of-band) and increase the
	// required signature threshold.
	_, anotherRootKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "key generation failed", err))
	}

	anotherKey, err := metadata.KeyFromPublicKey(anotherRootKey.Public())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "key conversion failed", err))
	}
	err = roles.Root().Signed.AddKey(anotherKey, "root")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "adding another key to root failed", err))
	}
	roles.Root().Signed.Roles["root"].Threshold = 2

	// Sign top-level metadata (in-band)
	// =================================
	// In this example we have access to all top-level signing keys, so we can use
	// them to create and add a signature for each role metadata.
	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		key := keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "loading a signer failed", err))
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
			panic(fmt.Sprintln("basic_repository.go:", "metadata signing failed", err))
		}
	}

	// Persist metadata (consistent snapshot)
	// ======================================
	// It is time to publish the first set of metadata for a client to safely
	// download the target file that we have registered for this example repository.

	// For the purpose of this example we will follow the consistent snapshot naming
	// convention for all metadata. This means that each metadata file, must be
	// prefixed with its version number, except for timestamp. The naming convention
	// also affects the target files, but we don't cover this in the example. See
	// the TUF specification for more details:
	// https://theupdateframework.github.io/specification/latest/#writing-consistent-snapshots

	// Also note that the TUF specification does not mandate a wireline format. In
	// this demo we use a non-compact JSON format and store all metadata in
	// temporary directory at CWD for review.
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "getting cwd failed", err))
	}
	tmpDir, err := os.MkdirTemp(cwd, "tmp")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "creating a temporary folder failed", err))
	}

	for _, name := range []string{"targets", "snapshot", "timestamp", "root"} {
		switch name {
		case "targets":
			filename := fmt.Sprintf("%d.%s.json", roles.Targets("targets").Signed.Version, name)
			err = roles.Targets("targets").ToFile(filepath.Join(tmpDir, filename), true)
		case "snapshot":
			filename := fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(tmpDir, filename), true)
		case "timestamp":
			filename := fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(tmpDir, filename), true)
		case "root":
			filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, name)
			err = roles.Root().ToFile(filepath.Join(tmpDir, filename), true)
		}
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "saving metadata to file failed", err))
		}
	}

	// Threshold signing (out-of-band)
	// ===============================
	// As mentioned above, using signature thresholds usually entails that not all
	// signing keys for a given role are in the same place. Let's briefly pretend
	// this is the case for the second root key we registered above, and we are now
	// on that key owner's computer. All the owner has to do is read the metadata
	// file, sign it, and write it back to the same file, and this can be repeated
	// until the threshold is satisfied.
	_, err = roles.Root().FromFile(filepath.Join(tmpDir, "1.root.json"))
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "loading root metadata from file failed", err))
	}
	outofbandSigner, err := signature.LoadSigner(anotherRootKey, crypto.Hash(0))
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "loading a signer failed", err))
	}
	_, err = roles.Root().Sign(outofbandSigner)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "signing root failed", err))
	}
	err = roles.Root().ToFile(filepath.Join(tmpDir, "1.root.json"), true)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "saving root metadata to file failed", err))
	}

	// Verify that metadata is signed correctly
	// ====================================
	// Verify root
	err = roles.Root().VerifyDelegate("root", roles.Root())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying root metadata failed", err))
	}

	// Verify targets
	err = roles.Root().VerifyDelegate("targets", roles.Targets("targets"))
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying targets metadata failed", err))
	}

	// Verify snapshot
	err = roles.Root().VerifyDelegate("snapshot", roles.Snapshot())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying snapshot metadata failed", err))
	}

	// Verify timestamp
	err = roles.Root().VerifyDelegate("timestamp", roles.Timestamp())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying timestamp metadata failed", err))
	}

	// Targets delegation
	// ==================
	// Similar to how the root role delegates responsibilities about integrity,
	// consistency and freshness to the corresponding top-level roles, a targets
	// role may further delegate its responsibility for target files (or a subset
	// thereof) to other targets roles. This allows creation of a granular trust
	// hierarchy, and further reduces the impact of a single role compromise.

	// In this example the top-level targets role trusts a new "go-scripts"
	// targets role to provide integrity for any target file that ends with ".go".
	delegateeName := "go-scripts"
	_, delegateePrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "key generation failed", err))
	}
	keys[delegateeName] = delegateePrivateKey

	// Delegatee
	// ---------
	// Create a new targets role, akin to how we created top-level targets above, and
	// add target file info from above according to the delegatee's responsibility.
	delegatee := metadata.Targets(helperExpireIn(7))
	delegatee.Signed.Targets[targetPath] = targetFileInfo
	roles.SetTargets(delegateeName, delegatee)

	// Delegator
	// ---------
	// Akin to top-level delegation, the delegator expresses its trust in the
	// delegatee by authorizing a threshold of cryptographic keys to provide
	// signatures for the delegatee metadata. It also provides the corresponding
	// public key store.
	// The delegation info defined by the delegator further requires the provision
	// of a unique delegatee name and constraints about the target files the
	// delegatee is responsible for, e.g. a list of path patterns. For details about
	// all configuration parameters see
	// https://theupdateframework.github.io/specification/latest/#delegations
	delegateeKey, _ := metadata.KeyFromPublicKey(delegateePrivateKey.Public())
	roles.Targets("targets").Signed.Delegations = &metadata.Delegations{
		Keys: map[string]*metadata.Key{
			delegateeKey.ID(): delegateeKey,
		},
		Roles: []metadata.DelegatedRole{
			{
				Name:        delegateeName,
				KeyIDs:      []string{delegateeKey.ID()},
				Threshold:   1,
				Terminating: true,
				Paths:       []string{"*.go"},
			},
		},
	}

	// Remove target file info from top-level targets (delegatee is now responsible)
	delete(roles.Targets("targets").Signed.Targets, targetPath)

	// Increase expiry (delegators should be less volatile)
	roles.Targets("targets").Signed.Expires = helperExpireIn(365)

	// Snapshot + Timestamp + Sign + Persist
	// -------------------------------------
	// In order to publish a new consistent set of metadata, we need to update
	// dependent roles (snapshot, timestamp) accordingly, bumping versions of all
	// changed metadata.

	// Bump targets version
	roles.Targets("targets").Signed.Version += 1

	// Update snapshot to account for changed and new targets(delegatee) metadata
	roles.Snapshot().Signed.Meta["targets.json"] = metadata.MetaFile(roles.Targets("targets").Signed.Version)
	roles.Snapshot().Signed.Meta[fmt.Sprintf("%s.json", delegateeName)] = metadata.MetaFile(1)
	roles.Snapshot().Signed.Version += 1

	// Update timestamp to account for changed snapshot metadata
	roles.Timestamp().Signed.Meta["snapshot.json"] = metadata.MetaFile(roles.Snapshot().Signed.Version)
	roles.Timestamp().Signed.Version += 1

	// Sign and write metadata for all changed roles, i.e. all but root
	for _, name := range []string{"targets", "snapshot", "timestamp", delegateeName} {
		key := keys[name]
		signer, err := signature.LoadSigner(key, crypto.Hash(0))
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "loading a signer failed", err))
		}
		switch name {
		case "targets":
			roles.Targets("targets").ClearSignatures()
			_, err = roles.Targets("targets").Sign(signer)
			if err != nil {
				panic(fmt.Sprintln("basic_repository.go:", "signing metadata failed", err))
			}
			filename := fmt.Sprintf("%d.%s.json", roles.Targets("targets").Signed.Version, name)
			err = roles.Targets("targets").ToFile(filepath.Join(tmpDir, filename), true)
		case "snapshot":
			roles.Snapshot().ClearSignatures()
			_, err = roles.Snapshot().Sign(signer)
			if err != nil {
				panic(fmt.Sprintln("basic_repository.go:", "signing metadata failed", err))
			}
			filename := fmt.Sprintf("%d.%s.json", roles.Snapshot().Signed.Version, name)
			err = roles.Snapshot().ToFile(filepath.Join(tmpDir, filename), true)
		case "timestamp":
			roles.Timestamp().ClearSignatures()
			_, err = roles.Timestamp().Sign(signer)
			if err != nil {
				panic(fmt.Sprintln("basic_repository.go:", "signing metadata failed", err))
			}
			filename := fmt.Sprintf("%s.json", name)
			err = roles.Timestamp().ToFile(filepath.Join(tmpDir, filename), true)
		case delegateeName:
			roles.Targets(delegateeName).ClearSignatures()
			_, err = roles.Targets(delegateeName).Sign(signer)
			if err != nil {
				panic(fmt.Sprintln("basic_repository.go:", "signing metadata failed", err))
			}
			filename := fmt.Sprintf("%d.%s.json", roles.Targets(delegateeName).Signed.Version, name)
			err = roles.Targets(delegateeName).ToFile(filepath.Join(tmpDir, filename), true)
		}
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "saving metadata to file failed", err))
		}
	}

	// Root key rotation (recover from a compromise / key loss)
	// ========================================================
	// TUF makes it easy to recover from a key compromise in-band. Given the trust
	// hierarchy through top-level and targets delegation you can easily
	// replace compromised or lost keys for any role using the delegating role, even
	// for the root role.
	// However, since root authorizes its own keys, it always has to be signed with
	// both the threshold of keys from the previous version and the threshold of
	// keys from the new version. This establishes a trusted line of continuity.

	// In this example we will replace a root key, and sign a new version of root
	// with the threshold of old and new keys. Since one of the previous root keys
	// remains in place, it can be used to count towards the old and new threshold.
	_, newRootKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "key generation failed", err))
	}
	oldRootKey, err := metadata.KeyFromPublicKey(keys["root"].Public())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "key conversion failed", err))
	}
	err = roles.Root().Signed.RevokeKey(oldRootKey.ID(), "root")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "revoking key failed", err))
	}
	// Add new key for root
	newRootKeyTUF, err := metadata.KeyFromPublicKey(newRootKey.Public())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "key conversion failed", err))
	}
	err = roles.Root().Signed.AddKey(newRootKeyTUF, "root")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "adding key to root failed", err))
	}
	roles.Root().Signed.Version += 1
	roles.Root().ClearSignatures()

	// Sign root
	for _, k := range []ed25519.PrivateKey{keys["root"], anotherRootKey, newRootKey} {
		signer, err := signature.LoadSigner(k, crypto.Hash(0))
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "loading a signer failed", err))
		}
		_, err = roles.Root().Sign(signer)
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "signing root failed", err))
		}
	}
	filename := fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, "root")
	err = roles.Root().ToFile(filepath.Join(tmpDir, filename), true)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "saving root to file failed", err))
	}

	// Verify again that metadata is signed correctly
	// ==============================================
	// Verify root
	err = roles.Root().VerifyDelegate("root", roles.Root())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying root metadata failed", err))
	}

	// Verify targets
	err = roles.Root().VerifyDelegate("targets", roles.Targets("targets"))
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying targets metadata failed", err))
	}

	// Verify snapshot
	err = roles.Root().VerifyDelegate("snapshot", roles.Snapshot())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying snapshot metadata failed", err))
	}

	// Verify timestamp
	err = roles.Root().VerifyDelegate("timestamp", roles.Timestamp())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying timestamp metadata failed", err))
	}

	// Verify delegatee
	err = roles.Targets("targets").VerifyDelegate(delegateeName, roles.Targets(delegateeName))
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying delegatee metadata failed", err))
	}

	// Use a mixture of key types
	// ==========================
	// Create an RSA key
	anotherRootKeyRSA, _ := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "RSA key generation failed", err))
	}
	anotherKeyRSA, err := metadata.KeyFromPublicKey(anotherRootKeyRSA.Public())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "RSA key conversion failed", err))
	}

	// Create an ECDSA key
	anotherRootKeyECDSA, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "ECDSA key generation failed", err))
	}
	anotherKeyECDSA, err := metadata.KeyFromPublicKey(anotherRootKeyECDSA.Public())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "ECDSA key conversion failed", err))
	}

	// Add the RSA key to root keys
	err = roles.Root().Signed.AddKey(anotherKeyRSA, "root")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "adding RSA key to root failed", err))
	}

	// Add the ECDSA key to root keys
	err = roles.Root().Signed.AddKey(anotherKeyECDSA, "root")
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "adding ECDSA key to root failed", err))
	}

	// Clear existing signatures, bump version and threshold
	roles.Root().Signed.Roles["root"].Threshold = 4
	roles.Root().Signed.Version += 1
	roles.Root().ClearSignatures()

	// Sign root with existing ed25519 keys
	for _, k := range []ed25519.PrivateKey{keys["root"], anotherRootKey, newRootKey} {
		signer, err := signature.LoadSigner(k, crypto.Hash(0))
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "loading a signer failed", err))
		}
		_, err = roles.Root().Sign(signer)
		if err != nil {
			panic(fmt.Sprintln("basic_repository.go:", "signing root failed", err))
		}
	}

	// Sign root with the new RSA and ECDSA keys
	outofbandSignerRSA, err := signature.LoadSigner(anotherRootKeyRSA, crypto.SHA256)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "loading RSA signer failed", err))
	}
	outofbandSignerECDSA, err := signature.LoadSigner(anotherRootKeyECDSA, crypto.SHA256)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "loading ECDSA signer failed", err))
	}
	_, err = roles.Root().Sign(outofbandSignerRSA)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "signing root failed", err))
	}
	_, err = roles.Root().Sign(outofbandSignerECDSA)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "signing root failed", err))
	}

	// Verify that root is signed correctly
	// ====================================
	err = roles.Root().VerifyDelegate("root", roles.Root())
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "verifying root metadata failed", err))
	}

	// Save root to file
	filename = fmt.Sprintf("%d.%s.json", roles.Root().Signed.Version, "root")
	err = roles.Root().ToFile(filepath.Join(tmpDir, filename), true)
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "saving root to file failed", err))
	}
	fmt.Println("Done! Metadata files location:", tmpDir)
}

// helperExpireIn returns time offset by days
func helperExpireIn(days int) time.Time {
	return time.Now().AddDate(0, 0, days).UTC()
}

// helperGetPathForTarget returns local and target paths for target
func helperGetPathForTarget(name string) (string, string) {
	cwd, err := os.Getwd()
	if err != nil {
		panic(fmt.Sprintln("basic_repository.go:", "getting cwd failed", err))
	}
	// _, dir := filepath.Split(cwd)
	// return filepath.Join(dir, name), filepath.Join(cwd, name)
	return name, filepath.Join(cwd, name)
}
