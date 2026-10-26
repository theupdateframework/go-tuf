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

// Package fixtures maintains the checked-in test repository. It is not a
// production repository publisher: versions and expiry dates are fixture inputs.
package fixtures

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/rsapss"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/trustedmetadata"
)

type repository struct {
	files     map[string][]byte
	root      *metadata.Metadata[metadata.RootType]
	snapshot  *metadata.Metadata[metadata.SnapshotType]
	timestamp *metadata.Metadata[metadata.TimestampType]
	targets   map[string]*metadata.Metadata[metadata.TargetsType]
}

func localPath(base, name string) (string, error) {
	if !filepath.IsLocal(filepath.FromSlash(name)) {
		return "", fmt.Errorf("fixture path must be relative: %q", name)
	}
	return filepath.Join(base, filepath.FromSlash(name)), nil
}

func readRepository(dir string) (*repository, error) {
	r := &repository{files: map[string][]byte{}, targets: map[string]*metadata.Metadata[metadata.TargetsType]{}}
	read := func(name string) ([]byte, error) {
		path, err := localPath(filepath.Join(dir, "repository", "metadata"), name+".json")
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path)
		r.files[name] = data
		return data, err
	}
	data, err := read(metadata.ROOT)
	if err != nil {
		return nil, err
	}
	r.root, err = metadata.Root().FromBytes(data)
	if err != nil {
		return nil, err
	}
	data, err = read(metadata.SNAPSHOT)
	if err != nil {
		return nil, err
	}
	r.snapshot, err = metadata.Snapshot().FromBytes(data)
	if err != nil {
		return nil, err
	}
	data, err = read(metadata.TIMESTAMP)
	if err != nil {
		return nil, err
	}
	r.timestamp, err = metadata.Timestamp().FromBytes(data)
	if err != nil {
		return nil, err
	}
	for filename := range r.snapshot.Signed.Meta {
		if filepath.Ext(filename) != ".json" {
			return nil, fmt.Errorf("unexpected snapshot entry %q", filename)
		}
		role := filename[:len(filename)-len(".json")]
		data, err = read(role)
		if err != nil {
			return nil, err
		}
		r.targets[role], err = metadata.Targets().FromBytes(data)
		if err != nil {
			return nil, err
		}
	}
	if r.targets[metadata.TARGETS] == nil {
		return nil, fmt.Errorf("snapshot must reference targets.json")
	}
	return r, nil
}

// Verify checks the signature chain, dependency versions/hashes/lengths, expiry,
// and every target's bytes. The historical parse-only 1.root.json is excluded.
func Verify(dir string) error {
	r, err := readRepository(dir)
	if err != nil {
		return err
	}
	return r.verify(dir)
}

func (r *repository) verify(dir string) error {
	trusted, err := trustedmetadata.New(r.files[metadata.ROOT])
	if err != nil {
		return fmt.Errorf("root: %w", err)
	}
	if _, err = trusted.UpdateTimestamp(r.files[metadata.TIMESTAMP]); err != nil {
		return fmt.Errorf("timestamp: %w", err)
	}
	if _, err = trusted.UpdateSnapshot(r.files[metadata.SNAPSHOT], false); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}
	if _, err = trusted.UpdateTargets(r.files[metadata.TARGETS]); err != nil {
		return fmt.Errorf("targets: %w", err)
	}
	seen := map[string]bool{metadata.TARGETS: true}
	queue := []string{metadata.TARGETS}
	for len(queue) > 0 {
		parent := queue[0]
		queue = queue[1:]
		md := r.targets[parent]
		for name, info := range md.Signed.Targets {
			path, err := localPath(filepath.Join(dir, "repository", "targets"), name)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if err = info.VerifyLengthHashes(data); err != nil {
				return fmt.Errorf("target %s: %w", name, err)
			}
		}
		if md.Signed.Delegations == nil {
			continue
		}
		if md.Signed.Delegations.SuccinctRoles != nil {
			return fmt.Errorf("static fixtures do not support succinct roles; use the simulator")
		}
		for _, delegated := range md.Signed.Delegations.Roles {
			if _, err = trusted.UpdateDelegatedTargets(r.files[delegated.Name], delegated.Name, parent); err != nil {
				return fmt.Errorf("delegation %s: %w", delegated.Name, err)
			}
			if !seen[delegated.Name] {
				seen[delegated.Name] = true
				queue = append(queue, delegated.Name)
			}
		}
	}
	for role := range r.targets {
		if !seen[role] {
			return fmt.Errorf("snapshot role %s has no reachable delegation", role)
		}
	}
	return nil
}

// Regenerate updates target hashes and metadata dependencies, re-signs the
// fixture chain, and verifies it in memory before writing any metadata files.
// Valid unchanged fixtures are left byte-for-byte intact. Existing versions,
// expiry dates, paths and optional metadata hash/length policies are preserved.
func Regenerate(dir string) error {
	r, err := readRepository(dir)
	if err != nil {
		return err
	}
	if r.verify(dir) == nil {
		return nil
	}
	signers := map[string]signature.Signer{}
	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		signers[role], err = rsapss.LoadRSAPSSSignerFromPEMFile(filepath.Join(dir, "keystore", role+"_key"))
		if err != nil {
			return fmt.Errorf("%s signer: %w", role, err)
		}
	}
	for role := range r.targets {
		if role == metadata.TARGETS {
			continue
		}
		// Public, deterministic TEST-ONLY keys replace the encrypted legacy
		// delegation key. Never use these keys for a real repository.
		seed := sha256.Sum256([]byte("go-tuf test fixture delegation: " + role))
		signers[role], err = signature.LoadED25519Signer(ed25519.NewKeyFromSeed(seed[:]))
		if err != nil {
			return err
		}
	}
	for role, md := range r.targets {
		for name, info := range md.Signed.Targets {
			path, err := localPath(filepath.Join(dir, "repository", "targets"), name)
			if err != nil {
				return err
			}
			algorithms := make([]string, 0, len(info.Hashes))
			for algorithm := range info.Hashes {
				algorithms = append(algorithms, algorithm)
			}
			slices.Sort(algorithms)
			updated, err := metadata.TargetFile().FromFile(path, algorithms...)
			if err != nil {
				return err
			}
			info.Length, info.Hashes = updated.Length, updated.Hashes
		}
		if md.Signed.Delegations != nil {
			if md.Signed.Delegations.SuccinctRoles != nil {
				return fmt.Errorf("static fixtures do not support succinct roles; use the simulator")
			}
			md.Signed.Delegations.Keys = map[string]*metadata.Key{}
			for i := range md.Signed.Delegations.Roles {
				delegated := &md.Signed.Delegations.Roles[i]
				if delegated.Name == metadata.TARGETS || signers[delegated.Name] == nil || delegated.Threshold != 1 {
					return fmt.Errorf("delegation %s must name a fixture role with threshold 1", delegated.Name)
				}
				public, err := signers[delegated.Name].PublicKey()
				if err != nil {
					return err
				}
				key, err := metadata.KeyFromPublicKey(public)
				if err != nil {
					return err
				}
				id, err := key.ID()
				if err != nil {
					return err
				}
				md.Signed.Delegations.Keys[id] = key
				delegated.KeyIDs = []string{id}
			}
		}
		r.files[role], err = sign(md, signers[role])
		if err != nil {
			return err
		}
	}
	r.files[metadata.ROOT], err = sign(r.root, signers[metadata.ROOT])
	if err != nil {
		return err
	}
	for role, md := range r.targets {
		if err = updateMeta(r.snapshot.Signed.Meta[role+".json"], md.Signed.Version, r.files[role]); err != nil {
			return err
		}
	}
	r.files[metadata.SNAPSHOT], err = sign(r.snapshot, signers[metadata.SNAPSHOT])
	if err != nil {
		return err
	}
	if err = updateMeta(r.timestamp.Signed.Meta["snapshot.json"], r.snapshot.Signed.Version, r.files[metadata.SNAPSHOT]); err != nil {
		return err
	}
	r.files[metadata.TIMESTAMP], err = sign(r.timestamp, signers[metadata.TIMESTAMP])
	if err != nil {
		return err
	}
	if err = r.verify(dir); err != nil {
		return fmt.Errorf("regenerated fixtures are invalid; no metadata written: %w", err)
	}
	// Stage complete files before replacing them, so individual files cannot be
	// truncated. Validation above happens before the first replacement.
	names := make([]string, 0, len(r.files))
	for name := range r.files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		path, err := localPath(filepath.Join(dir, "repository", "metadata"), name+".json")
		if err != nil {
			return err
		}
		if err = writeFile(path, r.files[name]); err != nil {
			return err
		}
	}
	return nil
}

func sign[T metadata.Roles](md *metadata.Metadata[T], signer signature.Signer) ([]byte, error) {
	md.ClearSignatures()
	if _, err := md.Sign(signer); err != nil {
		return nil, err
	}
	return md.ToBytes(true)
}

func updateMeta(info *metadata.MetaFiles, version int64, data []byte) error {
	if info == nil {
		return fmt.Errorf("missing metadata dependency")
	}
	info.Version = version
	if info.Length != 0 {
		info.Length = int64(len(data))
	}
	for algorithm := range info.Hashes {
		switch algorithm {
		case "sha256":
			sum := sha256.Sum256(data)
			info.Hashes[algorithm] = sum[:]
		case "sha512":
			sum := sha512.Sum512(data)
			info.Hashes[algorithm] = sum[:]
		default:
			return fmt.Errorf("unsupported metadata hash %q", algorithm)
		}
	}
	return nil
}

func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".fixture-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Chmod(f.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
