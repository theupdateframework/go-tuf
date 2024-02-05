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

package simulator

// Test utility to simulate a repository

// RepositorySimulator provides methods to modify repository metadata so that it's
// easy to "publish" new repository versions with modified metadata, while serving
// the versions to client test code.

// RepositorySimulator implements FetcherInterface so Updaters in tests can use it
// as a way to "download" new metadata from remote: in practice no downloading,
// network connections or even file access happens as RepositorySimulator serves
// everything from memory.

// Metadata and targets "hosted" by the simulator are made available in URL paths
// "/metadata/..." and "/targets/..." respectively.

// Example::

//     // Initialize repository with top-level metadata
//     sim := simulator.NewRepository()

//     // metadata can be modified directly: it is immediately available to clients
//     sim.Snapshot.Version += 1

//     // As an exception, new root versions require explicit publishing
//     sim.Root.Version += 1
//     sim.PublishRoot()

//     // there are helper functions
//     sim.AddTarget("targets", b"content", "targetpath")
//     sim.Targets.Version += 1
//     sim.UpdateSnapshot()
// """

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/sigstore/sigstore/pkg/signature"
	log "github.com/sirupsen/logrus"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

var SPEC_VER = "." + metadata.SPECIFICATION_VERSION

type FTMetadata struct {
	Name  string
	Value int
}

type FTTargets struct {
	Name  string
	Value *string
}

// FetchTracker contains actual target data
// and the related target metadata
type FetchTracker struct {
	Metadata []FTMetadata
	Targets  []FTTargets
}

// RepositoryTarget contains actual target data
// and the related target metadata
type RepositoryTarget struct {
	Data       []byte
	TargetFile *metadata.TargetFiles
}

// RepositorySimulator simulates a repository that can be used for testing
type RepositorySimulator struct {
	fetcher.Fetcher
	MDDelegates                    map[string]metadata.Metadata[metadata.TargetsType]
	SignedRoots                    [][]byte
	Signers                        map[string]map[string]*signature.Signer
	TargetFiles                    map[string]RepositoryTarget
	ComputeMetafileHashesAndLength bool
	PrefixTargetsWithHash          bool
	DumpDir                        string
	DumpVersion                    int64
	FetchTracker                   FetchTracker
	SafeExpiry                     time.Time
	MDTargets                      *metadata.Metadata[metadata.TargetsType]
	MDSnapshot                     *metadata.Metadata[metadata.SnapshotType]
	MDTimestamp                    *metadata.Metadata[metadata.TimestampType]
	MDRoot                         *metadata.Metadata[metadata.RootType]
	LocalDir                       string
}

// New initializes a RepositorySimulator
func NewRepository() *RepositorySimulator {
	now := time.Now().UTC()

	rs := RepositorySimulator{
		MDDelegates: map[string]metadata.Metadata[metadata.TargetsType]{},

		// Other metadata is signed on-demand (when fetched) but roots must be
		// explicitly published with PublishRoot() which maintains this list
		SignedRoots: [][]byte{},

		// Signers are used on-demand at fetch time to sign metadata
		// keys are roles, values are map of {keyid: signer}
		Signers: make(map[string]map[string]*signature.Signer),

		// Target downloads are served from this map
		TargetFiles: make(map[string]RepositoryTarget),

		// Whether to compute hashes and length for meta in snapshot/timestamp
		ComputeMetafileHashesAndLength: false,

		// Enable hash-prefixed target file names
		PrefixTargetsWithHash: true,

		DumpDir:     "",
		DumpVersion: 0,

		FetchTracker: FetchTracker{
			Metadata: []FTMetadata{},
			Targets:  []FTTargets{},
		},

		SafeExpiry: now.Truncate(time.Second).AddDate(0, 0, 30),
	}
	rs.setupMinimalValidRepository()

	return &rs
}

func (rs *RepositorySimulator) setupMinimalValidRepository() {
	rs.MDTargets = metadata.Targets(rs.SafeExpiry)
	rs.MDSnapshot = metadata.Snapshot(rs.SafeExpiry)
	rs.MDTimestamp = metadata.Timestamp(rs.SafeExpiry)
	rs.MDRoot = metadata.Root(rs.SafeExpiry)

	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		publicKey, _, signer := CreateKey()

		mtdkey, err := metadata.KeyFromPublicKey(*publicKey)
		if err != nil {
			log.Fatalf("repository simulator: key conversion failed while setting repository: %v", err)
		}

		err = rs.MDRoot.Signed.AddKey(mtdkey, role)
		if err != nil {
			log.Debugf("repository simulator: failed to add key: %v", err)
		}
		rs.AddSigner(role, mtdkey.ID(), *signer)
	}

	rs.PublishRoot()
}

func (rs *RepositorySimulator) Root() metadata.RootType {
	return rs.MDRoot.Signed
}

func (rs *RepositorySimulator) Timestamp() metadata.TimestampType {
	return rs.MDTimestamp.Signed
}

func (rs *RepositorySimulator) Snapshot() metadata.SnapshotType {
	return rs.MDSnapshot.Signed
}

func (rs *RepositorySimulator) Targets() metadata.TargetsType {
	return rs.MDTargets.Signed
}

// AllTargets allows receiving role name and signed portion of targets one by one
func (rs *RepositorySimulator) AllTargets() <-chan metadata.TargetsType {
	ch := make(chan metadata.TargetsType)
	go func() {
		ch <- rs.MDTargets.Signed
		for role, md := range rs.MDDelegates {
			targets := metadata.TargetsType{
				Type:        role,
				Version:     md.Signed.Version,
				Delegations: md.Signed.Delegations,
			}
			ch <- targets
		}
		close(ch)
	}()
	return ch
}

func CreateKey() (*ed25519.PublicKey, *ed25519.PrivateKey, *signature.Signer) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		log.Printf("failed to generate key: %v", err)
	}

	signer, err := signature.LoadSigner(private, crypto.Hash(0))
	if err != nil {
		log.Printf("failed to load signer: %v", err)
	}
	return &public, &private, &signer
}

func (rs *RepositorySimulator) AddSigner(role string, keyID string, signer signature.Signer) {
	if _, ok := rs.Signers[role]; !ok {
		rs.Signers[role] = make(map[string]*signature.Signer)
	}
	rs.Signers[role][keyID] = &signer
}

// RotateKeys removes all keys for role, then add threshold of new keys
func (rs *RepositorySimulator) RotateKeys(role string) {
	rs.MDRoot.Signed.Roles[role].KeyIDs = []string{}
	for k := range rs.Signers[role] {
		delete(rs.Signers[role], k)
	}
	for i := 0; i < rs.MDRoot.Signed.Roles[role].Threshold; i++ {

		publicKey, _, signer := CreateKey()
		mtdkey, err := metadata.KeyFromPublicKey(*publicKey)
		if err != nil {
			log.Fatalf("repository simulator: key conversion failed while rotating keys: %v", err)
		}
		err = rs.MDRoot.Signed.AddKey(mtdkey, role)
		if err != nil {
			log.Debugf("repository simulator: failed to add key: %v", err)
		}
		rs.AddSigner(role, mtdkey.ID(), *signer)
	}
}

// PublishRoot signs and stores a new serialized version of root
func (rs *RepositorySimulator) PublishRoot() {
	rs.MDRoot.ClearSignatures()
	for _, signer := range rs.Signers[metadata.ROOT] {
		_, err := rs.MDRoot.Sign(*signer)
		if err != nil {
			log.Debugf("repository simulator: failed to sign root: %v", err)
		}
	}

	mtd, err := rs.MDRoot.MarshalJSON()
	if err != nil {
		log.Debugf("failed to marshal metadata while publishing root: %v", err)
	}
	rs.SignedRoots = append(rs.SignedRoots, mtd)
	log.Debugf("published root v%d", rs.MDRoot.Signed.Version)
}

func lastIndex(str string, delimiter string) (string, string, string) {
	// TODO: check if contained and lengths
	spl := strings.Split(str, delimiter)
	res := strings.SplitAfterN(str, delimiter, len(spl)-1)
	return res[0], delimiter, res[1]
}

func partition(s string, delimiter string) (string, string) {
	splitted := strings.Split(s, delimiter)
	version := ""
	role := ""
	switch len(splitted) {
	case 1:
		role = splitted[0]
	case 2:
		version = splitted[0]
		role = splitted[1]
	case 3:
		version = splitted[0]
		if splitted[1] == "" && splitted[2] == "" {
			role = "."
		}
	case 4:
		version = splitted[0]
		if splitted[1] == "" && splitted[2] == "" && splitted[3] == "" {
			role = ".."
		}
	}
	return version, role
}

func (rs *RepositorySimulator) DownloadFile(urlPath string, maxLength int64, timeout time.Duration) ([]byte, error) {
	data, err := rs.fetch(urlPath)
	if err != nil {
		return data, err
	}
	if len(data) > int(maxLength) {
		err = &metadata.ErrDownloadLengthMismatch{
			Msg: fmt.Sprintf("Downloaded %d bytes exceeding the maximum allowed length of %d", len(data), maxLength),
		}
	}
	return data, err
}

func IsWindowsPath(path string) bool {
	match, _ := regexp.MatchString(`^[a-zA-Z]:\\`, path)
	return match
}

func trimPrefix(path string, prefix string) (string, error) {
	var toTrim string
	if IsWindowsPath(path) {
		toTrim = path
	} else {
		parsedURL, e := url.Parse(path)
		if e != nil {
			return "", e
		}
		toTrim = parsedURL.Path
	}

	return strings.TrimPrefix(toTrim, prefix), nil
}

func hasPrefix(path, prefix string) bool {
	return strings.HasPrefix(filepath.ToSlash(path), prefix)
}

func hasSuffix(path, prefix string) bool {
	return strings.HasSuffix(filepath.ToSlash(path), prefix)
}

func (rs *RepositorySimulator) fetch(urlPath string) ([]byte, error) {

	path, err := trimPrefix(urlPath, rs.LocalDir)
	if err != nil {
		return nil, err
	}
	if hasPrefix(path, "/metadata/") && hasSuffix(path, ".json") {
		fileName := path[len("/metadata/"):]
		verAndName := fileName[:len(path)-len("/metadata/")-len(".json")]
		versionStr, role := partition(verAndName, ".")
		var version int
		var err error
		if role == metadata.ROOT || (rs.MDRoot.Signed.ConsistentSnapshot && verAndName != metadata.TIMESTAMP) {
			version, err = strconv.Atoi(versionStr)
			if err != nil {
				log.Printf("repository simulator: downloading file: failed to convert version: %v", err)
			}
		} else {
			role = verAndName
			version = -1
		}
		return rs.FetchMetadata(role, &version)
	} else if hasPrefix(path, "/targets/") {
		targetPath := path[len("/targets/"):]
		dirParts, sep, prefixedFilename := lastIndex(targetPath, string(filepath.Separator))
		var filename string
		prefix := ""
		filename = prefixedFilename
		if rs.MDRoot.Signed.ConsistentSnapshot && rs.PrefixTargetsWithHash {
			prefix, filename = partition(prefixedFilename, ".")
		}
		targetPath = filepath.Join(dirParts, sep, filename)
		target, err := rs.FetchTarget(targetPath, prefix)
		if err != nil {
			log.Printf("failed to fetch target: %v", err)
		}
		return target, err
	}
	return nil, nil
}

// FetchTarget returns data for 'targetPath', checking 'targetHash' if it is given.
// If hash is None, then consistentSnapshot is not used
func (rs *RepositorySimulator) FetchTarget(targetPath string, targetHash string) ([]byte, error) {
	rs.FetchTracker.Targets = append(rs.FetchTracker.Targets, FTTargets{Name: targetPath, Value: &targetHash})
	repoTarget, ok := rs.TargetFiles[targetPath]
	if !ok {
		return nil, fmt.Errorf("no target %s", targetPath)
	}
	if targetHash != "" && !contains(repoTarget.TargetFile.Hashes, []byte(targetHash)) {
		return nil, fmt.Errorf("hash mismatch for %s", targetPath)
	}
	log.Printf("fetched target %s", targetPath)
	return repoTarget.Data, nil
}

func contains(hashes map[string]metadata.HexBytes, targetHash []byte) bool {
	for _, value := range hashes {
		if bytes.Equal(value, targetHash) {
			return true
		}
	}
	return false
}

// FetchMetadata returns signed metadata for 'role', using 'version' if it is given.
// If version is None, non-versioned metadata is being requested
func (rs *RepositorySimulator) FetchMetadata(role string, version *int) ([]byte, error) {
	rs.FetchTracker.Metadata = append(rs.FetchTracker.Metadata, FTMetadata{Name: role, Value: *version})
	// Decode role for the metadata
	// role, _ = strconv.Unquote(role)
	if role == metadata.ROOT {
		// Return a version previously serialized in PublishRoot()
		if version == nil || *version > len(rs.SignedRoots) && *version > 0 {
			log.Printf("unknown root version %d", *version)
			return []byte{}, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		log.Printf("fetched root version %d", version)
		return rs.SignedRoots[*version-1], nil
	}

	// Sign and serialize the requested metadata
	if role == metadata.TIMESTAMP {
		return signMetadata(role, rs.MDTimestamp, rs)
	} else if role == metadata.SNAPSHOT {
		return signMetadata(role, rs.MDSnapshot, rs)
	} else if role == metadata.TARGETS {
		return signMetadata(role, rs.MDTargets, rs)
	} else {
		md, ok := rs.MDDelegates[role]
		if !ok {
			log.Printf("unknown role %s", role)
			return []byte{}, &metadata.ErrDownloadHTTP{StatusCode: 404}
		}
		return signMetadata(role, &md, rs)
	}
}

func signMetadata[T metadata.Roles](role string, md *metadata.Metadata[T], rs *RepositorySimulator) ([]byte, error) {
	md.Signatures = []metadata.Signature{}
	for _, signer := range rs.Signers[role] {
		// TODO: check if a bool argument should be added to Sign as in python-tuf
		// Not appending only for a local repo example !!! missing type for signers
		_, err := md.Sign(*signer)
		if err != nil {
			log.Debugf("repository simulator: failed to sign metadata: %v", err)
		}
	}
	// TODO: test if the version is the correct one
	// log.Printf("fetched %s v%d with %d sigs", role, md.GetVersion(), len(rs.Signers[role]))
	mtd, err := md.MarshalJSON()
	if err != nil {
		log.Printf("failed to marshal metadata while signing for role %s: %v", role, err)
	}
	return mtd, err
}

func (rs *RepositorySimulator) computeHashesAndLength(role string) (map[string]metadata.HexBytes, int) {
	noVersion := -1
	data, err := rs.FetchMetadata(role, &noVersion)
	if err != nil {
		log.Debugf("failed to fetch metadata: %v", err)
	}
	digest := sha256.Sum256(data)
	hashes := map[string]metadata.HexBytes{"sha256": digest[:]}
	return hashes, len(data)
}

// UpdateTimestamp updates timestamp and assign snapshot version
// to snapshot meta version
func (rs *RepositorySimulator) UpdateTimestamp() {
	hashes := make(map[string]metadata.HexBytes)
	length := 0
	if rs.ComputeMetafileHashesAndLength {
		hashes, length = rs.computeHashesAndLength(metadata.SNAPSHOT)
	}
	rs.MDTimestamp.Signed.Meta[fmt.Sprintf("%s.json", metadata.SNAPSHOT)] = &metadata.MetaFiles{
		Length:  int64(length),
		Hashes:  hashes,
		Version: rs.MDSnapshot.Signed.Version,
	}

	rs.MDTimestamp.Signed.Version += 1
}

// UpdateSnapshot updates snapshot, assigns targets versions
// and updates timestamp
func (rs *RepositorySimulator) UpdateSnapshot() {
	for target := range rs.AllTargets() {
		hashes := make(map[string]metadata.HexBytes)
		length := 0
		if rs.ComputeMetafileHashesAndLength {
			hashes, length = rs.computeHashesAndLength(target.Type)
		}

		rs.MDSnapshot.Signed.Meta[fmt.Sprintf("%s.json", target.Type)] = &metadata.MetaFiles{
			Length:  int64(length),
			Hashes:  hashes,
			Version: target.Version,
		}
	}
	rs.MDSnapshot.Signed.Version += 1
	rs.UpdateTimestamp()
}

// Given a delegator name return, its corresponding TargetsType object
func (rs *RepositorySimulator) getDelegator(delegatorName string) *metadata.TargetsType {
	if delegatorName == metadata.TARGETS {
		return &rs.MDTargets.Signed
	}
	delegation := rs.MDDelegates[delegatorName]
	return &delegation.Signed
}

// AddTarget creates a target from data and adds it to the TargetFiles.
func (rs *RepositorySimulator) AddTarget(role string, data []byte, path string) {
	targets := rs.getDelegator(role)
	target, err := metadata.TargetFile().FromBytes(path, data, "sha256")
	if err != nil {
		log.Panicf("failed to add target from %s: %v", path, err)
	}
	targets.Targets[path] = target
	rs.TargetFiles[path] = RepositoryTarget{
		Data:       data,
		TargetFile: target,
	}
}

// AddDelegation adds delegated target role to the repository
func (rs *RepositorySimulator) AddDelegation(delegatorName string, role metadata.DelegatedRole, targets metadata.TargetsType) {
	delegator := rs.getDelegator(delegatorName)
	if delegator.Delegations != nil && delegator.Delegations.SuccinctRoles != nil {
		log.Fatalln("can't add a role when SuccinctRoles is used")
	}
	// Create delegation
	if delegator.Delegations == nil {
		delegator.Delegations = &metadata.Delegations{
			Keys:  map[string]*metadata.Key{},
			Roles: []metadata.DelegatedRole{},
		}
	}
	// Put delegation last by default
	delegator.Delegations.Roles = append(delegator.Delegations.Roles, role)

	// By default add one new key for the role
	publicKey, _, signer := CreateKey()
	mdkey, err := metadata.KeyFromPublicKey(*publicKey)
	if err != nil {
		log.Fatalf("repository simulator: key conversion failed while adding delegation: %v", err)
	}
	err = delegator.AddKey(mdkey, role.Name)
	if err != nil {
		log.Debugf("repository simulator: failed to add key: %v", err)
	}
	rs.AddSigner(role.Name, mdkey.ID(), *signer)
	if _, ok := rs.MDDelegates[role.Name]; !ok {
		rs.MDDelegates[role.Name] = metadata.Metadata[metadata.TargetsType]{
			Signed:             targets,
			UnrecognizedFields: map[string]interface{}{},
		}
	}
}

// AddSuccinctRoles adds succinct roles info to a delegator with name "delegatorName".
//
// Note that for each delegated role represented by succinct roles an empty
// Targets instance is created
func (rs *RepositorySimulator) AddSuccinctRoles(delegatorName string, bitLength int, namePrefix string) {
	delegator := rs.getDelegator(delegatorName)
	if delegator.Delegations != nil && delegator.Delegations.Roles != nil {
		log.Fatalln("can't add a SuccinctRoles when delegated roles are used")
	}
	publicKey, _, signer := CreateKey()
	mdkey, err := metadata.KeyFromPublicKey(*publicKey)
	if err != nil {
		log.Fatalf("repository simulator: key conversion failed while adding succinct roles: %v", err)
	}
	succinctRoles := &metadata.SuccinctRoles{
		KeyIDs:     []string{},
		Threshold:  1,
		BitLength:  bitLength,
		NamePrefix: namePrefix,
	}
	delegator.Delegations = &metadata.Delegations{Roles: nil, SuccinctRoles: succinctRoles}
	// Add targets metadata for all bins
	for _, delegatedName := range succinctRoles.GetRoles() {
		rs.MDDelegates[delegatedName] = metadata.Metadata[metadata.TargetsType]{
			Signed: metadata.TargetsType{
				Expires: rs.SafeExpiry,
			},
		}
		rs.AddSigner(delegatedName, mdkey.ID(), *signer)
	}
	err = delegator.AddKey(mdkey, metadata.TARGETS)
	if err != nil {
		log.Debugf("repository simulator: failed to add key: %v", err)
	}
}

// Write dumps current repository metadata to rs.DumpDir

// This is a debugging tool: dumping repository state before running
// Updater refresh may be useful while debugging a test.
func (rs *RepositorySimulator) Write() {
	if rs.DumpDir == "" {
		rs.DumpDir = os.TempDir()
		log.Debugf("Repository Simulator dumps in %s\n", rs.DumpDir)
	}
	rs.DumpVersion += 1
	destDir := filepath.Join(rs.DumpDir, strconv.Itoa(int(rs.DumpVersion)))
	err := os.MkdirAll(destDir, os.ModePerm)
	if err != nil {
		log.Debugf("repository simulator: failed to create dir: %v", err)
	}
	for ver := 1; ver < len(rs.SignedRoots)+1; ver++ {
		f, _ := os.Create(filepath.Join(destDir, fmt.Sprintf("%d.root.json", ver)))
		defer f.Close()
		meta, err := rs.FetchMetadata(metadata.ROOT, &ver)
		if err != nil {
			log.Debugf("failed to fetch metadata: %v", err)
		}
		_, err = f.Write(meta)
		if err != nil {
			log.Debugf("repository simulator: failed to write signed roots: %v", err)
		}
	}
	noVersion := -1
	for _, role := range []string{metadata.TIMESTAMP, metadata.SNAPSHOT, metadata.TARGETS} {
		f, _ := os.Create(filepath.Join(destDir, fmt.Sprintf("%s.json", role)))
		defer f.Close()
		meta, err := rs.FetchMetadata(role, &noVersion)
		if err != nil {
			log.Debugf("failed to fetch metadata: %v", err)
		}
		_, err = f.Write(meta)
		if err != nil {
			log.Debugf("repository simulator: failed to write signed roots: %v", err)
		}
	}
	for role := range rs.MDDelegates {
		quotedRole := url.PathEscape(role)
		f, _ := os.Create(filepath.Join(destDir, fmt.Sprintf("%s.json", quotedRole)))
		defer f.Close()
		meta, err := rs.FetchMetadata(role, &noVersion)
		if err != nil {
			log.Debugf("failed to fetch metadata: %v", err)
		}
		_, err = f.Write(meta)
		if err != nil {
			log.Debugf("repository simulator: failed to write signed roots: %v", err)
		}
	}
}
