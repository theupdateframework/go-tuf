// Copyright 2026 The Update Framework Authors
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

package updater

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/secure-systems-lab/go-securesystemslib/cjson"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
	"github.com/theupdateframework/go-tuf/v2/metadata/config"
)

// A delegated role name must not change where its cached metadata is read
// from on disk. persistMetadata, downloadMetadata and generateTargetFilePath
// all url.PathEscape the role name before using it as a path component, so a
// name is confined to LocalMetadataDir. loadTargets previously joined the raw
// name, so a name containing a path-traversal sequence or characters rewritten
// by url.PathEscape either resolved outside LocalMetadataDir or missed the
// escaped file written on persist.
func TestDelegatedRoleNameLocalReadStaysInMetadataDir(t *testing.T) {
	const targetPath = "target.txt"

	cases := []struct {
		name string
		role string
	}{
		{name: "dotdot", role: ".."},
		{name: "dot", role: "."},
		{name: "slash", role: "a/b"},
		{name: "space", role: "role with space"},
		{name: "percent", role: "100%"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := simulator.NewTestRepository(t)
			defer repo.Cleanup()

			delegate(repo, metadata.TARGETS, tc.role, "*")
			repo.AddTarget(tc.role, []byte("hello"), targetPath)
			repo.UpdateSnapshot()

			// First client fetches the delegated metadata and caches it locally.
			up1, err := createAndRefresh(t, repo)
			require.NoError(t, err)
			info, err := up1.GetTargetInfo(targetPath)
			require.NoError(t, err)
			require.NotNil(t, info)

			expectedFile := filepath.Join(repo.MetadataDir, url.PathEscape(tc.role)+".json")
			assert.Equal(t, repo.MetadataDir, filepath.Dir(expectedFile))
			assert.FileExists(t, expectedFile)

			// A fresh client reads that cached metadata back instead of
			// refetching it from the remote repository.
			repo.Simulator.FetchTracker.Metadata = []simulator.FTMetadata{}
			up2, err := createAndRefresh(t, repo)
			require.NoError(t, err)
			info, err = up2.GetTargetInfo(targetPath)
			require.NoError(t, err)
			require.NotNil(t, info)

			refetched := slices.ContainsFunc(repo.Simulator.FetchTracker.Metadata, func(m simulator.FTMetadata) bool {
				return m.Name == tc.role
			})
			assert.False(t, refetched, "delegated role %q should be read from the local cache, not refetched", tc.role)
		})
	}
}

// A compromised delegated role + online snapshot/timestamp keys must not be
// able to delegate to any top-level role name (or case-folded variant) to
// override top-level targets, poison local cached root/timestamp/snapshot/targets
// metadata, or bypass TUF §5.5.5 rollback protection.
func TestDelegatedRoleCannotOverwriteTopLevelCacheOrBypassRollback(t *testing.T) {
	newKeyAndSigner := func(t *testing.T) (*metadata.Key, signature.Signer) {
		t.Helper()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		k, err := metadata.KeyFromPublicKey(pub)
		require.NoError(t, err)
		s, err := signature.LoadSignerVerifier(priv, crypto.Hash(0))
		require.NoError(t, err)
		return k, s
	}

	rawDelegationBytes := func(t *testing.T, teamKey *metadata.Key, teamSigner signature.Signer, badRole string, badKey *metadata.Key, exp time.Time) []byte {
		t.Helper()
		teamKeyID, err := teamKey.ID()
		require.NoError(t, err)
		badKeyID, err := badKey.ID()
		require.NoError(t, err)

		// Build a valid TargetsType, rewrite the delegated role name in raw
		// JSON, and sign the canonical Signed object with teamSigner so the
		// remote document carries a valid signature over the forbidden role name.
		placeholder := metadata.Targets(exp)
		placeholder.Signed.Version = 2
		placeholder.Signed.Delegations = &metadata.Delegations{
			Keys: map[string]*metadata.Key{badKeyID: badKey},
			Roles: []metadata.DelegatedRole{{
				Name:      "placeholder-role",
				KeyIDs:    []string{badKeyID},
				Threshold: 1,
				Paths:     []string{"*/*", "*"},
			}},
		}
		validBytes, err := placeholder.ToBytes(false)
		require.NoError(t, err)

		var doc map[string]any
		require.NoError(t, json.Unmarshal(validBytes, &doc))
		signedMap := doc["signed"].(map[string]any)
		delegationsMap := signedMap["delegations"].(map[string]any)
		rolesSlice := delegationsMap["roles"].([]any)
		rolesSlice[0].(map[string]any)["name"] = badRole

		canonicalSigned, err := cjson.EncodeCanonical(signedMap)
		require.NoError(t, err)
		sigBytes, err := teamSigner.SignMessage(bytes.NewReader(canonicalSigned))
		require.NoError(t, err)
		doc["signatures"] = []map[string]any{{
			"keyid": teamKeyID,
			"sig":   hex.EncodeToString(sigBytes),
		}}

		out, err := json.Marshal(doc)
		require.NoError(t, err)
		return out
	}

	badRoles := []string{
		"root", "Root",
		"timestamp", "Timestamp",
		"snapshot", "Snapshot",
		"targets", "Targets",
		"",
	}

	for _, consistentSnapshot := range []bool{true, false} {
		t.Run(fmt.Sprintf("consistent_snapshot_%t", consistentSnapshot), func(t *testing.T) {
			for _, badRole := range badRoles {
				t.Run("role_"+badRole, func(t *testing.T) {
					exp := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Second)

					rootKey, rootSigner := newKeyAndSigner(t)
					targetsKey, targetsSigner := newKeyAndSigner(t)
					snapshotKey, snapshotSigner := newKeyAndSigner(t)
					timestampKey, timestampSigner := newKeyAndSigner(t)
					teamKey, teamSigner := newKeyAndSigner(t)
					subKey, subSigner := newKeyAndSigner(t)

					rootMeta := metadata.Root(exp)
					rootMeta.Signed.ConsistentSnapshot = consistentSnapshot
					require.NoError(t, rootMeta.Signed.AddKey(rootKey, metadata.ROOT))
					require.NoError(t, rootMeta.Signed.AddKey(targetsKey, metadata.TARGETS))
					require.NoError(t, rootMeta.Signed.AddKey(snapshotKey, metadata.SNAPSHOT))
					require.NoError(t, rootMeta.Signed.AddKey(timestampKey, metadata.TIMESTAMP))
					_, err := rootMeta.Sign(rootSigner)
					require.NoError(t, err)
					rootV1Bytes, err := rootMeta.ToBytes(false)
					require.NoError(t, err)

					legitTopTarget, err := metadata.TargetFile().FromBytes("core/app.bin", []byte("patched-v2"))
					require.NoError(t, err)

					// Historical targets v1 and current targets v2 (delegating * to team-a).
					teamKeyID, err := teamKey.ID()
					require.NoError(t, err)
					makeTargets := func(ver int64, content string) []byte {
						tf, err := metadata.TargetFile().FromBytes("core/app.bin", []byte(content))
						require.NoError(t, err)
						tg := metadata.Targets(exp)
						tg.Signed.Version = ver
						tg.Signed.Targets["core/app.bin"] = tf
						tg.Signed.Delegations = &metadata.Delegations{
							Keys: map[string]*metadata.Key{teamKeyID: teamKey},
							Roles: []metadata.DelegatedRole{{
								Name:      "team-a",
								KeyIDs:    []string{teamKeyID},
								Threshold: 1,
								Paths:     []string{"*/*", "*"},
							}},
						}
						_, err = tg.Sign(targetsSigner)
						require.NoError(t, err)
						b, err := tg.ToBytes(false)
						require.NoError(t, err)
						return b
					}
					targetsV1Bytes := makeTargets(1, "old-v1")
					targetsV2Bytes := makeTargets(2, "patched-v2")

					teamV1 := metadata.Targets(exp)
					teamV1.Signed.Version = 1
					_, err = teamV1.Sign(teamSigner)
					require.NoError(t, err)
					teamV1Bytes, err := teamV1.ToBytes(false)
					require.NoError(t, err)

					var mu sync.Mutex
					files := map[string][]byte{
						"/1.root.json": rootV1Bytes,
					}
					rolePath := func(role string, ver int64) string {
						escaped := url.PathEscape(role)
						if consistentSnapshot {
							return fmt.Sprintf("/%d.%s.json", ver, escaped)
						}
						return fmt.Sprintf("/%s.json", escaped)
					}
					files[rolePath(metadata.TARGETS, 1)] = targetsV1Bytes
					files[rolePath(metadata.TARGETS, 2)] = targetsV2Bytes
					files[rolePath("team-a", 1)] = teamV1Bytes

					publishSnapAndTS := func(ver int64, meta map[string]int64) {
						snap := metadata.Snapshot(exp)
						snap.Signed.Version = ver
						snap.Signed.Meta = map[string]*metadata.MetaFiles{}
						for k, v := range meta {
							snap.Signed.Meta[k] = metadata.MetaFile(v)
						}
						_, err := snap.Sign(snapshotSigner)
						require.NoError(t, err)
						snapBytes, err := snap.ToBytes(false)
						require.NoError(t, err)
						files[rolePath(metadata.SNAPSHOT, ver)] = snapBytes

						ts := metadata.Timestamp(exp)
						ts.Signed.Version = ver
						ts.Signed.Meta = map[string]*metadata.MetaFiles{"snapshot.json": metadata.MetaFile(ver)}
						_, err = ts.Sign(timestampSigner)
						require.NoError(t, err)
						tsBytes, err := ts.ToBytes(false)
						require.NoError(t, err)
						files["/timestamp.json"] = tsBytes
					}

					publishSnapAndTS(2, map[string]int64{"targets.json": 2, "team-a.json": 1})

					srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						data, ok := files[r.URL.Path]
						mu.Unlock()
						if ok {
							_, _ = w.Write(data)
							return
						}
						http.NotFound(w, r)
					}))
					defer srv.Close()

					metaDir := t.TempDir()
					targetsDir := t.TempDir()
					require.NoError(t, os.WriteFile(filepath.Join(metaDir, "root.json"), rootV1Bytes, 0o644))

					newClientFromCachedRoot := func() *Updater {
						cachedRoot, err := os.ReadFile(filepath.Join(metaDir, "root.json"))
						require.NoError(t, err)
						cfg, err := config.New(srv.URL, cachedRoot)
						require.NoError(t, err)
						cfg.LocalMetadataDir = metaDir
						cfg.LocalTargetsDir = targetsDir
						cfg.PrefixTargetsWithHash = consistentSnapshot
						up, err := New(cfg)
						require.NoError(t, err)
						return up
					}

					// Step 1: Client refreshes cleanly at v2.
					up1 := newClientFromCachedRoot()
					require.NoError(t, up1.Refresh())
					origRootCached, err := os.ReadFile(filepath.Join(metaDir, "root.json"))
					require.NoError(t, err)

					// Step 2: Compromised team-a + snapshot + timestamp attempt to delegate to badRole
					// and override both "team-a/plugin.bin" and top-level "core/app.bin".
					subVer := int64(99)
					if badRole == metadata.TARGETS {
						subVer = 2
					}
					subMeta := metadata.Targets(exp)
					subMeta.Signed.Version = subVer
					evilTF, err := metadata.TargetFile().FromBytes("team-a/plugin.bin", []byte("evil"))
					require.NoError(t, err)
					forgedTopTF, err := metadata.TargetFile().FromBytes("core/app.bin", []byte("forged-by-delegation"))
					require.NoError(t, err)
					subMeta.Signed.Targets["team-a/plugin.bin"] = evilTF
					subMeta.Signed.Targets["core/app.bin"] = forgedTopTF
					_, err = subMeta.Sign(subSigner)
					require.NoError(t, err)
					subBytes, err := subMeta.ToBytes(false)
					require.NoError(t, err)

					snapMetaV3 := map[string]int64{
						"targets.json": 2,
						"team-a.json":  2,
					}
					snapMetaV3[fmt.Sprintf("%s.json", badRole)] = subVer

					mu.Lock()
					files[rolePath("team-a", 2)] = rawDelegationBytes(t, teamKey, teamSigner, badRole, subKey, exp)
					files[rolePath(metadata.TARGETS, 2)] = targetsV2Bytes
					publishSnapAndTS(3, snapMetaV3)
					if consistentSnapshot {
						files[rolePath(badRole, subVer)] = subBytes
					}
					mu.Unlock()

					up2 := newClientFromCachedRoot()
					require.NoError(t, up2.Refresh())

					// For non-consistent snapshots, even if a dynamic mirror swaps /<badRole>.json
					// to the forged TargetsType payload right before GetTargetInfo, it must be rejected.
					if !consistentSnapshot {
						mu.Lock()
						files[rolePath(badRole, subVer)] = subBytes
						mu.Unlock()
					}

					_, err = up2.GetTargetInfo("team-a/plugin.bin")
					require.ErrorIs(t, err, &metadata.ErrDeserialization{}, "delegation to %q must be rejected on parse", badRole)
					require.ErrorIs(t, err, &metadata.ErrValue{}, "delegation to %q must fail with ErrValue", badRole)

					// Top-level target in memory and via GetTargetInfo must not be overridden.
					topInfo, err := up2.GetTargetInfo("core/app.bin")
					require.NoError(t, err)
					assert.True(t, topInfo.Equal(*legitTopTarget))
					assert.True(t, up2.GetTopLevelTargets()["core/app.bin"].Equal(*legitTopTarget))

					// All four cached top-level metadata files on disk remain valid and unpoisoned.
					afterRootCached, err := os.ReadFile(filepath.Join(metaDir, "root.json"))
					require.NoError(t, err)
					assert.Equal(t, origRootCached, afterRootCached)

					afterTimestampCached, err := os.ReadFile(filepath.Join(metaDir, "timestamp.json"))
					require.NoError(t, err)
					parsedTS, err := metadata.Timestamp().FromBytes(afterTimestampCached)
					require.NoError(t, err)
					assert.Equal(t, int64(3), parsedTS.Signed.Version)

					afterSnapshotCached, err := os.ReadFile(filepath.Join(metaDir, "snapshot.json"))
					require.NoError(t, err)
					parsedSnap, err := metadata.Snapshot().FromBytes(afterSnapshotCached)
					require.NoError(t, err)
					assert.Equal(t, int64(3), parsedSnap.Signed.Version)

					afterTargetsCached, err := os.ReadFile(filepath.Join(metaDir, "targets.json"))
					require.NoError(t, err)
					parsedTargets, err := metadata.Targets().FromBytes(afterTargetsCached)
					require.NoError(t, err)
					assert.Equal(t, int64(2), parsedTargets.Signed.Version)
					assert.True(t, parsedTargets.Signed.Targets["core/app.bin"].Equal(*legitTopTarget))

					// Step 3: Attempted rollback to targets v1 on next Refresh must fail with ErrBadVersionNumber.
					snapMetaV4 := map[string]int64{
						"targets.json": 1,
						"team-a.json":  2,
					}
					if badRole != metadata.TARGETS {
						snapMetaV4[fmt.Sprintf("%s.json", badRole)] = subVer
					}
					mu.Lock()
					files[rolePath(metadata.TARGETS, 1)] = targetsV1Bytes
					publishSnapAndTS(4, snapMetaV4)
					mu.Unlock()

					up3 := newClientFromCachedRoot()
					err = up3.Refresh()
					assert.ErrorIs(t, err, &metadata.ErrBadVersionNumber{})
				})
			}
		})
	}
}

// TestLoadTargetsRejectsTopLevelAndEmptyRoleNames directly exercises the
// defense-in-depth checks in (*Updater).loadTargets and preOrderDepthFirstWalk
// even when an in-memory DelegatedRole bypasses JSON unmarshaling.
func TestLoadTargetsRejectsTopLevelAndEmptyRoleNames(t *testing.T) {
	repo := simulator.NewTestRepository(t)
	defer repo.Cleanup()

	repo.AddTarget(metadata.TARGETS, []byte("legit-top"), "top/file.txt")
	delegate(repo, metadata.TARGETS, "team-a", "sub/*")
	repo.AddTarget("team-a", []byte("legit-sub"), "sub/existing.txt")
	up := refreshedUpdater(t, repo)

	// Load "team-a" cleanly first so it is present in up.trusted.Targets.
	info, err := up.GetTargetInfo("sub/existing.txt")
	require.NoError(t, err)
	require.NotNil(t, info)

	// Root delegator may only load the top-level "targets" role.
	_, err = up.loadTargets(context.Background(), "team-a", metadata.ROOT)
	assert.ErrorIs(t, err, &metadata.ErrValue{})

	origCached := map[string][]byte{}
	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		b, err := os.ReadFile(filepath.Join(repo.MetadataDir, role+".json"))
		require.NoError(t, err)
		origCached[role] = b
	}

	repo.Simulator.FetchTracker.Metadata = nil

	reserved := []string{
		"",
		"root", "Root",
		"timestamp", "Timestamp",
		"snapshot", "Snapshot",
		"targets", "Targets",
		"\u017fnapshot",
	}

	for _, badRole := range reserved {
		t.Run("role_"+badRole, func(t *testing.T) {
			// Direct loadTargets call with non-root parent must fail before any I/O.
			_, err := up.loadTargets(context.Background(), badRole, "team-a")
			assert.ErrorIs(t, err, &metadata.ErrValue{})

			// Even if in-memory Delegations on trusted "team-a" contain badRole,
			// GetTargetInfo must reject it during the delegation walk without
			// overriding top-level roles or touching cached metadata.
			up.trusted.Targets["team-a"].Signed.Delegations.Roles = []metadata.DelegatedRole{{
				Name:      badRole,
				KeyIDs:    []string{"any-key"},
				Threshold: 1,
				Paths:     []string{"sub/*", "top/*"},
			}}
			_, err = up.GetTargetInfo("sub/new.txt")
			if badRole == metadata.TARGETS {
				// Exact "targets" is also skipped by preOrderDepthFirstWalk's cycle check.
				assert.ErrorContains(t, err, "not found")
			} else {
				assert.ErrorIs(t, err, &metadata.ErrValue{})
			}

			topTF := up.GetTopLevelTargets()["top/file.txt"]
			require.NotNil(t, topTF)
			assert.Equal(t, int64(len("legit-top")), topTF.Length)
		})
	}

	assert.Empty(t, repo.Simulator.FetchTracker.Metadata, "rejected delegated role names must not trigger remote fetches")
	for _, role := range metadata.TOP_LEVEL_ROLE_NAMES {
		after, err := os.ReadFile(filepath.Join(repo.MetadataDir, role+".json"))
		require.NoError(t, err)
		assert.Equal(t, origCached[role], after, "cached %s.json must remain untouched", role)
	}
}
