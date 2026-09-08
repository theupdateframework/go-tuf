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

package updater

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/simulator"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

func TestSelectTargetHashAlgorithm(t *testing.T) {
	for _, tt := range []struct {
		name     string
		hashes   metadata.Hashes
		expected string
	}{
		{
			name:     "no hashes",
			hashes:   metadata.Hashes{},
			expected: "",
		},
		{
			name:     "single hash",
			hashes:   metadata.Hashes{"sha512": {0x01}},
			expected: "sha512",
		},
		{
			name:     "sha256 preferred over sha512",
			hashes:   metadata.Hashes{"sha512": {0x01}, "sha256": {0x02}},
			expected: "sha256",
		},
		{
			name:     "preferred algorithm wins over an unknown one",
			hashes:   metadata.Hashes{"aardvark": {0x01}, "sha512": {0x02}},
			expected: "sha512",
		},
		{
			name:     "unknown algorithms fall back to lexicographic order",
			hashes:   metadata.Hashes{"zebra": {0x01}, "aardvark": {0x02}, "mongoose": {0x03}},
			expected: "aardvark",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// repeat, as a wrong implementation relying on map iteration
			// order may pick the expected algorithm by chance
			for range 100 {
				assert.Equal(t, tt.expected, selectTargetHashAlgorithm(tt.hashes))
			}
		})
	}
}

// urlRecordingFetcher records the URLs it is asked for and always serves the
// same content
type urlRecordingFetcher struct {
	urls []string
	data []byte
}

func (f *urlRecordingFetcher) DownloadFile(urlPath string, _ int64, _ time.Duration) ([]byte, error) {
	f.urls = append(f.urls, urlPath)
	return f.data, nil
}

func TestDownloadTargetHashPrefixIsDeterministic(t *testing.T) {
	// A target listing more than one hash must always resolve to the same
	// hash-prefixed URL (ref. https://github.com/theupdateframework/go-tuf/issues/746)

	err := loadOrResetTrustedRootMetadata()
	assert.NoError(t, err)
	simulator.Sim.MDRoot.Signed.ConsistentSnapshot = true
	simulator.Sim.MDRoot.Signed.Version += 1
	simulator.Sim.PublishRoot()

	updaterConfig, err := loadUpdaterConfig()
	assert.NoError(t, err)
	updaterConfig.DisableLocalCache = true
	updaterConfig.PrefixTargetsWithHash = true
	updater, err := runRefresh(updaterConfig, time.Now())
	assert.NoError(t, err)

	content := []byte("target content")
	sha256Hash := sha256.Sum256(content)
	sha512Hash := sha512.Sum512(content)
	targetFile := &metadata.TargetFiles{
		Length: int64(len(content)),
		Hashes: metadata.Hashes{
			"sha256": sha256Hash[:],
			"sha512": sha512Hash[:],
		},
		Path: "dir/file.txt",
	}
	// sha256 is preferred, so that is the hash the URL is built from
	expectedURL := fmt.Sprintf("https://example.com/targets/dir/%s.file.txt", hex.EncodeToString(sha256Hash[:]))

	// repeat, as Go randomizes map iteration order and a single call could
	// pick the expected hash by chance
	for range 100 {
		fetcher := &urlRecordingFetcher{data: content}
		updaterConfig.Fetcher = fetcher

		_, _, err := updater.DownloadTarget(targetFile, "ignored", "https://example.com/targets")
		assert.NoError(t, err)
		assert.Equal(t, []string{expectedURL}, fetcher.urls)
	}
}
