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

package config

import (
	"errors"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
	"github.com/theupdateframework/go-tuf/v2/metadata/fetcher"
)

// TestUpdaterConfigNew tests the New constructor using table-driven tests.
// It covers valid and invalid remote URL inputs.
func TestUpdaterConfigNew(t *testing.T) {
	rootBytes := helpers.CreateTestRootJSON(t)

	tests := []struct {
		name         string
		remoteURL    string
		expectError  bool
		errorMessage string
		validate     func(t *testing.T, cfg *UpdaterConfig)
	}{
		{
			name:        "valid simple path",
			remoteURL:   "simple/path",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.NotNil(t, cfg)
				assert.Equal(t, "simple/path", cfg.RemoteMetadataURL)
				assert.Equal(t, int64(256), cfg.MaxRootRotations)
				assert.Equal(t, 32, cfg.MaxDelegations)
				assert.Equal(t, int64(512000), cfg.RootMaxLength)
				assert.Equal(t, int64(16384), cfg.TimestampMaxLength)
				assert.Equal(t, int64(2000000), cfg.SnapshotMaxLength)
				assert.Equal(t, int64(5000000), cfg.TargetsMaxLength)
				assert.False(t, cfg.UnsafeLocalMode)
				assert.True(t, cfg.PrefixTargetsWithHash)
				assert.NotNil(t, cfg.Fetcher)
				assert.IsType(t, &fetcher.DefaultFetcher{}, cfg.Fetcher)
			},
		},
		{
			name:        "valid absolute path",
			remoteURL:   "/absolute/path/to/metadata",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.NotNil(t, cfg)
				assert.Equal(t, "/absolute/path/to/metadata", cfg.RemoteMetadataURL)
			},
		},
		{
			name:        "valid https URL",
			remoteURL:   "https://example.com/metadata",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.Equal(t, "https://example.com/metadata", cfg.RemoteMetadataURL)
				assert.Equal(t, "https://example.com/metadata/targets", cfg.RemoteTargetsURL)
			},
		},
		{
			name:        "valid file URL",
			remoteURL:   "file:///path/to/metadata",
			expectError: false,
		},
		{
			name:        "empty remote URL",
			remoteURL:   "",
			expectError: false,
			validate: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				assert.NotNil(t, cfg)
				assert.Equal(t, "", cfg.RemoteMetadataURL)
			},
		},
		{
			name:         "invalid control character in URL",
			remoteURL:    string([]byte{0x7f}),
			expectError:  true,
			errorMessage: "invalid control character",
		},
		{
			name:        "path with spaces",
			remoteURL:   "path with spaces",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := New(tt.remoteURL, rootBytes)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				assert.Nil(t, cfg)
				return
			}
			assert.NoError(t, err)
			assert.NotNil(t, cfg)
			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestUpdaterConfigDefaults verifies the default configuration values.
func TestUpdaterConfigDefaults(t *testing.T) {
	t.Run("default configuration values", func(t *testing.T) {
		rootBytes := helpers.CreateTestRootJSON(t)
		cfg, err := New("https://example.com", rootBytes)
		assert.NoError(t, err)

		// Inputs are stored on the config, and the targets URL is derived
		// from the metadata URL.
		assert.Equal(t, "https://example.com", cfg.RemoteMetadataURL)
		assert.Equal(t, "https://example.com/targets", cfg.RemoteTargetsURL)
		assert.Equal(t, rootBytes, cfg.LocalTrustedRoot)

		// The local cache directories are left for the caller to choose.
		assert.Empty(t, cfg.LocalMetadataDir)
		assert.Empty(t, cfg.LocalTargetsDir)

		assert.Equal(t, int64(256), cfg.MaxRootRotations)
		assert.Equal(t, 32, cfg.MaxDelegations)
		assert.Equal(t, int64(512000), cfg.RootMaxLength)
		assert.Equal(t, int64(16384), cfg.TimestampMaxLength)
		assert.Equal(t, int64(2000000), cfg.SnapshotMaxLength)
		assert.Equal(t, int64(5000000), cfg.TargetsMaxLength)
		assert.False(t, cfg.UnsafeLocalMode)
		assert.True(t, cfg.PrefixTargetsWithHash)
		assert.False(t, cfg.DisableLocalCache)
		assert.NotNil(t, cfg.Fetcher)
		assert.IsType(t, &fetcher.DefaultFetcher{}, cfg.Fetcher)
	})
}

// TestEnsurePathsExistTable tests EnsurePathsExist via table-driven subtests.
// EnsurePathsExist calls os.MkdirAll to create local cache directories.
func TestEnsurePathsExistTable(t *testing.T) {
	tests := []struct {
		name         string
		buildConfig  func(t *testing.T) *UpdaterConfig
		expectError  bool
		errorIs      error
		errorMessage string
	}{
		{
			name: "creates metadata and targets directories",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = filepath.Join(tmp, "metadata")
				cfg.LocalTargetsDir = filepath.Join(tmp, "targets")
				return cfg
			},
			expectError: false,
		},
		{
			name: "creates deeply nested directories",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = filepath.Join(tmp, "a", "b", "c", "metadata")
				cfg.LocalTargetsDir = filepath.Join(tmp, "a", "b", "c", "targets")
				return cfg
			},
			expectError: false,
		},
		{
			name: "no-op when DisableLocalCache is true",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.DisableLocalCache = true
				// Empty paths that would otherwise fail
				cfg.LocalMetadataDir = ""
				cfg.LocalTargetsDir = ""
				return cfg
			},
			expectError: false,
		},
		{
			name: "fails when metadata dir path is empty",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = ""
				cfg.LocalTargetsDir = ""
				return cfg
			},
			expectError: true,
			errorIs:     os.ErrNotExist,
		},
		{
			name: "fails when metadata dir path is a file",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				// Create a file at the path where a directory is expected
				metadataFile := filepath.Join(tmp, "metadata_file")
				err := os.WriteFile(metadataFile, []byte("test"), 0600)
				assert.NoError(t, err)

				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = metadataFile
				cfg.LocalTargetsDir = filepath.Join(tmp, "targets")
				return cfg
			},
			expectError: true,
		},
		{
			name: "already-existing directories succeed",
			buildConfig: func(t *testing.T) *UpdaterConfig {
				t.Helper()
				tmp := t.TempDir()
				metadataDir := filepath.Join(tmp, "metadata")
				targetsDir := filepath.Join(tmp, "targets")
				assert.NoError(t, os.MkdirAll(metadataDir, 0700))
				assert.NoError(t, os.MkdirAll(targetsDir, 0700))

				cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
				assert.NoError(t, err)
				cfg.LocalMetadataDir = metadataDir
				cfg.LocalTargetsDir = targetsDir
				return cfg
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.buildConfig(t)
			err := cfg.EnsurePathsExist()

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorIs != nil {
					assert.ErrorIs(t, err, tt.errorIs)
				}
				if tt.errorMessage != "" {
					assert.Contains(t, err.Error(), tt.errorMessage)
				}
				return
			}
			assert.NoError(t, err)
			if !cfg.DisableLocalCache {
				assert.DirExists(t, cfg.LocalMetadataDir)
				assert.DirExists(t, cfg.LocalTargetsDir)
			}
		})
	}
}

// nonDefaultFetcher implements fetcher.Fetcher but is intentionally not a
// *fetcher.DefaultFetcher, so it triggers the type-assertion failure path
// in each SetDefaultFetcher* method below.
type nonDefaultFetcher struct{}

func (nonDefaultFetcher) DownloadFile(string, int64, time.Duration) ([]byte, error) {
	return nil, nil
}

// newCfgWithFetcher builds a fresh UpdaterConfig and swaps in the given
// fetcher. The "wrong type" cases below use this to force the type
// assertion in the SetDefaultFetcher* methods to fail.
func newCfgWithFetcher(t *testing.T, f fetcher.Fetcher) *UpdaterConfig {
	t.Helper()
	cfg, err := New("https://example.com", helpers.CreateTestRootJSON(t))
	assert.NoError(t, err)
	cfg.Fetcher = f
	return cfg
}

// stubRoundTripper is an in-memory transport: it fails the first failFirst
// requests and answers the rest with 200 "ok". The setter tests download
// through it to observe which client and retry policy the fetcher uses.
type stubRoundTripper struct {
	failFirst int
	calls     int
}

// failAlways makes a stubRoundTripper fail every request.
const failAlways = math.MaxInt

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.calls++
	if s.calls <= s.failFirst {
		return nil, errors.New("stub transport failure")
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}, nil
}

// useStubTransport gives a default fetcher a private http.Client backed by
// rt, leaving the shared http.DefaultClient untouched. Other fetcher types
// are left as they are.
func useStubTransport(f fetcher.Fetcher, rt http.RoundTripper) {
	if df, ok := f.(*fetcher.DefaultFetcher); ok {
		df.SetHTTPClient(&http.Client{Transport: rt})
	}
}

// download fetches through the config's fetcher. The host is never dialled:
// every request is answered by a stubRoundTripper.
func download(cfg *UpdaterConfig) ([]byte, error) {
	return cfg.Fetcher.DownloadFile("http://go-tuf.invalid/root.json", 16, 0)
}

// TestSetDefaultFetcherHTTPClientTable covers cfg.SetDefaultFetcherHTTPClient.
// The method only does anything if cfg.Fetcher is the default fetcher.
func TestSetDefaultFetcherHTTPClientTable(t *testing.T) {
	tests := []struct {
		name        string
		fetcher     fetcher.Fetcher
		expectError bool
		errorMsg    string
	}{
		{
			name:    "default fetcher accepts a custom http.Client",
			fetcher: fetcher.NewDefaultFetcher(),
		},
		{
			name:        "non-default fetcher is rejected",
			fetcher:     nonDefaultFetcher{},
			expectError: true,
			errorMsg:    "fetcher is not type fetcher.DefaultFetcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newCfgWithFetcher(t, tt.fetcher)
			rt := &stubRoundTripper{}
			err := cfg.SetDefaultFetcherHTTPClient(&http.Client{Transport: rt})
			if tt.expectError {
				assert.ErrorContains(t, err, tt.errorMsg)
				return
			}
			assert.NoError(t, err)
			// Downloads must now go through the supplied client.
			data, err := download(cfg)
			assert.NoError(t, err)
			assert.Equal(t, "ok", string(data))
			assert.Equal(t, 1, rt.calls)
		})
	}
}

// TestSetDefaultFetcherTransportTable covers cfg.SetDefaultFetcherTransport.
func TestSetDefaultFetcherTransportTable(t *testing.T) {
	tests := []struct {
		name        string
		fetcher     fetcher.Fetcher
		expectError bool
		errorMsg    string
	}{
		{
			name:    "default fetcher accepts a custom RoundTripper",
			fetcher: fetcher.NewDefaultFetcher(),
		},
		{
			name:        "non-default fetcher is rejected",
			fetcher:     nonDefaultFetcher{},
			expectError: true,
			errorMsg:    "fetcher is not type fetcher.DefaultFetcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newCfgWithFetcher(t, tt.fetcher)
			// Start from a transport that fails, so a successful download
			// proves the RoundTripper passed to the setter replaced it.
			useStubTransport(tt.fetcher, &stubRoundTripper{failFirst: failAlways})
			rt := &stubRoundTripper{}
			err := cfg.SetDefaultFetcherTransport(rt)
			if tt.expectError {
				assert.ErrorContains(t, err, tt.errorMsg)
				return
			}
			assert.NoError(t, err)
			data, err := download(cfg)
			assert.NoError(t, err)
			assert.Equal(t, "ok", string(data))
			assert.Equal(t, 1, rt.calls)
		})
	}
}

// TestSetDefaultFetcherRetryTable covers cfg.SetDefaultFetcherRetry, which
// configures constant-interval retries via the underlying fetcher.
func TestSetDefaultFetcherRetryTable(t *testing.T) {
	tests := []struct {
		name        string
		fetcher     fetcher.Fetcher
		interval    time.Duration
		count       uint
		expectError bool
		errorMsg    string
		// failFirst is how many leading requests the transport fails.
		failFirst int
		// wantCalls is how many requests the download must make.
		wantCalls       int
		wantDownloadErr bool
	}{
		{
			name:            "default fetcher stops after the configured count",
			fetcher:         fetcher.NewDefaultFetcher(),
			interval:        time.Millisecond,
			count:           3,
			failFirst:       failAlways,
			wantCalls:       3,
			wantDownloadErr: true,
		},
		{
			name:      "zero retry count does not cap retries",
			fetcher:   fetcher.NewDefaultFetcher(),
			interval:  0,
			count:     0,
			failFirst: 2,
			wantCalls: 3,
		},
		{
			name:        "non-default fetcher is rejected",
			fetcher:     nonDefaultFetcher{},
			interval:    50 * time.Millisecond,
			count:       1,
			expectError: true,
			errorMsg:    "fetcher is not type fetcher.DefaultFetcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newCfgWithFetcher(t, tt.fetcher)
			rt := &stubRoundTripper{failFirst: tt.failFirst}
			useStubTransport(tt.fetcher, rt)
			err := cfg.SetDefaultFetcherRetry(tt.interval, tt.count)
			if tt.expectError {
				assert.ErrorContains(t, err, tt.errorMsg)
				return
			}
			assert.NoError(t, err)
			_, err = download(cfg)
			if tt.wantDownloadErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCalls, rt.calls)
		})
	}
}

// TestSetRetryOptionsTable covers cfg.SetRetryOptions, which forwards
// variadic backoff.RetryOption values to the underlying fetcher.
func TestSetRetryOptionsTable(t *testing.T) {
	tests := []struct {
		name        string
		fetcher     fetcher.Fetcher
		opts        []backoff.RetryOption
		expectError bool
		errorMsg    string
		// failFirst is how many leading requests the transport fails.
		failFirst int
		// wantCalls is how many requests the download must make.
		wantCalls       int
		wantDownloadErr bool
	}{
		{
			// Passing no options drops the default fetcher's single-try
			// limit, so one failure is retried (after backoff's default
			// initial interval of roughly half a second).
			name:      "no options removes the default single-try limit",
			fetcher:   fetcher.NewDefaultFetcher(),
			opts:      nil,
			failFirst: 1,
			wantCalls: 2,
		},
		{
			name:    "default fetcher stops after the max-tries option",
			fetcher: fetcher.NewDefaultFetcher(),
			opts: []backoff.RetryOption{
				backoff.WithMaxTries(5),
				backoff.WithBackOff(backoff.NewConstantBackOff(time.Millisecond)),
			},
			failFirst:       failAlways,
			wantCalls:       5,
			wantDownloadErr: true,
		},
		{
			name:        "non-default fetcher is rejected",
			fetcher:     nonDefaultFetcher{},
			opts:        []backoff.RetryOption{backoff.WithMaxTries(1)},
			expectError: true,
			errorMsg:    "fetcher is not type fetcher.DefaultFetcher",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := newCfgWithFetcher(t, tt.fetcher)
			rt := &stubRoundTripper{failFirst: tt.failFirst}
			useStubTransport(tt.fetcher, rt)
			err := cfg.SetRetryOptions(tt.opts...)
			if tt.expectError {
				assert.ErrorContains(t, err, tt.errorMsg)
				return
			}
			assert.NoError(t, err)
			_, err = download(cfg)
			if tt.wantDownloadErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantCalls, rt.calls)
		})
	}
}
