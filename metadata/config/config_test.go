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

package config

import (
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/rdimitrov/go-tuf-metadata/metadata/fetcher"
	"github.com/stretchr/testify/assert"
)

func TestNewUpdaterConfig(t *testing.T) {
	// setup testing table (tt) and create subtest for each entry
	for _, tt := range []struct {
		name      string
		desc      string
		remoteURL string
		rootBytes []byte
		config    *UpdaterConfig
		wantErr   error
	}{
		{
			name:      "success",
			desc:      "No errors expected",
			remoteURL: "somepath",
			rootBytes: []byte("somerootbytes"),
			config: &UpdaterConfig{
				MaxRootRotations:      32,
				MaxDelegations:        32,
				RootMaxLength:         512000,
				TimestampMaxLength:    16384,
				SnapshotMaxLength:     2000000,
				TargetsMaxLength:      5000000,
				Fetcher:               &fetcher.DefaultFetcher{},
				LocalTrustedRoot:      []byte("somerootbytes"),
				RemoteMetadataURL:     "somepath",
				RemoteTargetsURL:      "somepath/targets",
				DisableLocalCache:     false,
				PrefixTargetsWithHash: true,
			},
			wantErr: nil,
		},
		{
			name:      "invalid character in URL",
			desc:      "Invalid ASCII control sequence in input",
			remoteURL: string([]byte{0x7f}),
			rootBytes: []byte("somerootbytes"),
			config:    nil,
			wantErr:   &url.Error{}, // just make sure this is non-nil, url pkg has no exported errors
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// this will only be printed if run in verbose mode or if test fails
			t.Logf("Desc: %s", tt.desc)
			// run the function under test
			updaterConfig, err := New(tt.remoteURL, tt.rootBytes)
			// special case if we expect no error
			if tt.wantErr == nil {
				assert.NoErrorf(t, err, "expected no error but got %v", err)
				assert.EqualExportedValuesf(t, *tt.config, *updaterConfig, "expected %#+v but got %#+v", tt.config, updaterConfig)
				return
			}
			// compare the error with our expected error
			assert.Nilf(t, updaterConfig, "expected nil but got %#+v", updaterConfig)
			assert.Errorf(t, err, "expected %v but got %v", tt.wantErr, err)
		})
	}
}

func TestEnsurePathsExist(t *testing.T) {
	// setup testing table (tt) and create subtest for each entry
	for _, tt := range []struct {
		name    string
		desc    string
		config  *UpdaterConfig
		setup   func(t *testing.T, cfg *UpdaterConfig)
		wantErr error
	}{
		{
			name: "success",
			desc: "No errors expected",
			config: &UpdaterConfig{
				DisableLocalCache: false,
			},
			setup: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
				tmp := t.TempDir()
				cfg.LocalTargetsDir = filepath.Join(tmp, "targets")
				cfg.LocalMetadataDir = filepath.Join(tmp, "metadata")
			},
			wantErr: nil,
		},
		{
			name: "path not exist",
			desc: "No local directories error",
			config: &UpdaterConfig{
				DisableLocalCache: false,
			},
			setup: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
			},
			wantErr: os.ErrNotExist,
		},
		{
			name: "no local cache",
			desc: "Test if method no-op works",
			config: &UpdaterConfig{
				DisableLocalCache: true,
			},
			setup: func(t *testing.T, cfg *UpdaterConfig) {
				t.Helper()
			},
			wantErr: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// this will only be printed if run in verbose mode or if test fails
			t.Logf("Desc: %s", tt.desc)
			// run special test setup in case it is needed for any subtest
			tt.setup(t, tt.config)
			// run the method under test
			err := tt.config.EnsurePathsExist()
			// special case if we expect no error
			if tt.wantErr == nil {
				assert.NoErrorf(t, err, "expected no error but got %v", err)
				return
			}
			// compare the error with our expected error
			assert.ErrorIsf(t, err, tt.wantErr, "expected %v but got %v", tt.wantErr, err)
		})
	}
}
