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

package multirepo

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewConfig(t *testing.T) {
	for _, tt := range []struct {
		name    string
		desc    string
		repoMap []byte
		roots   map[string][]byte
		config  *MultiRepoConfig
		wantErr error
	}{
		{
			name:    "Success",
			desc:    "This tests expects no error when creating a new config",
			repoMap: []byte(""),
			roots:   map[string][]byte{},
			config:  &MultiRepoConfig{},
			wantErr: nil,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Desc: %s", tt.desc)

			cfg, err := NewConfig(tt.repoMap, tt.roots)

			if tt.wantErr == nil {
				assert.NoErrorf(t, err, "expected no error but got %v", err)
				return
			}

			assert.ErrorIsf(t, err, tt.wantErr, "expected error %v but got %v", tt.wantErr, err)
			assert.Equalf(t, tt.config, cfg, "expected config %v but got %v", tt.config, cfg)
		})
	}
}

func TestNew(t *testing.T) {
	for _, tt := range []struct {
		name    string
		desc    string
		config  *MultiRepoConfig
		client  *MultiRepoClient
		wantErr error
	}{
		{
			name: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Desc: %s", tt.desc)

			client, err := New(tt.config)

			if tt.wantErr == nil {
				assert.NoErrorf(t, err, "expected no error but got %v", err)
				return
			}

			assert.ErrorIsf(t, err, tt.wantErr, "expected error %v but got %v", tt.wantErr, err)
			assert.Equalf(t, tt.client, client, "expected client %v but got %v", tt.client, client)
		})
	}
}
