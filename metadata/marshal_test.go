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

package metadata

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
)

func TestMarshalUnmarshalJSON(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "RootType Marshal/Unmarshal",
			input:   RootType{Type: "root", SpecVersion: "1.0", ConsistentSnapshot: true, Version: 1, Expires: fixedTime},
			wantErr: false,
		},
		{
			name:    "SnapshotType Marshal/Unmarshal",
			input:   SnapshotType{Type: "snapshot", SpecVersion: "1.0", Version: 1, Expires: fixedTime},
			wantErr: false,
		},
		{
			name:    "TimestampType Marshal/Unmarshal",
			input:   TimestampType{Type: "timestamp", SpecVersion: "1.0", Version: 1, Expires: fixedTime},
			wantErr: false,
		},
		{
			name:    "TargetsType Marshal/Unmarshal",
			input:   TargetsType{Type: "targets", SpecVersion: "1.0", Version: 1, Expires: fixedTime},
			wantErr: false,
		},
		{
			name:    "MetaFiles Marshal/Unmarshal",
			input:   MetaFiles{Length: 123, Hashes: Hashes{"sha256": HexBytes("abc123")}, Version: 1},
			wantErr: false,
		},
		{
			name:    "TargetFiles Marshal/Unmarshal",
			input:   TargetFiles{Length: 123, Hashes: Hashes{"sha256": HexBytes("abc123")}},
			wantErr: false,
		},
		{
			name:    "Key Marshal/Unmarshal",
			input:   Key{Type: "ed25519", Scheme: "scheme", Value: KeyVal{PublicKey: "publicKey"}},
			wantErr: false,
		},
		{
			name:    "Signature Marshal/Unmarshal",
			input:   Signature{KeyID: "keyid", Signature: HexBytes("signature")},
			wantErr: false,
		},
		{
			name:    "Delegations Marshal/Unmarshal",
			input:   Delegations{Keys: map[string]*Key{"keyid": {Type: "ed25519", Scheme: "scheme", Value: KeyVal{PublicKey: "publicKey"}}}},
			wantErr: false,
		},
		{
			name:    "DelegatedRole Marshal/Unmarshal",
			input:   DelegatedRole{Name: "role", KeyIDs: []string{"keyid"}, Threshold: 1, Terminating: true},
			wantErr: false,
		},
		{
			name:    "SuccinctRoles Marshal/Unmarshal",
			input:   SuccinctRoles{KeyIDs: []string{"keyid"}, Threshold: 1, BitLength: 256, NamePrefix: "prefix"},
			wantErr: false,
		},
		{
			name:    "HexBytes Marshal/Unmarshal",
			input:   HexBytes("abc123"),
			wantErr: false,
		},
		{
			name:    "Empty HexBytes Marshal/Unmarshal",
			input:   HexBytes(""),
			wantErr: false,
		},
		{
			name:    "Role Marshal/Unmarshal",
			input:   Role{KeyIDs: []string{"key1", "key2"}, Threshold: 2},
			wantErr: false,
		},
		{
			name:    "KeyVal Marshal/Unmarshal",
			input:   KeyVal{PublicKey: "public-key-bytes"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Marshal the input
			data, err := json.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return // Skip unmarshal test if marshal was expected to fail
			}

			// Unmarshal back to same type
			switch v := tt.input.(type) {
			case RootType:
				var result RootType
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Type, v.Type)
				assert.Equal(t, result.Version, v.Version)
				assert.Equal(t, result.SpecVersion, v.SpecVersion)

			case SnapshotType:
				var result SnapshotType
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Type, v.Type)
				assert.Equal(t, result.Version, v.Version)

			case TimestampType:
				var result TimestampType
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Type, v.Type)
				assert.Equal(t, result.Version, v.Version)

			case TargetsType:
				var result TargetsType
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Type, v.Type)
				assert.Equal(t, result.Version, v.Version)

			case MetaFiles:
				var result MetaFiles
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Length, v.Length)
				assert.Equal(t, result.Version, v.Version)

			case TargetFiles:
				var result TargetFiles
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Length, v.Length)

			case Key:
				var result Key
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Type, v.Type)
				assert.Equal(t, result.Scheme, v.Scheme)

			case Signature:
				var result Signature
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.KeyID, v.KeyID)
				assert.Equal(t, string(result.Signature), string(v.Signature))

			case Delegations:
				var result Delegations
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, len(result.Keys), len(v.Keys))

			case DelegatedRole:
				var result DelegatedRole
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Name, v.Name)
				assert.Equal(t, result.Threshold, v.Threshold)
				assert.Equal(t, result.Terminating, v.Terminating)

			case SuccinctRoles:
				var result SuccinctRoles
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Threshold, v.Threshold)
				assert.Equal(t, result.BitLength, v.BitLength)
				assert.Equal(t, result.NamePrefix, v.NamePrefix)

			case HexBytes:
				var result HexBytes
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, string(result), string(v))

			case Role:
				var result Role
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, result.Threshold, v.Threshold)
				assert.ElementsMatch(t, result.KeyIDs, v.KeyIDs)

			case KeyVal:
				var result KeyVal
				err = json.Unmarshal(data, &result)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}
				assert.Equal(t, string(result.PublicKey), string(v.PublicKey))

			default:
				t.Errorf("Unknown type for roundtrip test: %T", tt.input)
			}

			assert.NoError(t, err)
		})
	}
}

func TestMarshalEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name:    "Nil map in Delegations",
			input:   Delegations{Keys: nil},
			wantErr: false,
		},
		{
			name:    "Empty KeyIDs slice",
			input:   Role{KeyIDs: []string{}, Threshold: 1},
			wantErr: false,
		},
		{
			name:    "Zero threshold",
			input:   Role{KeyIDs: []string{"key1"}, Threshold: 0},
			wantErr: false,
		},
		{
			name:    "Negative threshold",
			input:   SuccinctRoles{KeyIDs: []string{"key1"}, Threshold: -1, BitLength: 256, NamePrefix: "prefix"},
			wantErr: false, // JSON marshaling might allow this
		},
		{
			name:    "Very large numbers",
			input:   MetaFiles{Length: 9223372036854775807, Version: 9223372036854775807}, // max int64
			wantErr: false,
		},
		{
			name:    "Unicode in strings",
			input:   DelegatedRole{Name: "роль-тест-🔑", KeyIDs: []string{"🔑-keyid"}, Threshold: 1},
			wantErr: false,
		},
		{
			name:    "Empty strings",
			input:   Key{Type: "", Scheme: "", Value: KeyVal{PublicKey: ""}},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				// Verify it produces valid JSON
				var result interface{}
				err = json.Unmarshal(data, &result)
				helpers.NoError(t, err)
			}
		})
	}
}

func TestUnmarshalErrorCases(t *testing.T) {
	tests := []struct {
		name       string
		targetType string
		jsonData   string
		wantErr    bool
	}{
		{
			name:       "Invalid JSON",
			targetType: "RootType",
			jsonData:   "{invalid json}",
			wantErr:    true,
		},
		{
			name:       "Missing required fields",
			targetType: "RootType",
			jsonData:   "{}",
			wantErr:    false, // JSON unmarshaling might use zero values
		},
		{
			name:       "Wrong type for numeric field",
			targetType: "MetaFiles",
			jsonData:   `{"length": "not-a-number", "version": 1}`,
			wantErr:    true,
		},
		{
			name:       "Null values",
			targetType: "Signature",
			jsonData:   `{"keyid": null, "sig": null}`,
			wantErr:    false, // Might be handled gracefully
		},
		{
			name:       "Array instead of object",
			targetType: "Key",
			jsonData:   `[]`,
			wantErr:    true,
		},
		{
			name:       "Nested invalid JSON",
			targetType: "Delegations",
			jsonData:   `{"keys": {"key1": {"keytype": 123}}}`, // keytype should be string
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error

			switch tt.targetType {
			case "RootType":
				var result RootType
				err = json.Unmarshal([]byte(tt.jsonData), &result)
			case "MetaFiles":
				var result MetaFiles
				err = json.Unmarshal([]byte(tt.jsonData), &result)
			case "Signature":
				var result Signature
				err = json.Unmarshal([]byte(tt.jsonData), &result)
			case "Key":
				var result Key
				err = json.Unmarshal([]byte(tt.jsonData), &result)
			case "Delegations":
				var result Delegations
				err = json.Unmarshal([]byte(tt.jsonData), &result)
			default:
				t.Fatalf("Unknown target type: %s", tt.targetType)
			}

			if tt.wantErr {
				assert.Error(t, err, "Expected error for invalid JSON")
			} else {
				assert.NoError(t, err, "Expected no error for valid JSON")
			}
		})
	}
}

func TestComplexStructuresMarshaling(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name    string
		input   any
		wantErr bool
	}{
		{
			name: "Complete RootType with all fields",
			input: RootType{
				Type:        "root",
				SpecVersion: "1.0.31",
				Version:     1,
				Expires:     fixedTime,
				Keys: map[string]*Key{
					"key1": {
						Type:   "ed25519",
						Scheme: "ed25519",
						Value:  KeyVal{PublicKey: "publickey1"},
					},
					"key2": {
						Type:   "rsa",
						Scheme: "rsa-pss-sha256",
						Value:  KeyVal{PublicKey: "publickey2"},
					},
				},
				Roles: map[string]*Role{
					"root": {
						KeyIDs:    []string{"key1"},
						Threshold: 1,
					},
					"targets": {
						KeyIDs:    []string{"key2"},
						Threshold: 1,
					},
				},
				ConsistentSnapshot: true,
			},
			wantErr: false,
		},
		{
			name: "TargetsType with complex targets and delegations",
			input: TargetsType{
				Type:        "targets",
				SpecVersion: "1.0.31",
				Version:     2,
				Expires:     fixedTime,
				Targets: map[string]*TargetFiles{
					"file1.txt": {
						Length: 1024,
						Hashes: Hashes{
							"sha256": HexBytes("abc123"),
							"sha512": HexBytes("def456"),
						},
					},
				},
				Delegations: &Delegations{
					Keys: map[string]*Key{
						"delegate-key": {
							Type:   "ed25519",
							Scheme: "ed25519",
							Value:  KeyVal{PublicKey: "delegate-public-key"},
						},
					},
					Roles: []DelegatedRole{
						{
							Name:        "delegate-role",
							KeyIDs:      []string{"delegate-key"},
							Threshold:   1,
							Terminating: false,
							Paths:       []string{"path/*"},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Nested structure with empty collections",
			input: TargetsType{
				Type:        "targets",
				SpecVersion: "1.0.31",
				Version:     1,
				Expires:     fixedTime,
				Targets:     map[string]*TargetFiles{},
				Delegations: &Delegations{
					Keys:  map[string]*Key{},
					Roles: []DelegatedRole{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			data, err := json.Marshal(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify valid JSON
			var jsonData interface{}
			err = json.Unmarshal(data, &jsonData)
			helpers.NoError(t, err)

			// Test unmarshaling back
			switch tt.input.(type) {
			case RootType:
				var result RootType
				err = json.Unmarshal(data, &result)
				helpers.NoError(t, err)
			case TargetsType:
				var result TargetsType
				err = json.Unmarshal(data, &result)
				helpers.NoError(t, err)
			}
		})
	}
}
