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
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertMarshalRoundTrip checks both directions of a type's JSON encoding.
// Marshalling input must produce wantJSON, which catches fields dropped on
// the way out. Unmarshalling that into a new value of the same type and
// marshalling again must reproduce the same bytes, which catches fields
// dropped on the way back in.
func assertMarshalRoundTrip(t *testing.T, input any, wantJSON string) {
	t.Helper()

	encoded, err := json.Marshal(input)
	require.NoError(t, err)
	assert.JSONEq(t, wantJSON, string(encoded))

	decoded := reflect.New(reflect.TypeOf(input))
	require.NoError(t, json.Unmarshal(encoded, decoded.Interface()))

	reencoded, err := json.Marshal(decoded.Elem().Interface())
	require.NoError(t, err)
	assert.Equal(t, string(encoded), string(reencoded))
}

func TestMarshalUnmarshalJSON(t *testing.T) {
	fixedTime := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	tests := []struct {
		name     string
		input    any
		wantJSON string
	}{
		{
			name:     "RootType Marshal/Unmarshal",
			input:    RootType{Type: "root", SpecVersion: "1.0", ConsistentSnapshot: true, Version: 1, Expires: fixedTime, Keys: map[string]*Key{}, Roles: map[string]*Role{}},
			wantJSON: `{"_type":"root","spec_version":"1.0","consistent_snapshot":true,"version":1,"expires":"2024-01-01T00:00:00Z","keys":{},"roles":{}}`,
		},
		{
			name:     "SnapshotType Marshal/Unmarshal",
			input:    SnapshotType{Type: "snapshot", SpecVersion: "1.0", Version: 1, Expires: fixedTime, Meta: map[string]*MetaFiles{}},
			wantJSON: `{"_type":"snapshot","spec_version":"1.0","version":1,"expires":"2024-01-01T00:00:00Z","meta":{}}`,
		},
		{
			name:     "TimestampType Marshal/Unmarshal",
			input:    TimestampType{Type: "timestamp", SpecVersion: "1.0", Version: 1, Expires: fixedTime, Meta: map[string]*MetaFiles{"snapshot.json": MetaFile(1)}},
			wantJSON: `{"_type":"timestamp","spec_version":"1.0","version":1,"expires":"2024-01-01T00:00:00Z","meta":{"snapshot.json":{"version":1}}}`,
		},
		{
			name:     "TargetsType Marshal/Unmarshal",
			input:    TargetsType{Type: "targets", SpecVersion: "1.0", Version: 1, Expires: fixedTime, Targets: map[string]*TargetFiles{}},
			wantJSON: `{"_type":"targets","spec_version":"1.0","version":1,"expires":"2024-01-01T00:00:00Z","targets":{}}`,
		},
		{
			name:     "MetaFiles Marshal/Unmarshal",
			input:    MetaFiles{Length: 123, Hashes: Hashes{"sha256": HexBytes("abc123")}, Version: 1},
			wantJSON: `{"length":123,"hashes":{"sha256":"616263313233"},"version":1}`,
		},
		{
			name:     "TargetFiles Marshal/Unmarshal",
			input:    TargetFiles{Length: 123, Hashes: Hashes{"sha256": HexBytes("abc123")}},
			wantJSON: `{"length":123,"hashes":{"sha256":"616263313233"}}`,
		},
		{
			name:     "Key Marshal/Unmarshal",
			input:    Key{Type: "ed25519", Scheme: "scheme", Value: KeyVal{PublicKey: "publicKey"}},
			wantJSON: `{"keytype":"ed25519","scheme":"scheme","keyval":{"public":"publicKey"}}`,
		},
		{
			name:     "Signature Marshal/Unmarshal",
			input:    Signature{KeyID: "keyid", Signature: HexBytes("signature")},
			wantJSON: `{"keyid":"keyid","sig":"7369676e6174757265"}`,
		},
		{
			name:     "Delegations Marshal/Unmarshal",
			input:    Delegations{Keys: map[string]*Key{"keyid": {Type: "ed25519", Scheme: "scheme", Value: KeyVal{PublicKey: "publicKey"}}}},
			wantJSON: `{"keys":{"keyid":{"keytype":"ed25519","scheme":"scheme","keyval":{"public":"publicKey"}}}}`,
		},
		{
			name:     "DelegatedRole Marshal/Unmarshal",
			input:    DelegatedRole{Name: "role", KeyIDs: []string{"keyid"}, Threshold: 1, Terminating: true},
			wantJSON: `{"name":"role","keyids":["keyid"],"threshold":1,"terminating":true}`,
		},
		{
			name:     "SuccinctRoles Marshal/Unmarshal",
			input:    SuccinctRoles{KeyIDs: []string{"keyid"}, Threshold: 1, BitLength: 8, NamePrefix: "prefix"},
			wantJSON: `{"keyids":["keyid"],"threshold":1,"bit_length":8,"name_prefix":"prefix"}`,
		},
		{
			name:     "HexBytes Marshal/Unmarshal",
			input:    HexBytes("abc123"),
			wantJSON: `"616263313233"`,
		},
		{
			name:     "Empty HexBytes Marshal/Unmarshal",
			input:    HexBytes(""),
			wantJSON: `""`,
		},
		{
			name:     "Role Marshal/Unmarshal",
			input:    Role{KeyIDs: []string{"key1", "key2"}, Threshold: 2},
			wantJSON: `{"keyids":["key1","key2"],"threshold":2}`,
		},
		{
			name:     "KeyVal Marshal/Unmarshal",
			input:    KeyVal{PublicKey: "public-key-bytes"},
			wantJSON: `{"public":"public-key-bytes"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMarshalRoundTrip(t, tt.input, tt.wantJSON)
		})
	}
}

func TestMarshalEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		wantJSON string
	}{
		{
			name:     "Empty KeyIDs slice",
			input:    Role{KeyIDs: []string{}, Threshold: 1},
			wantJSON: `{"keyids":[],"threshold":1}`,
		},
		{
			name:     "Zero threshold",
			input:    Role{KeyIDs: []string{"key1"}, Threshold: 0},
			wantJSON: `{"keyids":["key1"],"threshold":0}`,
		},
		{
			// JSON marshaling allows a negative threshold; validation
			// happens elsewhere.
			name:     "Negative threshold",
			input:    SuccinctRoles{KeyIDs: []string{"key1"}, Threshold: -1, BitLength: 8, NamePrefix: "prefix"},
			wantJSON: `{"keyids":["key1"],"threshold":-1,"bit_length":8,"name_prefix":"prefix"}`,
		},
		{
			name:     "Very large numbers",
			input:    MetaFiles{Length: 9223372036854775807, Version: 9223372036854775807}, // max int64
			wantJSON: `{"length":9223372036854775807,"version":9223372036854775807}`,
		},
		{
			name:     "Unicode in strings",
			input:    DelegatedRole{Name: "роль-тест-🔑", KeyIDs: []string{"🔑-keyid"}, Threshold: 1},
			wantJSON: `{"name":"роль-тест-🔑","keyids":["🔑-keyid"],"threshold":1,"terminating":false}`,
		},
		{
			name:     "Empty strings",
			input:    Key{Type: "", Scheme: "", Value: KeyVal{PublicKey: ""}},
			wantJSON: `{"keytype":"","scheme":"","keyval":{"public":""}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMarshalRoundTrip(t, tt.input, tt.wantJSON)
		})
	}

	// A nil keys map serialises as null, which the decoder refuses, so this
	// value cannot round-trip.
	t.Run("Nil map in Delegations", func(t *testing.T) {
		encoded, err := json.Marshal(Delegations{Keys: nil})
		require.NoError(t, err)
		assert.JSONEq(t, `{"keys":null}`, string(encoded))

		var decoded Delegations
		assert.ErrorContains(t, json.Unmarshal(encoded, &decoded), "delegation keys must not be null")
	})
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
			wantErr:    true, // Required maps must not be missing or null.
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
			wantErr:    true, // null sig is invalid hex bytes
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
		name     string
		input    any
		wantJSON string
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
			wantJSON: `{
				"_type": "root",
				"spec_version": "1.0.31",
				"version": 1,
				"expires": "2024-01-01T00:00:00Z",
				"consistent_snapshot": true,
				"keys": {
					"key1": {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "publickey1"}},
					"key2": {"keytype": "rsa", "scheme": "rsa-pss-sha256", "keyval": {"public": "publickey2"}}
				},
				"roles": {
					"root": {"keyids": ["key1"], "threshold": 1},
					"targets": {"keyids": ["key2"], "threshold": 1}
				}
			}`,
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
			wantJSON: `{
				"_type": "targets",
				"spec_version": "1.0.31",
				"version": 2,
				"expires": "2024-01-01T00:00:00Z",
				"targets": {
					"file1.txt": {
						"length": 1024,
						"hashes": {"sha256": "616263313233", "sha512": "646566343536"}
					}
				},
				"delegations": {
					"keys": {
						"delegate-key": {"keytype": "ed25519", "scheme": "ed25519", "keyval": {"public": "delegate-public-key"}}
					},
					"roles": [
						{
							"name": "delegate-role",
							"keyids": ["delegate-key"],
							"threshold": 1,
							"terminating": false,
							"paths": ["path/*"]
						}
					]
				}
			}`,
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
			wantJSON: `{
				"_type": "targets",
				"spec_version": "1.0.31",
				"version": 1,
				"expires": "2024-01-01T00:00:00Z",
				"targets": {},
				"delegations": {"keys": {}, "roles": []}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertMarshalRoundTrip(t, tt.input, tt.wantJSON)
		})
	}
}
