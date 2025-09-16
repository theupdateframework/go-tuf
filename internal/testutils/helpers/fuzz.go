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

package helpers

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand"
	"strings"
	"testing"
	"time"
)

// FuzzDataGenerator provides utilities for generating fuzz test data
type FuzzDataGenerator struct {
	rand *rand.Rand
}

// NewFuzzDataGenerator creates a new fuzz data generator
func NewFuzzDataGenerator(seed int64) *FuzzDataGenerator {
	return &FuzzDataGenerator{
		rand: rand.New(rand.NewSource(seed)),
	}
}

// GenerateRandomString generates a random string of specified length
func (f *FuzzDataGenerator) GenerateRandomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[f.rand.Intn(len(charset))]
	}
	return string(b)
}

// GenerateRandomBytes generates random bytes of specified length
func (f *FuzzDataGenerator) GenerateRandomBytes(length int) []byte {
	b := make([]byte, length)
	f.rand.Read(b)
	return b
}

// GenerateRandomInt generates a random integer up to max
func (f *FuzzDataGenerator) GenerateRandomInt(max int) int {
	return f.rand.Intn(max)
}

// GenerateRandomJSON generates random JSON-like data for fuzzing
func (f *FuzzDataGenerator) GenerateRandomJSON() []byte {
	data := map[string]any{
		"signed": map[string]any{
			"_type":        f.GenerateRandomString(f.rand.Intn(20) + 1),
			"version":      f.rand.Intn(1000),
			"spec_version": f.GenerateRandomString(10),
			"expires":      time.Now().Add(time.Duration(f.rand.Intn(365*24)) * time.Hour).Format(time.RFC3339),
		},
		"signatures": []map[string]any{
			{
				"keyid": f.GenerateRandomString(64),
				"sig":   f.GenerateRandomString(128),
			},
		},
	}

	jsonData, _ := json.Marshal(data)
	return jsonData
}

// GenerateCorruptedJSON generates various types of corrupted JSON for fuzzing
func (f *FuzzDataGenerator) GenerateCorruptedJSON() []byte {
	corruptionTypes := []func() []byte{
		// Truncated JSON
		func() []byte {
			validJSON := f.GenerateRandomJSON()
			if len(validJSON) > 10 {
				return validJSON[:len(validJSON)/2]
			}
			return validJSON
		},
		// Invalid characters
		func() []byte {
			return []byte(strings.ReplaceAll(string(f.GenerateRandomJSON()), ":", f.GenerateRandomString(5)))
		},
		// Nested objects with random depths
		func() []byte {
			depth := f.rand.Intn(100) + 1
			json := "{"
			for i := range depth {
				json += fmt.Sprintf(`"level%d": {`, i)
			}
			json += `"value": "test"`
			for range depth {
				json += "}"
			}
			json += "}"
			return []byte(json)
		},
		// Very long strings
		func() []byte {
			longString := f.GenerateRandomString(f.rand.Intn(10000) + 1000)
			return fmt.Appendf([]byte{}, `{"long_string": "%s"}`, longString)
		},
		// Invalid Unicode
		func() []byte {
			return append([]byte(`{"test": "`), append(f.GenerateRandomBytes(50), []byte(`"}`)...)...)
		},
	}

	corruptionFunc := corruptionTypes[f.rand.Intn(len(corruptionTypes))]
	return corruptionFunc()
}

// FuzzMetadataOperations provides fuzz testing for metadata operations
func FuzzMetadataOperations(f *testing.F, operation func(data []byte) error) {
	f.Helper()

	// Add seed data
	generator := NewFuzzDataGenerator(time.Now().UnixNano())

	// Add valid metadata as seeds
	f.Add(CreateTestRootJSON(&testing.T{}))
	f.Add(CreateTestTargetsJSON(&testing.T{}))
	f.Add(CreateTestSnapshotJSON(&testing.T{}))
	f.Add(CreateTestTimestampJSON(&testing.T{}))

	// Add some corrupted data as seeds
	for range 10 {
		f.Add(generator.GenerateCorruptedJSON())
	}

	// Add edge cases
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte("null"))
	f.Add([]byte("[]"))

	f.Fuzz(func(t *testing.T, data []byte) {
		// The operation should never panic, even with invalid input
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("operation panicked with input %q: %v", string(data), r)
			}
		}()

		// Execute the operation - errors are expected and acceptable
		_ = operation(data)
	})
}

// FuzzJSONMarshaling tests JSON marshaling/unmarshaling with random data
func FuzzJSONMarshaling(f *testing.F) {
	f.Helper()

	// Add seed data
	f.Add(CreateTestRootJSON(&testing.T{}))
	f.Add([]byte(`{"test": "value"}`))
	f.Add([]byte(`{}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON marshaling panicked with input %q: %v", string(data), r)
			}
		}()

		var v any
		err := json.Unmarshal(data, &v)
		if err != nil {
			// Invalid JSON is expected, not an error
			return
		}

		// If we can unmarshal, we should be able to marshal back
		_, err = json.Marshal(v)
		if err != nil {
			t.Errorf("failed to marshal back after unmarshal: %v", err)
		}
	})
}

// FuzzStringOperations tests string operations with random input
func FuzzStringOperations(f *testing.F, operation func(s string) error) {
	f.Helper()

	generator := NewFuzzDataGenerator(time.Now().UnixNano())

	// Add seed data
	f.Add("")
	f.Add("test")
	f.Add("1234567890")
	f.Add("special!@#$%^&*()chars")
	f.Add(strings.Repeat("a", 1000))

	// Add random strings
	for range 5 {
		f.Add(generator.GenerateRandomString(100))
	}

	f.Fuzz(func(t *testing.T, s string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("string operation panicked with input %q: %v", s, r)
			}
		}()

		_ = operation(s)
	})
}

// FuzzBytesOperations tests byte operations with random input
func FuzzBytesOperations(f *testing.F, operation func(data []byte) error) {
	f.Helper()

	generator := NewFuzzDataGenerator(time.Now().UnixNano())

	// Add seed data
	f.Add([]byte(""))
	f.Add([]byte("test"))
	f.Add([]byte{0, 1, 2, 3, 255})

	// Add random bytes
	for range 5 {
		f.Add(generator.GenerateRandomBytes(100))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("bytes operation panicked with input %v: %v", data, r)
			}
		}()

		_ = operation(data)
	})
}

// GenerateRandomMetadataFields generates random values for metadata fields
func (f *FuzzDataGenerator) GenerateRandomMetadataFields() map[string]any {
	return map[string]any{
		"version":      f.rand.Intn(1000000),
		"spec_version": f.GenerateRandomString(f.rand.Intn(20) + 1),
		"expires":      f.GenerateRandomTime().Format(time.RFC3339),
		"type":         f.GenerateRandomString(f.rand.Intn(20) + 1),
		"length":       f.rand.Intn(1000000),
		"hashes": map[string]string{
			"sha256": f.GenerateRandomString(64),
			"sha512": f.GenerateRandomString(128),
		},
		"keyids":    []string{f.GenerateRandomString(64), f.GenerateRandomString(64)},
		"threshold": f.rand.Intn(10) + 1,
		"custom": map[string]any{
			"random_field": f.GenerateRandomString(100),
			"number":       f.rand.Intn(1000),
		},
	}
}

// GenerateRandomTime generates a random time within a reasonable range
func (f *FuzzDataGenerator) GenerateRandomTime() time.Time {
	// Generate time between 2020 and 2030
	start := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2030, 12, 31, 23, 59, 59, 0, time.UTC)

	duration := end.Sub(start)
	randomDuration := time.Duration(f.rand.Int63n(int64(duration)))

	return start.Add(randomDuration)
}

// GenerateRandomSignature generates a random signature structure
func (f *FuzzDataGenerator) GenerateRandomSignature() map[string]any {
	return map[string]any{
		"keyid": f.GenerateRandomString(64),
		"sig":   f.GenerateRandomString(f.rand.Intn(200) + 50),
	}
}

// GenerateRandomKey generates a random key structure
func (f *FuzzDataGenerator) GenerateRandomKey() map[string]any {
	keyTypes := []string{"ed25519", "rsa", "ecdsa", "unknown"}
	schemes := []string{"ed25519", "rsa-pss-sha256", "ecdsa-sha2-nistp256", "unknown"}

	return map[string]any{
		"keytype": keyTypes[f.rand.Intn(len(keyTypes))],
		"scheme":  schemes[f.rand.Intn(len(schemes))],
		"keyval": map[string]any{
			"public": f.GenerateRandomString(f.rand.Intn(500) + 50),
		},
	}
}

// CreateFuzzTestMetadata creates various metadata structures for fuzz testing
func (f *FuzzDataGenerator) CreateFuzzTestMetadata(metadataType string) []byte {
	base := map[string]any{
		"signed": map[string]any{
			"_type": metadataType,
		},
		"signatures": []any{
			f.GenerateRandomSignature(),
		},
	}

	// Add type-specific fields
	signed := base["signed"].(map[string]any)
	fields := f.GenerateRandomMetadataFields()
	maps.Copy(signed, fields)

	// Add type-specific structures
	switch metadataType {
	case "root":
		signed["keys"] = map[string]any{
			f.GenerateRandomString(64): f.GenerateRandomKey(),
		}
		signed["roles"] = map[string]any{
			"root": map[string]any{
				"keyids":    []string{f.GenerateRandomString(64)},
				"threshold": f.rand.Intn(5) + 1,
			},
		}
		signed["consistent_snapshot"] = f.rand.Intn(2) == 1

	case "targets":
		signed["targets"] = map[string]any{
			f.GenerateRandomString(20): fields["hashes"],
		}

	case "snapshot":
		signed["meta"] = map[string]any{
			"targets.json": map[string]any{
				"version": f.rand.Intn(1000),
				"hashes":  fields["hashes"],
				"length":  f.rand.Intn(10000),
			},
		}

	case "timestamp":
		signed["meta"] = map[string]any{
			"snapshot.json": map[string]any{
				"version": f.rand.Intn(1000),
				"hashes":  fields["hashes"],
				"length":  f.rand.Intn(10000),
			},
		}
	}

	jsonData, _ := json.Marshal(base)
	return jsonData
}
