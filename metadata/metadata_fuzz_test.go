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

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
)

// FuzzRootFromBytes tests Root metadata parsing with random input
func FuzzRootFromBytes(f *testing.F) {
	// Add seed corpus
	root := Root()
	validData, _ := root.ToBytes(false)
	f.Add(validData)

	// Add some edge cases
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "root"}}`))
	f.Add([]byte(`{"signed": {"_type": "wrong"}, "signatures": []}`))

	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	// Add corrupted metadata
	for i := 0; i < 5; i++ {
		f.Add(generator.CreateFuzzTestMetadata("root"))
		f.Add(generator.GenerateCorruptedJSON())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Root().FromBytes panicked with input %q: %v", string(data), r)
			}
		}()

		_, err := Root().FromBytes(data)
		// Errors are expected and acceptable for invalid input
		_ = err
	})
}

// FuzzTargetsFromBytes tests Targets metadata parsing with random input
func FuzzTargetsFromBytes(f *testing.F) {
	// Add seed corpus
	targets := Targets()
	validData, _ := targets.ToBytes(false)
	f.Add(validData)

	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "targets"}}`))

	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	for i := 0; i < 5; i++ {
		f.Add(generator.CreateFuzzTestMetadata("targets"))
		f.Add(generator.GenerateCorruptedJSON())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Targets().FromBytes panicked with input %q: %v", string(data), r)
			}
		}()

		_, err := Targets().FromBytes(data)
		_ = err
	})
}

// FuzzSnapshotFromBytes tests Snapshot metadata parsing with random input
func FuzzSnapshotFromBytes(f *testing.F) {
	snapshot := Snapshot()
	validData, _ := snapshot.ToBytes(false)
	f.Add(validData)

	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "snapshot"}}`))

	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	for i := 0; i < 5; i++ {
		f.Add(generator.CreateFuzzTestMetadata("snapshot"))
		f.Add(generator.GenerateCorruptedJSON())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Snapshot().FromBytes panicked with input %q: %v", string(data), r)
			}
		}()

		_, err := Snapshot().FromBytes(data)
		_ = err
	})
}

// FuzzTimestampFromBytes tests Timestamp metadata parsing with random input
func FuzzTimestampFromBytes(f *testing.F) {
	timestamp := Timestamp()
	validData, _ := timestamp.ToBytes(false)
	f.Add(validData)

	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "timestamp"}}`))

	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	for i := 0; i < 5; i++ {
		f.Add(generator.CreateFuzzTestMetadata("timestamp"))
		f.Add(generator.GenerateCorruptedJSON())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Timestamp().FromBytes panicked with input %q: %v", string(data), r)
			}
		}()

		_, err := Timestamp().FromBytes(data)
		_ = err
	})
}

// FuzzMetadataToBytes tests metadata serialization
func FuzzMetadataToBytes(f *testing.F) {
	// Add some variations
	f.Add(int64(1), true) // version, compact
	f.Add(int64(999999), false)
	f.Add(int64(0), true)
	f.Add(int64(-1), false)

	f.Fuzz(func(t *testing.T, version int64, compact bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ToBytes panicked with version %d, compact %t: %v", version, compact, r)
			}
		}()

		// Test each metadata type
		testCases := []func(){
			func() {
				root := Root()
				root.Signed.Version = version
				_, _ = root.ToBytes(compact)
			},
			func() {
				targets := Targets()
				targets.Signed.Version = version
				_, _ = targets.ToBytes(compact)
			},
			func() {
				snapshot := Snapshot()
				snapshot.Signed.Version = version
				_, _ = snapshot.ToBytes(compact)
			},
			func() {
				timestamp := Timestamp()
				timestamp.Signed.Version = version
				_, _ = timestamp.ToBytes(compact)
			},
		}

		for _, testFunc := range testCases {
			testFunc()
		}
	})
}

// FuzzJSONMarshaling tests JSON marshaling of metadata structures
func FuzzJSONMarshaling(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	// Add valid JSON samples
	f.Add([]byte(`{"test": "value"}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`[]`))
	f.Add(helpers.CreateTestRootJSON(&testing.T{}))

	// Add some random data
	for i := 0; i < 5; i++ {
		f.Add(generator.GenerateRandomJSON())
		f.Add(generator.GenerateCorruptedJSON())
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("JSON marshaling panicked with input %q: %v", string(data), r)
			}
		}()

		var v interface{}
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

// FuzzHexBytes tests HexBytes marshaling/unmarshaling
func FuzzHexBytes(f *testing.F) {
	// Add seed data
	f.Add([]byte(""))
	f.Add([]byte("test"))
	f.Add([]byte("0123456789abcdef"))
	f.Add([]byte{0, 1, 2, 3, 255})

	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())
	for i := 0; i < 10; i++ {
		f.Add(generator.GenerateRandomBytes(100))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("HexBytes operations panicked with input %v: %v", data, r)
			}
		}()

		hexBytes := HexBytes(data)

		// Test JSON marshaling
		jsonData, err := json.Marshal(hexBytes)
		if err != nil {
			return // Some data might not be marshalable
		}

		// Test JSON unmarshaling
		var unmarshaled HexBytes
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			return // Some JSON might not be unmarshalable
		}

		// If both operations succeeded, the data should be the same
		if len(data) > 0 && string(hexBytes) != string(unmarshaled) {
			t.Errorf("HexBytes roundtrip failed: original %v, got %v", hexBytes, unmarshaled)
		}
	})
}

// FuzzMetadataFieldsValidation tests validation of metadata fields
func FuzzMetadataFieldsValidation(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	// Add seed test cases
	f.Add("root", int64(1), "1.0.31")
	f.Add("targets", int64(999), "1.0.0")
	f.Add("snapshot", int64(0), "")
	f.Add("timestamp", int64(-1), "invalid")

	// Add random cases
	for i := 0; i < 5; i++ {
		f.Add(
			generator.GenerateRandomString(20),
			int64(generator.GenerateRandomInt(1000000)-500000),
			generator.GenerateRandomString(10),
		)
	}

	f.Fuzz(func(t *testing.T, metadataType string, version int64, specVersion string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Metadata field validation panicked with type=%s, version=%d, spec=%s: %v",
					metadataType, version, specVersion, r)
			}
		}()

		// Create metadata structure with fuzz data
		metadata := map[string]interface{}{
			"signed": map[string]interface{}{
				"_type":        metadataType,
				"version":      version,
				"spec_version": specVersion,
				"expires":      time.Now().Add(24 * time.Hour).Format(time.RFC3339),
			},
			"signatures": []interface{}{},
		}

		jsonData, err := json.Marshal(metadata)
		if err != nil {
			return
		}

		// Test parsing with each metadata type
		_, _ = Root().FromBytes(jsonData)
		_, _ = Targets().FromBytes(jsonData)
		_, _ = Snapshot().FromBytes(jsonData)
		_, _ = Timestamp().FromBytes(jsonData)
	})
}

// FuzzSignatureOperations tests signature-related operations
func FuzzSignatureOperations(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	// Add seed data
	f.Add("valid-keyid", []byte("signature-data"))
	f.Add("", []byte(""))
	f.Add("very-long-"+generator.GenerateRandomString(1000), generator.GenerateRandomBytes(1000))

	for i := 0; i < 5; i++ {
		f.Add(
			generator.GenerateRandomString(64),
			generator.GenerateRandomBytes(128),
		)
	}

	f.Fuzz(func(t *testing.T, keyID string, sigData []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Signature operations panicked with keyID=%s, sigData len=%d: %v",
					keyID, len(sigData), r)
			}
		}()

		// Create signature structure
		sig := Signature{
			KeyID:     keyID,
			Signature: HexBytes(sigData),
		}

		// Test JSON marshaling
		jsonData, err := json.Marshal(sig)
		if err != nil {
			return
		}

		// Test JSON unmarshaling
		var unmarshaled Signature
		err = json.Unmarshal(jsonData, &unmarshaled)
		if err != nil {
			return
		}

		// Test adding to metadata
		root := Root()
		root.Signatures = append(root.Signatures, sig)

		// Test serialization
		_, _ = root.ToBytes(false)
	})
}

// FuzzCompleteMetadataStructure tests complete metadata structure with random data
func FuzzCompleteMetadataStructure(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(time.Now().UnixNano())

	// Add seed data for complete metadata structures
	for _, metadataType := range []string{"root", "targets", "snapshot", "timestamp"} {
		f.Add(generator.CreateFuzzTestMetadata(metadataType))
	}

	// Add some edge cases
	f.Add([]byte(`{"signed": {}, "signatures": []}`))
	f.Add([]byte(`{"signed": {"_type": "root", "version": 999999999}, "signatures": []}`))

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("Complete metadata structure test panicked with input len=%d: %v",
					len(data), r)
			}
		}()

		// Test parsing with all metadata types
		metadataTypes := []func() interface{}{
			func() interface{} { m, _ := Root().FromBytes(data); return m },
			func() interface{} { m, _ := Targets().FromBytes(data); return m },
			func() interface{} { m, _ := Snapshot().FromBytes(data); return m },
			func() interface{} { m, _ := Timestamp().FromBytes(data); return m },
		}

		for _, parseFunc := range metadataTypes {
			parseFunc()
		}

		// Test if it's valid JSON at all
		var v interface{}
		if err := json.Unmarshal(data, &v); err == nil {
			// If it's valid JSON, test re-marshaling
			_, _ = json.Marshal(v)
		}
	})
}
