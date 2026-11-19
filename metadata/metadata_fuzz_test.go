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
	"bytes"
	"encoding/json"
	"testing"
	"unicode/utf8"

	"github.com/theupdateframework/go-tuf/v2/internal/testutils/helpers"
)

// The seed corpora and fuzz bodies below build metadata with fixedExpire
// rather than the constructors' default of time.Now(), so a given input
// always produces the same bytes.

// FuzzRootFromBytes tests Root metadata parsing with random input
func FuzzRootFromBytes(f *testing.F) {
	// Add seed corpus
	root := Root(fixedExpire)
	validData, _ := root.ToBytes(false)
	f.Add(validData)

	// Add some edge cases
	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "root"}}`))
	f.Add([]byte(`{"signed": {"_type": "wrong"}, "signatures": []}`))

	generator := helpers.NewFuzzDataGenerator(0, 0)

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
	targets := Targets(fixedExpire)
	validData, _ := targets.ToBytes(false)
	f.Add(validData)

	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "targets"}}`))

	generator := helpers.NewFuzzDataGenerator(0, 0)

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
	snapshot := Snapshot(fixedExpire)
	validData, _ := snapshot.ToBytes(false)
	f.Add(validData)

	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "snapshot"}}`))

	generator := helpers.NewFuzzDataGenerator(0, 0)

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
	timestamp := Timestamp(fixedExpire)
	validData, _ := timestamp.ToBytes(false)
	f.Add(validData)

	f.Add([]byte(""))
	f.Add([]byte("{}"))
	f.Add([]byte(`{"signed": {"_type": "timestamp"}}`))

	generator := helpers.NewFuzzDataGenerator(0, 0)

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

// FuzzMetadataToBytes tests metadata serialization: every role must
// serialise for any version, and the version must survive a re-parse.
func FuzzMetadataToBytes(f *testing.F) {
	// Add some variations
	f.Add(int64(1), true) // version, pretty
	f.Add(int64(999999), false)
	f.Add(int64(0), true)
	f.Add(int64(-1), false)

	f.Fuzz(func(t *testing.T, version int64, pretty bool) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("ToBytes panicked with version %d, pretty %t: %v", version, pretty, r)
			}
		}()

		root := Root(fixedExpire)
		root.Signed.Version = version
		data, err := root.ToBytes(pretty)
		if err != nil {
			t.Fatalf("root ToBytes failed: %v", err)
		}
		if parsed, err := Root().FromBytes(data); err != nil {
			t.Errorf("root did not re-parse: %v", err)
		} else if parsed.Signed.Version != version {
			t.Errorf("root version changed: want %d, got %d", version, parsed.Signed.Version)
		}

		targets := Targets(fixedExpire)
		targets.Signed.Version = version
		data, err = targets.ToBytes(pretty)
		if err != nil {
			t.Fatalf("targets ToBytes failed: %v", err)
		}
		if parsed, err := Targets().FromBytes(data); err != nil {
			t.Errorf("targets did not re-parse: %v", err)
		} else if parsed.Signed.Version != version {
			t.Errorf("targets version changed: want %d, got %d", version, parsed.Signed.Version)
		}

		snapshot := Snapshot(fixedExpire)
		snapshot.Signed.Version = version
		data, err = snapshot.ToBytes(pretty)
		if err != nil {
			t.Fatalf("snapshot ToBytes failed: %v", err)
		}
		if parsed, err := Snapshot().FromBytes(data); err != nil {
			t.Errorf("snapshot did not re-parse: %v", err)
		} else if parsed.Signed.Version != version {
			t.Errorf("snapshot version changed: want %d, got %d", version, parsed.Signed.Version)
		}

		timestamp := Timestamp(fixedExpire)
		timestamp.Signed.Version = version
		data, err = timestamp.ToBytes(pretty)
		if err != nil {
			t.Fatalf("timestamp ToBytes failed: %v", err)
		}
		if parsed, err := Timestamp().FromBytes(data); err != nil {
			t.Errorf("timestamp did not re-parse: %v", err)
		} else if parsed.Signed.Version != version {
			t.Errorf("timestamp version changed: want %d, got %d", version, parsed.Signed.Version)
		}
	})
}

// FuzzHexBytes tests that HexBytes survives a JSON round trip unchanged.
func FuzzHexBytes(f *testing.F) {
	// Add seed data
	f.Add([]byte(""))
	f.Add([]byte("test"))
	f.Add([]byte("0123456789abcdef"))
	f.Add([]byte{0, 1, 2, 3, 255})

	generator := helpers.NewFuzzDataGenerator(0, 0)
	for i := 0; i < 10; i++ {
		f.Add(generator.GenerateRandomBytes(100))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("HexBytes operations panicked with input %v: %v", data, r)
			}
		}()

		// Any byte slice has a hex encoding, so neither direction may fail.
		jsonData, err := json.Marshal(HexBytes(data))
		if err != nil {
			t.Fatalf("HexBytes marshal failed for %v: %v", data, err)
		}

		var unmarshaled HexBytes
		if err = json.Unmarshal(jsonData, &unmarshaled); err != nil {
			t.Fatalf("HexBytes unmarshal failed for %s: %v", jsonData, err)
		}

		if !bytes.Equal(data, unmarshaled) {
			t.Errorf("HexBytes roundtrip failed: original %v, got %v", data, unmarshaled)
		}
	})
}

// FuzzMetadataFieldsValidation tests the type check in FromBytes. The payload
// carries every collection a role requires, so the only thing deciding
// whether a role accepts it is the fuzzed _type: the version and
// spec_version are not validated on parse.
func FuzzMetadataFieldsValidation(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(0, 0)

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

		// Build the fuzz payload. The expires field is a fixed constant
		// so the payload stays reproducible for a given input across
		// runs. Local variable is named `payload` rather than `metadata`
		// to avoid shadowing the enclosing package name.
		payload := map[string]interface{}{
			"signed": map[string]interface{}{
				"_type":        metadataType,
				"version":      version,
				"spec_version": specVersion,
				"expires":      "2030-01-01T00:00:00Z",
				"keys":         map[string]interface{}{},
				"roles":        map[string]interface{}{},
				"meta": map[string]interface{}{
					"snapshot.json": map[string]interface{}{"version": 1},
				},
				"targets": map[string]interface{}{},
			},
			"signatures": []interface{}{},
		}

		jsonData, err := json.Marshal(payload)
		if err != nil {
			return
		}

		// Each role must accept the payload exactly when _type names it.
		check := func(role string, err error) {
			t.Helper()
			if metadataType == role && err != nil {
				t.Errorf("%s rejected a payload of its own type: %v", role, err)
			}
			if metadataType != role && err == nil {
				t.Errorf("%s accepted a payload of type %q", role, metadataType)
			}
		}
		_, err = Root().FromBytes(jsonData)
		check(ROOT, err)
		_, err = Targets().FromBytes(jsonData)
		check(TARGETS, err)
		_, err = Snapshot().FromBytes(jsonData)
		check(SNAPSHOT, err)
		_, err = Timestamp().FromBytes(jsonData)
		check(TIMESTAMP, err)
	})
}

// FuzzSignatureOperations tests that a Signature survives a JSON round trip
// and can be attached to metadata that still serialises.
func FuzzSignatureOperations(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(0, 0)

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

		jsonData, err := json.Marshal(sig)
		if err != nil {
			t.Fatalf("Signature marshal failed: %v", err)
		}

		var unmarshaled Signature
		if err = json.Unmarshal(jsonData, &unmarshaled); err != nil {
			t.Fatalf("Signature unmarshal failed for %s: %v", jsonData, err)
		}

		if !bytes.Equal(sigData, unmarshaled.Signature) {
			t.Errorf("signature bytes changed: want %x, got %x", sigData, unmarshaled.Signature)
		}
		// encoding/json replaces invalid UTF-8, so only valid key IDs are
		// expected to come back unchanged.
		if utf8.ValidString(keyID) && unmarshaled.KeyID != keyID {
			t.Errorf("key ID changed: want %q, got %q", keyID, unmarshaled.KeyID)
		}

		// Metadata carrying the signature must still serialise.
		root := Root(fixedExpire)
		root.Signatures = append(root.Signatures, sig)
		if _, err = root.ToBytes(false); err != nil {
			t.Errorf("ToBytes failed with the signature attached: %v", err)
		}
	})
}

// FuzzCompleteMetadataStructure tests complete metadata structure with random data
func FuzzCompleteMetadataStructure(f *testing.F) {
	generator := helpers.NewFuzzDataGenerator(0, 0)

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
	})
}
